#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <algorithm>
#include <cstring>
#include <map>
#include <unordered_set>
#include <fstream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ctime>
#include <atomic>
#include <set>
#include <sstream>

#pragma comment(lib, "ws2_32.lib")

// 文件名通知命令前缀
#define FILE_NAME_CMD "/file_name "
// 文件传输完成通知
#define FILE_END_CMD "/file_end"
// 数据包确认命令
#define PACKET_ACK_CMD "/packet_ack "

#define SOCKET_ERROR (-1)
#define INVALID_SOCKET (SOCKET)(~0)

// 数据包头部结构
const int PACKET_MAGIC = 0x12345678;
const int MAX_RETRY_COUNT = 3;
const int ACK_TIMEOUT_MS = 2000;

// 修改包头结构，增加校验和和序列号
struct PacketHeader {
    int magic;          // 魔法值，用于识别文件分包
    int total_packets;  // 总包数
    int current_packet; // 当前包序号
    int data_size;      // 本包数据大小
    bool is_last;       // 是否最后一包
    unsigned short checksum; // 数据校验和
    unsigned short sequence; // 序列号(0-65535)
};

// 重新计算包头大小
const int HEADER_SIZE = sizeof(PacketHeader);
const int MAX_PACKET_SIZE = (1<<16) + HEADER_SIZE;
const int MAX_DATA_SIZE = MAX_PACKET_SIZE - HEADER_SIZE;

// 计算数据的简单校验和
unsigned short calculate_checksum(const char* data, int length) {
    unsigned short sum = 0;
    for (int i = 0; i < length; ++i) {
        sum += (unsigned char)data[i];
    }
    return sum;
}

// 用户信息结构体
struct User {
    std::string username;
    SOCKET sock;
    int current_group_id; // 0表示全局聊天
    std::string ip_address; // 用户IP地址
};

// 群组信息结构体
struct Group {
    int id;
    std::string name;
    std::string creator;  // 群组创建者
    std::vector<std::string> members; // 群成员
};

class ChatServer {
private:
    SOCKET server_fd;
    std::vector<SOCKET> clients;
    std::map<std::string, User> users;       // 用户名 -> 用户信息
    std::map<int, Group> groups;             // 群ID -> 群组信息
    std::unordered_set<std::string> blacklist; // 用户名黑名单
    std::unordered_set<std::string> ip_blacklist; // IP黑名单
    std::map<std::string, std::vector<char>> file_buffers; // 接收文件缓冲区
    std::map<std::string, int> received_packets; // 已接收包数
    std::map<std::string, std::set<int>> received_packet_set; // 已接收的包序号集合
    std::mutex clients_mutex;
    std::mutex users_mutex;
    std::mutex groups_mutex;
    std::mutex blacklist_mutex;
    std::mutex file_mutex;
    std::atomic<bool> running;
    int next_group_id; // 群ID计数器
    std::string current_receiving_file;
    std::atomic<unsigned short> sequence_number; // 序列号生成器

    // 获取客户端IP地址
    std::string get_client_ip(SOCKET client_socket) {
        sockaddr_in client_addr;
        int addr_len = sizeof(client_addr);
        getpeername(client_socket, (sockaddr*)&client_addr, &addr_len);
        return inet_ntoa(client_addr.sin_addr);
    }

    // 验证IP地址格式 (Windows兼容版本)
    bool validate_ip_address(const std::string& ip) {
        // 简单的IP地址格式验证
        int parts[4];
        char dot;
        std::stringstream ss(ip);

        ss >> parts[0] >> dot >> parts[1] >> dot >> parts[2] >> dot >> parts[3];

        if (ss.fail() || !ss.eof()) {
            return false;
        }

        for (int i = 0; i < 4; i++) {
            if (parts[i] < 0 || parts[i] > 255) {
                return false;
            }
        }

        return true;
    }

    // 等待数据包确认
    bool wait_for_ack(SOCKET sock, int packet_seq) {
        char ack_buffer[256];
        fd_set readfds;
        struct timeval timeout;

        for (int retry = 0; retry < MAX_RETRY_COUNT; ++retry) {
            FD_ZERO(&readfds);
            FD_SET(sock, &readfds);
            timeout.tv_sec = ACK_TIMEOUT_MS / 1000;
            timeout.tv_usec = (ACK_TIMEOUT_MS % 1000) * 1000;

            int result = select(0, &readfds, NULL, NULL, &timeout);
            if (result > 0 && FD_ISSET(sock, &readfds)) {
                int ack_size = recv(sock, ack_buffer, sizeof(ack_buffer) - 1, 0);
                if (ack_size > 0) {
                    ack_buffer[ack_size] = '\0';
                    std::string ack_msg(ack_buffer, ack_size);
                    if (ack_msg.find(PACKET_ACK_CMD) == 0) {
                        int ack_seq = std::stoi(ack_msg.substr(strlen(PACKET_ACK_CMD)));
                        if (ack_seq == packet_seq) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    // 发送文件到所有客户端（带确认机制）
    void send_file_to_all_clients(const std::string& filename, const std::vector<char>& file_data) {
        int total_packets = (file_data.size() + MAX_DATA_SIZE - 1) / MAX_DATA_SIZE;
        PacketHeader header;
        header.magic = PACKET_MAGIC;
        header.total_packets = total_packets;

        std::cout << "开始转发文件: " << filename << " (" << file_data.size()
                  << " 字节, " << total_packets << " 个包)" << std::endl;

        for (int i = 0; i < total_packets; ++i) {
            if (!running) break;

            int data_size = std::min(MAX_DATA_SIZE, (int)file_data.size() - i * MAX_DATA_SIZE);
            const char* data_ptr = file_data.data() + i * MAX_DATA_SIZE;

            header.current_packet = i;
            header.data_size = data_size;
            header.is_last = (i == total_packets - 1);
            header.sequence = sequence_number++;
            header.checksum = calculate_checksum(data_ptr, data_size);

            // 构建数据包
            char packet[MAX_PACKET_SIZE];
            memcpy(packet, &header, HEADER_SIZE);
            memcpy(packet + HEADER_SIZE, data_ptr, data_size);

            // 广播数据包给所有客户端（带确认机制）
            std::lock_guard<std::mutex> lock(clients_mutex);
            for (auto& sock : clients) {
                bool ack_received = false;
                for (int retry = 0; retry < MAX_RETRY_COUNT && !ack_received; ++retry) {
                    int total_sent = 0;
                    while (total_sent < HEADER_SIZE + data_size) {
                        int send_len = send(sock, packet + total_sent,
                                          (HEADER_SIZE + data_size) - total_sent, 0);
                        if (send_len == SOCKET_ERROR) {
                            std::cerr << "发送到客户端失败，错误: " << WSAGetLastError() << std::endl;
                            break;
                        }
                        total_sent += send_len;
                    }

                    if (total_sent == HEADER_SIZE + data_size) {
                        ack_received = wait_for_ack(sock, header.sequence);
                    }

                    if (!ack_received && retry < MAX_RETRY_COUNT - 1) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(100 * (retry + 1)));
                    }
                }

                if (!ack_received) {
                    std::cerr << "客户端确认超时，可能已断开连接" << std::endl;
                }
            }

            // 显示转发进度
            if (i % 10 == 0 || header.is_last) {
                std::cout << "\r文件转发进度: [" << (i + 1) << "/" << total_packets << "]" << std::flush;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }

        std::cout << std::endl << "文件转发完成: " << filename << std::endl;
    }

    // 处理文件分包数据（带校验和验证）
    void handle_file_packet(const std::string& username, const char* data, int data_len) {
        if (data_len < HEADER_SIZE) {
            std::cerr << "无效的数据包：头部信息不完整" << std::endl;
            return;
        }

        PacketHeader* header = (PacketHeader*)data;
        if (header->magic != PACKET_MAGIC) {
            std::cerr << "数据包魔术值不匹配，忽略" << std::endl;
            return;
        }

        // 验证数据大小
        if (header->data_size > MAX_DATA_SIZE || data_len < HEADER_SIZE + header->data_size) {
            std::cerr << "数据包大小异常，包序号: " << header->current_packet << std::endl;
            return;
        }

        const char* packet_data = data + HEADER_SIZE;
        int actual_data_size = std::min(header->data_size, data_len - HEADER_SIZE);

        // 验证校验和
        unsigned short calculated_checksum = calculate_checksum(packet_data, actual_data_size);
        if (calculated_checksum != header->checksum) {
            std::cerr << "数据包校验和错误，来自用户: " << username
                      << "，包序号: " << header->current_packet << std::endl;
            return;
        }

        std::lock_guard<std::mutex> lock(file_mutex);

        // 发送ACK确认
        std::string ack_msg = PACKET_ACK_CMD + std::to_string(header->sequence);
        {
            std::lock_guard<std::mutex> ulock(users_mutex);
            auto user_it = users.find(username);
            if (user_it != users.end()) {
                send(user_it->second.sock, ack_msg.c_str(), ack_msg.size(), 0);
            }
        }

        // 初始化缓冲区（接收第一个包时）
        if (header->current_packet == 0) {
            // 生成唯一的文件名
            std::string filename = "file_from_" + username + "_" + std::to_string(time(nullptr)) + ".dat";
            file_buffers[filename].clear();
            received_packets[filename] = 0;
            received_packet_set[filename].clear();
            current_receiving_file = filename;

            std::cout << "开始接收文件: " << filename << "，来自用户: " << username
                      << "，总包数: " << header->total_packets << std::endl;
        }

        // 检查是否已接收过该数据包
        if (received_packet_set[current_receiving_file].count(header->current_packet)) {
            std::cout << "收到重复包，序号: " << header->current_packet << "，已忽略" << std::endl;
            return;
        }

        // 严格按顺序接收数据包
        if (header->current_packet == received_packets[current_receiving_file]) {
            file_buffers[current_receiving_file].insert(
                file_buffers[current_receiving_file].end(),
                packet_data,
                packet_data + actual_data_size
            );

            received_packet_set[current_receiving_file].insert(header->current_packet);
            received_packets[current_receiving_file]++;

            // 显示接收进度
            if (header->current_packet % 10 == 0 || header->is_last) {
                std::cout << "\r文件接收进度: [" << received_packets[current_receiving_file]
                          << "/" << header->total_packets << "]" << std::flush;
            }

            // 所有包接收完成后，转发给所有客户端
            if (header->is_last && received_packets[current_receiving_file] == header->total_packets) {
                std::cout << std::endl << "文件接收完成，开始转发: " << current_receiving_file
                          << " (" << file_buffers[current_receiving_file].size() << " 字节)" << std::endl;

                // 1. 发送文件名通知
                std::string name_cmd = FILE_NAME_CMD + current_receiving_file;
                broadcast(name_cmd);

                // 2. 发送文件分包
                send_file_to_all_clients(current_receiving_file, file_buffers[current_receiving_file]);

                // 3. 发送文件结束通知
                broadcast(FILE_END_CMD);

                // 清理缓冲区
                file_buffers.erase(current_receiving_file);
                received_packets.erase(current_receiving_file);
                received_packet_set.erase(current_receiving_file);
                current_receiving_file.clear();
            }
        } else {
            std::cerr << "数据包顺序错误：预期 " << received_packets[current_receiving_file]
                      << ", 实际收到: " << header->current_packet << std::endl;
        }
    }

public:
    ChatServer(int port) : running(false), next_group_id(1), sequence_number(0) {
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            throw std::runtime_error("WSAStartup failed: " + std::to_string(result));
        }

        server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server_fd == INVALID_SOCKET) {
            throw std::runtime_error("socket creation failed: " + std::to_string(WSAGetLastError()));
        }

        int opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
            throw std::runtime_error("setsockopt failed: " + std::to_string(WSAGetLastError()));
        }

        sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) == SOCKET_ERROR) {
            closesocket(server_fd);
            throw std::runtime_error("bind failed: " + std::to_string(WSAGetLastError()));
        }

        if (listen(server_fd, 10) == SOCKET_ERROR) {
            closesocket(server_fd);
            throw std::runtime_error("listen failed: " + std::to_string(WSAGetLastError()));
        }

        std::cout << "服务器启动成功，端口: " << port << std::endl;
        std::cout << "服务器命令: \n";
        std::cout << "list_users(查看用户)、list_groups(查看群组)\n";
        std::cout << "kick_user 用户名(踢人)、ban_user 用户名(封禁)\n";
        std::cout << "unban_user 用户名(解封)、ban_ip IP地址(封禁IP)\n";
        std::cout << "unban_ip IP地址(解封IP)、list_banned_ips(查看被封禁的IP)\n";
        std::cout << "send_notice 消息(系统通知)、help(帮助)\n";
        running = true;
    }

    ~ChatServer() {
        running = false;
        for (size_t i = 0; i < clients.size(); ++i) {
            closesocket(clients[i]);
        }
        closesocket(server_fd);
        WSACleanup();
    }

    // 广播消息
    void broadcast(const std::string& message, SOCKET sender = INVALID_SOCKET) {
        std::lock_guard<std::mutex> lock(clients_mutex);
        for (auto& sock : clients) {
            if (sock != sender) {
                send(sock, message.c_str(), message.size(), 0);
            }
        }
    }

    // 发送系统通知
    void send_system_notice(const std::string& content) {
        std::string notice = "[系统通知] " + content;
        broadcast(notice);
        std::cout << "已发送系统通知: " << content << std::endl;
    }

    // 发送消息到指定群组
    void send_to_group(int group_id, const std::string& message) {
        std::string formatted_msg = message;
        std::vector<std::string> target_members;

        if (group_id == 0) {
            std::lock_guard<std::mutex> ulock(users_mutex);
            for (auto& user : users) {
                target_members.push_back(user.first);
            }
        } else {
            std::lock_guard<std::mutex> glock(groups_mutex);
            auto group_it = groups.find(group_id);
            if (group_it == groups.end()) {
                std::cerr << "群组ID " << group_id << " 不存在" << std::endl;
                return;
            }
            formatted_msg = "[" + group_it->second.name + "] " + message;
            target_members = group_it->second.members;
        }

        std::lock_guard<std::mutex> ulock(users_mutex);
        for (auto& member : target_members) {
            auto user_it = users.find(member);
            if (user_it != users.end()) {
                SOCKET client_sock = user_it->second.sock;
                int send_len = send(client_sock, formatted_msg.c_str(), formatted_msg.size(), 0);
                if (send_len == SOCKET_ERROR) {
                    std::cerr << "发送给用户 " << member << " 失败: " << WSAGetLastError() << std::endl;
                }
            }
        }
    }

    // 处理客户端命令
    void process_command(const std::string& username, const std::string& command) {
        try {
            if (command.substr(0, 4) == "/cg ") {
                std::string group_name = command.substr(4);
                if (group_name.empty()) {
                    send(users[username].sock, "群组名称不能为空", 15, 0);
                    return;
                }

                std::lock_guard<std::mutex> glock(groups_mutex);
                int group_id = next_group_id++;
                groups[group_id] = {group_id, group_name, username, {username}};

                std::lock_guard<std::mutex> ulock(users_mutex);
                users[username].current_group_id = group_id;

                std::string response = "群组创建成功! ID: " + std::to_string(group_id) + ", 名称: " + group_name;
                send(users[username].sock, response.c_str(), response.size(), 0);
            } else if (command.substr(0, 6) == "/join ") {
                int group_id = std::stoi(command.substr(6));
                std::lock_guard<std::mutex> glock(groups_mutex);
                auto group_it = groups.find(group_id);

                if (group_it == groups.end()) {
                    send(users[username].sock, "群组ID不存在", 12, 0);
                    return;
                }

                bool is_member = false;
                for (auto& mem : group_it->second.members) {
                    if (mem == username) {
                        is_member = true;
                        break;
                    }
                }
                if (is_member) {
                    send(users[username].sock, "你已在该群组中", 12, 0);
                    return;
                }

                group_it->second.members.push_back(username);
                std::lock_guard<std::mutex> ulock(users_mutex);
                users[username].current_group_id = group_id;

                std::string response = "已加入群组: " + group_it->second.name + " (ID: " + std::to_string(group_id) + ")";
                send(users[username].sock, response.c_str(), response.size(), 0);
            } else if (command.substr(0, 4) == "/sg ") {
                int group_id = std::stoi(command.substr(4));
                if (group_id == 0) {
                    std::lock_guard<std::mutex> ulock(users_mutex);
                    users[username].current_group_id = 0;
                    send(users[username].sock, "已切换到全局聊天", 14, 0);
                    return;
                }

                std::lock_guard<std::mutex> glock(groups_mutex);
                auto group_it = groups.find(group_id);
                if (group_it == groups.end()) {
                    send(users[username].sock, "群组ID不存在", 12, 0);
                    return;
                }

                bool is_member = false;
                for (auto& mem : group_it->second.members) {
                    if (mem == username) {
                        is_member = true;
                        break;
                    }
                }
                if (!is_member) {
                    send(users[username].sock, "请先加入该群组", 12, 0);
                    return;
                }

                std::lock_guard<std::mutex> ulock(users_mutex);
                users[username].current_group_id = group_id;
                std::string response = "已切换到群组: " + group_it->second.name;
                send(users[username].sock, response.c_str(), response.size(), 0);
            } else if (command == "/list") {
                std::lock_guard<std::mutex> glock(groups_mutex);
                std::string response = "群组列表:\n";
                for (auto& group : groups) {
                    response += "ID: " + std::to_string(group.first) + ", 名称: " + group.second.name +
                                ", 创建者: " + group.second.creator +
                                ", 成员数: " + std::to_string(group.second.members.size()) + "\n";
                }
                send(users[username].sock, response.c_str(), response.size(), 0);
            } else if (command.substr(0, 4) == "/gm ") {
                int group_id = std::stoi(command.substr(4));
                std::lock_guard<std::mutex> glock(groups_mutex);
                auto group_it = groups.find(group_id);

                if (group_it == groups.end()) {
                    send(users[username].sock, "群组ID不存在", 12, 0);
                    return;
                }

                std::string response = "群组 " + group_it->second.name + " 成员:\n";
                for (auto& mem : group_it->second.members) {
                    if (mem == group_it->second.creator) {
                        response += "- " + mem + " (创建者)\n";
                    } else {
                        response += "- " + mem + "\n";
                    }
                }
                send(users[username].sock, response.c_str(), response.size(), 0);
            } else if (command.substr(0, 8) == "/remove ") {
                size_t space_pos = command.find(' ', 8);
                if (space_pos == std::string::npos) {
                    send(users[username].sock, "格式错误: /remove 群ID 用户名", 26, 0);
                    return;
                }
                int group_id = std::stoi(command.substr(8, space_pos - 8));
                std::string target_user = command.substr(space_pos + 1);

                std::lock_guard<std::mutex> glock(groups_mutex);
                auto group_it = groups.find(group_id);
                if (group_it == groups.end()) {
                    send(users[username].sock, "群组ID不存在", 12, 0);
                    return;
                }

                if (group_it->second.creator != username) {
                    send(users[username].sock, "权限不足: 只有创建者可移除成员", 26, 0);
                    return;
                }

                auto& members = group_it->second.members;
                auto mem_it = std::find(members.begin(), members.end(), target_user);
                if (mem_it == members.end()) {
                    send(users[username].sock, "目标用户不在该群组中", 18, 0);
                    return;
                }

                members.erase(mem_it);
                std::lock_guard<std::mutex> ulock(users_mutex);
                auto user_it = users.find(target_user);
                if (user_it != users.end()) {
                    user_it->second.current_group_id = 0;
                    std::string remove_msg = "你已被移出群组: " + group_it->second.name;
                    send(user_it->second.sock, remove_msg.c_str(), remove_msg.size(), 0);
                }
                std::string msg = "已移除用户: " + target_user;
                send(users[username].sock, msg.c_str(), msg.size(), 0);
                std::cout << username << "(群组创建者) 移出 " << target_user << " 至群组 " << group_it->second.name << std::endl;
            } else if (command == "/help") {
                std::string help = "客户端命令:\n";
                help += "/cg 群组名 - 创建群组\n";
                help += "/join 群ID - 加入群组\n";
                help += "/sg 群ID - 切换当前群组(0为全局)\n";
                help += "/list - 查看所有群组\n";
                help += "/gm 群ID - 查看群组成员\n";
                help += "/remove 群ID 用户名 - 移除群成员(创建者)\n";
                help += "/sendfile 文件名 - 发送文件\n";
                help += "/quit - 退出聊天\n";
                send(users[username].sock, help.c_str(), help.size(), 0);
            } else {
                send(users[username].sock, "未知命令，请输入/help查看帮助", 26, 0);
            }
        } catch (...) {
            send(users[username].sock, "命令格式错误，例如: /cg 我的群 或 /remove 1 用户名", 40, 0);
        }
    }

    // 处理客户端连接
    void handle_client(SOCKET client_socket) {
        char buffer[MAX_PACKET_SIZE] = {0};
        std::string username;

        // 获取客户端IP地址
        std::string client_ip = get_client_ip(client_socket);
        std::cout << "新连接来自IP: " << client_ip << std::endl;

        // 检查IP是否在黑名单中
        {
            std::lock_guard<std::mutex> blacklock(blacklist_mutex);
            if (ip_blacklist.count(client_ip)) {
                const char* err = "你的IP地址已被封禁，无法连接服务器";
                send(client_socket, err, strlen(err), 0);
                closesocket(client_socket);
                std::cout << "已阻止被封禁IP的连接: " << client_ip << std::endl;
                return;
            }
        }

        // 接收用户名
        int valread = recv(client_socket, buffer, MAX_PACKET_SIZE - 1, 0);
        if (valread <= 0) {
            std::cerr << "接收用户名失败: " << WSAGetLastError() << std::endl;
            closesocket(client_socket);
            return;
        }
        username = std::string(buffer, valread);

        // 检查是否在黑名单
        {
            std::lock_guard<std::mutex> blacklock(blacklist_mutex);
            if (blacklist.count(username)) {
                const char* err = "你已被禁止登录";
                send(client_socket, err, strlen(err), 0);
                closesocket(client_socket);
                std::cout << "黑名单用户 " << username << " 尝试登录，IP: " << client_ip << std::endl;
                return;
            }
        }

        // 检查用户名是否已存在
        bool exists = false;
        {
            std::lock_guard<std::mutex> ulock(users_mutex);
            exists = users.count(username);
            if (exists) {
                const char* err = "用户名已存在";
                send(client_socket, err, strlen(err), 0);
                closesocket(client_socket);
                return;
            }
            users[username] = {username, client_socket, 0, client_ip};
        }

        {
            std::lock_guard<std::mutex> clock(clients_mutex);
            clients.push_back(client_socket);
        }

        std::cout << username << " 已连接，IP: " << client_ip << std::endl;
        broadcast(username + " 加入聊天!");

        // 发送欢迎消息
        std::string welcome = "欢迎加入聊天!\n客户端命令:\n";
        welcome += "/cg 群组名 - 创建群组\n";
        welcome += "/join 群ID - 加入群组\n";
        welcome += "/sg 群ID - 切换当前群组(0为全局)\n";
        welcome += "/list - 查看所有群组\n";
        welcome += "/gm 群ID - 查看群组成员\n";
        welcome += "/remove 群ID 用户名 - 移除群成员(创建者)\n";
        welcome += "/sendfile 文件名 - 发送文件\n";
        welcome += "/quit - 退出聊天\n";
        send(client_socket, welcome.c_str(), welcome.size(), 0);

        // 消息循环
        while (running) {
            int valread = recv(client_socket, buffer, MAX_PACKET_SIZE - 1, 0);
            if (valread <= 0) break;

            // 关键：先判断是否为文件分包（检查魔法值）
            bool is_file_packet = false;
            if (valread >= HEADER_SIZE) {
                PacketHeader* header = (PacketHeader*)buffer;
                if (header->magic == PACKET_MAGIC) {
                    is_file_packet = true;
                }
            }

            if (is_file_packet) {
                // 是文件分包，交给 handle_file_packet 处理
                handle_file_packet(username, buffer, valread);
            } else {
                // 是普通文本消息，按原逻辑处理
                std::string msg(buffer, valread);

                // 处理ACK确认包（来自其他客户端的ACK）
                if (msg.find(PACKET_ACK_CMD) == 0) {
                    continue; // ACK包由wait_for_ack处理
                }

                if (msg == "/quit") break;
                if (msg.substr(0, 10) == "/sendfile ") {
                    std::string filename = msg.substr(10);
                    std::cout << username << " 开始发送文件: " << filename << std::endl;
                    continue;
                }
                if (msg[0] == '/') {
                    process_command(username, msg);
                } else {
                    // 发送到群组或全局
                    int current_group = users[username].current_group_id;
                    send_to_group(current_group, username + ": " + msg);
                    std::cout << "[" << (current_group == 0 ? "全局" : std::to_string(current_group)) << "] "
                              << username << " (" << client_ip << "): " << msg << std::endl;
                }
            }
        }

        // 客户端断开处理
        std::cout << username << " 已断开，IP: " << client_ip << std::endl;
        broadcast(username + " 离开聊天!");

        {
            std::lock_guard<std::mutex> glock(groups_mutex);
            for (auto& group : groups) {
                auto& members = group.second.members;
                auto it = std::find(members.begin(), members.end(), username);
                if (it != members.end()) {
                    members.erase(it);
                }
            }
        }

        {
            std::lock_guard<std::mutex> ulock(users_mutex);
            users.erase(username);
        }

        {
            std::lock_guard<std::mutex> clock(clients_mutex);
            auto it = std::find(clients.begin(), clients.end(), client_socket);
            if (it != clients.end()) {
                clients.erase(it);
            }
        }

        closesocket(client_socket);
    }

    // 启动服务器
    void start() {
        while (running) {
            sockaddr_in client_addr;
            int addrlen = sizeof(client_addr);
            SOCKET new_socket = accept(server_fd, (struct sockaddr*)&client_addr, &addrlen);

            if (new_socket == INVALID_SOCKET) {
                if (running)
                    std::cerr << "接收连接失败: " << WSAGetLastError() << std::endl;
                continue;
            }

            std::thread(&ChatServer::handle_client, this, new_socket).detach();
        }
    }

    // 服务器命令：查看用户
    void list_users() {
        std::lock_guard<std::mutex> lock(users_mutex);
        std::cout << "\n当前在线用户(" << users.size() << "):\n";
        for (auto& user : users) {
            std::cout << "用户名: " << user.first
                      << ", IP: " << user.second.ip_address
                      << ", 群组: " << (user.second.current_group_id == 0 ? "全局" : std::to_string(user.second.current_group_id)) << "\n";
        }
        std::cout << std::endl;
    }

    // 服务器命令：查看群组
    void list_all_groups() {
        std::lock_guard<std::mutex> lock(groups_mutex);
        std::cout << "\n当前群组(" << groups.size() << "):\n";
        for (auto& group : groups) {
            std::cout << "ID: " << group.first << ", 名称: " << group.second.name
                      << ", 创建者: " << group.second.creator
                      << ", 成员数: " << group.second.members.size() << "\n";
        }
        std::cout << std::endl;
    }

    // 服务器命令：踢人
    void kick_user(const std::string& username) {
        std::lock_guard<std::mutex> ulock(users_mutex);
        auto it = users.find(username);
        if (it == users.end()) {
            std::cout << "用户 " << username << " 不存在\n";
            return;
        }

        SOCKET sock = it->second.sock;
        std::string ip = it->second.ip_address;
        std::string msg = username + " 被管理员踢出";

        {
            std::lock_guard<std::mutex> glock(groups_mutex);
            for (auto& group : groups) {
                auto& members = group.second.members;
                auto mem_it = std::find(members.begin(), members.end(), username);
                if (mem_it != members.end()) {
                    members.erase(mem_it);
                }
            }
        }

        users.erase(it);

        {
            std::lock_guard<std::mutex> clock(clients_mutex);
            auto it = std::find(clients.begin(), clients.end(), sock);
            if (it != clients.end()) {
                clients.erase(it);
            }
        }

        // 发送踢出消息给被踢用户
        std::string kick_msg = "你已被管理员踢出服务器";
        send(sock, kick_msg.c_str(), kick_msg.size(), 0);

        closesocket(sock);

        std::cout << "已踢出用户: " << username << " (IP: " << ip << ")" << std::endl;
        broadcast(msg);
    }

    // 服务器命令：封禁用户
    void ban_user(const std::string& username) {
        std::lock_guard<std::mutex> blacklock(blacklist_mutex);
        {
            std::lock_guard<std::mutex> ulock(users_mutex);
            auto user_it = users.find(username);
            if (user_it != users.end()) {
                std::string ip = user_it->second.ip_address;
                kick_user(username);
                std::cout << "用户 " << username << " 的IP地址为: " << ip << std::endl;
            } else {
                // 用户不在线，但仍然加入黑名单
                blacklist.insert(username);
                std::cout << "用户 " << username << " 不在线，已加入黑名单" << std::endl;
                return;
            }
        }
        blacklist.insert(username);
        std::cout << "已封禁用户: " << username << std::endl;
    }

    // 服务器命令：解封用户
    void unban_user(const std::string& username) {
        std::lock_guard<std::mutex> blacklock(blacklist_mutex);
        if (blacklist.erase(username)) {
            std::cout << "已解封用户: " << username << std::endl;
        } else {
            std::cout << "用户 " << username << " 不在黑名单中" << std::endl;
        }
    }

    // 服务器命令：封禁IP
    void ban_ip(const std::string& ip) {
        // 验证IP格式
        if (!validate_ip_address(ip)) {
            std::cout << "无效的IP地址格式: " << ip << std::endl;
            return;
        }

        std::lock_guard<std::mutex> blacklock(blacklist_mutex);
        ip_blacklist.insert(ip);

        // 踢出该IP的所有用户
        std::vector<std::string> users_to_kick;
        {
            std::lock_guard<std::mutex> ulock(users_mutex);
            for (auto& user : users) {
                if (user.second.ip_address == ip) {
                    users_to_kick.push_back(user.first);
                }
            }
        }

        // 逐个踢出用户（注意：这里不能持有users_mutex，因为kick_user内部会获取它）
        for (auto& username : users_to_kick) {
            kick_user(username);
        }

        std::cout << "已封禁IP: " << ip << "，并踢出 " << users_to_kick.size() << " 个用户" << std::endl;
    }

    // 服务器命令：解封IP
    void unban_ip(const std::string& ip) {
        std::lock_guard<std::mutex> blacklock(blacklist_mutex);
        if (ip_blacklist.erase(ip)) {
            std::cout << "已解封IP: " << ip << std::endl;
        } else {
            std::cout << "IP " << ip << " 不在黑名单中" << std::endl;
        }
    }

    // 服务器命令：查看被封禁的IP
    void list_banned_ips() {
        std::lock_guard<std::mutex> blacklock(blacklist_mutex);
        std::cout << "\n被封禁的IP地址(" << ip_blacklist.size() << "):\n";
        for (auto& ip : ip_blacklist) {
            std::cout << "- " << ip << "\n";
        }

        std::cout << "\n被封禁的用户名(" << blacklist.size() << "):\n";
        for (auto& user : blacklist) {
            std::cout << "- " << user << "\n";
        }
        std::cout << std::endl;
    }
};

int main(int argc, char* argv[]) {
    try {
        int port = (argc > 1) ? std::stoi(argv[1]) : 8080;
        ChatServer server(port);

        std::thread server_thread(&ChatServer::start, &server);
        server_thread.detach();

        // 服务器命令循环
        std::string cmd;
        while (true) {
            std::cout << "服务器> ";
            std::getline(std::cin, cmd);

            if (cmd == "list_users") {
                server.list_users();
            } else if (cmd == "list_groups") {
                server.list_all_groups();
            } else if (cmd.substr(0, 10) == "kick_user ") {
                server.kick_user(cmd.substr(10));
            } else if (cmd.substr(0, 9) == "ban_user ") {
                server.ban_user(cmd.substr(9));
            } else if (cmd.substr(0, 11) == "unban_user ") {
                server.unban_user(cmd.substr(11));
            } else if (cmd.substr(0, 7) == "ban_ip ") {
                server.ban_ip(cmd.substr(7));
            } else if (cmd.substr(0, 9) == "unban_ip ") {
                server.unban_ip(cmd.substr(9));
            } else if (cmd == "list_banned_ips") {
                server.list_banned_ips();
            } else if (cmd.substr(0, 12) == "send_notice ") {
                server.send_system_notice(cmd.substr(12));
            } else if (cmd == "help") {
                std::cout << "服务器命令:\n";
                std::cout << "list_users - 查看当前在线用户\n";
                std::cout << "list_groups - 查看所有群组\n";
                std::cout << "kick_user 用户名 - 踢除指定用户\n";
                std::cout << "ban_user 用户名 - 封禁用户(禁止登录)\n";
                std::cout << "unban_user 用户名 - 解封用户\n";
                std::cout << "ban_ip IP地址 - 封禁IP地址(禁止该IP连接)\n";
                std::cout << "unban_ip IP地址 - 解封IP地址\n";
                std::cout << "list_banned_ips - 查看所有被封禁的IP和用户\n";
                std::cout << "send_notice 消息 - 发送系统通知给所有用户\n";
                std::cout << "help - 显示帮助信息\n";
                std::cout << "quit - 退出服务器\n";
            } else if (cmd == "quit" || cmd == "exit") {
                std::cout << "正在关闭服务器..." << std::endl;
                break;
            } else if (!cmd.empty()) {
                std::cout << "未知命令，输入 help 查看帮助" << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
