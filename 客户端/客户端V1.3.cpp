#include <bits/stdc++.h>
#include <string>
#include <thread>
#include <mutex>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <fstream>
#include <atomic>

#pragma comment(lib, "ws2_32.lib")

// 文件名通知命令前缀
#define FILE_NAME_CMD "/file_name "
// 文件传输完成通知
#define FILE_END_CMD "/file_end"
// 数据包确认命令
#define PACKET_ACK_CMD "/packet_ack "

#define SOCKET_ERROR (-1)
#define INVALID_SOCKET (SOCKET)(~0)
#define CODE_BLOCK_MARKER "```"

const int PACKET_MAGIC = 0x12345678;
const int MAX_RETRY_COUNT = 3;  // 最大重试次数
const int ACK_TIMEOUT_MS = 2000; // ACK超时时间(毫秒)

// 修改包头结构，增加序列号和校验和
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

// 修复的inet_pton实现
int my_inet_pton(int af, const char* src, void* dst) {
    if (af != AF_INET) return -1;
    if (!src || !dst) return -1;

    unsigned long addr = inet_addr(src);
    if (addr == INADDR_NONE) {
        return 0; // 无效的IP地址
    }

    memcpy(dst, &addr, sizeof(addr));
    return 1;
}

void clear_line() {
    std::cout << "\r" << std::string(80, ' ') << "\r";
}

class ChatClient {
private:
    SOCKET sock;
    std::atomic<bool> running;
    bool is_sending_file;
    std::mutex cout_mutex;
    int current_group_id;
    bool in_code_block;
    std::string code_block_buffer;

    std::map<std::string, std::vector<char>> file_buffers;
    std::map<std::string, int> received_packets;
    std::map<std::string, std::set<int>> received_packet_set;
    std::string current_receiving_file;
    std::mutex file_mutex;
    unsigned short sequence_number;

    // 等待数据包确认
    bool wait_for_ack(int packet_seq) {
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
            } else if (result == 0) {
                // 超时，继续重试
                continue;
            } else {
                // select错误
                int error = WSAGetLastError();
                std::cerr << "select错误: " << error << std::endl;
                break;
            }
        }
        return false;
    }

public:
    ChatClient(const std::string& ip, int port) : running(false), current_group_id(0),
                                                 in_code_block(false), is_sending_file(false),
                                                 sequence_number(0) {
        WSADATA wsaData;
        int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (result != 0) {
            throw std::runtime_error("WSAStartup失败: " + std::to_string(result));
        }

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            WSACleanup();
            throw std::runtime_error("socket创建失败: " + std::to_string(WSAGetLastError()));
        }

        // 设置socket选项，避免地址占用
        int opt = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
            closesocket(sock);
            WSACleanup();
            throw std::runtime_error("setsockopt失败: " + std::to_string(WSAGetLastError()));
        }

        // 设置接收超时
        DWORD timeout = 5000; // 5秒超时
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
            closesocket(sock);
            WSACleanup();
            throw std::runtime_error("设置接收超时失败: " + std::to_string(WSAGetLastError()));
        }

        sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);

        // 使用标准的inet_pton或者修复的版本
        if (my_inet_pton(AF_INET, ip.c_str(), &serv_addr.sin_addr) <= 0) {
            // 如果自定义函数失败，尝试使用标准函数
            serv_addr.sin_addr.s_addr = inet_addr(ip.c_str());
            if (serv_addr.sin_addr.s_addr == INADDR_NONE) {
                closesocket(sock);
                WSACleanup();
                throw std::runtime_error("无效的IP地址: " + ip);
            }
        }

        std::cout << "正在连接到服务器 " << ip << ":" << port << "..." << std::endl;

        // 连接服务器
        if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR) {
            int error = WSAGetLastError();
            closesocket(sock);
            WSACleanup();
            throw std::runtime_error("连接服务器失败 (错误代码: " + std::to_string(error) + ")");
        }

        // 连接成功后禁用超时
        timeout = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

        running = true;
        std::cout << "成功连接到服务器!" << std::endl;
    }

    ~ChatClient() {
        running = false;
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
        }
        WSACleanup();
    }

    void send_message(const std::string& message) {
        if (send(sock, message.c_str(), message.size(), 0) == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error != WSAEWOULDBLOCK) {
                std::cerr << "发送消息失败: " << error << std::endl;
                running = false;
            }
        }
    }

    // 优化的文件分包发送函数
    void send_file_packets(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            std::cerr << "无法打开文件: " << filename << std::endl;
            return;
        }

        std::streamsize file_size = file.tellg();
        file.seekg(0, std::ios::beg);
        int total_packets = (file_size + MAX_DATA_SIZE - 1) / MAX_DATA_SIZE;

        std::cout << "开始发送文件: " << filename << " (" << file_size << " 字节, "
                  << total_packets << " 个包)" << std::endl;

        char data_buffer[MAX_DATA_SIZE];
        PacketHeader header;
        header.magic = PACKET_MAGIC;
        header.total_packets = total_packets;

        for (int i = 0; i < total_packets; ++i) {
            if (!running) break;

            file.read(data_buffer, MAX_DATA_SIZE);
            std::streamsize bytes_read = file.gcount();

            header.current_packet = i;
            header.data_size = (int)bytes_read;
            header.is_last = (i == total_packets - 1);
            header.sequence = sequence_number++;
            header.checksum = calculate_checksum(data_buffer, bytes_read);

            // 构建数据包
            char packet[MAX_PACKET_SIZE];
            memcpy(packet, &header, HEADER_SIZE);
            memcpy(packet + HEADER_SIZE, data_buffer, bytes_read);

            // 带重传机制的发送
            bool ack_received = false;
            for (int retry = 0; retry < MAX_RETRY_COUNT && !ack_received; ++retry) {
                int total_sent = 0;
                while (total_sent < HEADER_SIZE + bytes_read) {
                    int send_len = send(sock, packet + total_sent,
                                      (HEADER_SIZE + bytes_read) - total_sent, 0);
                    if (send_len == SOCKET_ERROR) {
                        int error = WSAGetLastError();
                        std::cerr << "发送失败 (错误: " << error << ")，重试 " << retry + 1 << std::endl;
                        break;
                    }
                    total_sent += send_len;
                }

                if (total_sent == HEADER_SIZE + bytes_read) {
                    ack_received = wait_for_ack(header.sequence);
                }

                if (!ack_received && retry < MAX_RETRY_COUNT - 1) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100 * (retry + 1)));
                }
            }

            if (!ack_received) {
                std::cerr << "文件传输失败: 数据包 " << i << " 确认超时" << std::endl;
                file.close();
                return;
            }

            // 显示发送进度
            if (i % 10 == 0 || header.is_last) {
                std::cout << "\r文件发送进度: [" << (i + 1) << "/" << total_packets << "]" << std::flush;
            }

            // 控制发送速率，避免网络拥塞
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }

        file.close();
        std::cout << std::endl << "文件发送完成: " << filename << std::endl;
    }

    void save_received_file(const std::string& filename, const std::vector<char>& file_data) {
        std::string dir = "file";
#ifdef _WIN32
        CreateDirectoryA(dir.c_str(), NULL);
#else
        mkdir(dir.c_str(), 0777);
#endif

        std::string file_path = dir + "/" + filename;
        std::ofstream outfile(file_path, std::ios::binary);
        if (outfile.is_open()) {
            outfile.write(file_data.data(), file_data.size());
            outfile.close();
            std::cout << "\n文件保存成功: " << file_path << " (" << file_data.size() << " 字节)" << std::endl;
        } else {
            std::cerr << "\n无法创建文件: " << file_path << std::endl;
        }
    }

    void handle_file_packet(const char* data, int data_len) {
        if (current_receiving_file.empty()) return;

        PacketHeader* header = (PacketHeader*)data;

        // 验证包头完整性
        if (data_len < HEADER_SIZE || header->data_size > MAX_DATA_SIZE) {
            std::cerr << "无效的数据包大小" << std::endl;
            return;
        }

        // 验证校验和
        const char* packet_data = data + HEADER_SIZE;
        int actual_data_size = std::min(header->data_size, data_len - HEADER_SIZE);
        unsigned short calculated_checksum = calculate_checksum(packet_data, actual_data_size);

        if (calculated_checksum != header->checksum) {
            std::cerr << "数据包校验和错误，包序号: " << header->current_packet << std::endl;
            return;
        }

        std::lock_guard<std::mutex> lock(file_mutex);

        // 发送ACK确认
        std::string ack_msg = PACKET_ACK_CMD + std::to_string(header->sequence);
        send(sock, ack_msg.c_str(), ack_msg.size(), 0);

        // 检查是否已接收过该数据包
        if (received_packet_set[current_receiving_file].count(header->current_packet)) {
            return; // 重复包，忽略
        }

        // 存储数据包
        file_buffers[current_receiving_file].insert(
            file_buffers[current_receiving_file].end(),
            packet_data,
            packet_data + actual_data_size
        );

        received_packet_set[current_receiving_file].insert(header->current_packet);
        received_packets[current_receiving_file]++;

        // 显示接收进度
        if (header->current_packet % 10 == 0 || header->is_last) {
            std::cout << "\r接收文件进度: " << current_receiving_file
                      << " [" << received_packets[current_receiving_file]
                      << "/" << header->total_packets << "]" << std::flush;
        }
    }

    void receive_messages() {
        char buffer[MAX_PACKET_SIZE] = {0};
        while (running) {
            int valread = recv(sock, buffer, MAX_PACKET_SIZE - 1, 0);
            if (valread <= 0) {
                if (valread == 0) {
                    // 正常断开连接
                    std::lock_guard<std::mutex> lock(cout_mutex);
                    std::cout << "\n服务器已断开连接" << std::endl;
                } else {
                    int error = WSAGetLastError();
                    if (error != WSAETIMEDOUT && error != WSAEWOULDBLOCK) {
                        std::lock_guard<std::mutex> lock(cout_mutex);
                        std::cout << "\n与服务器连接断开 (错误: " << error << ")" << std::endl;
                    } else {
                        // 超时或暂时不可用，继续循环
                        continue;
                    }
                }
                running = false;
                break;
            }

            std::string message(buffer, valread);

            // 处理文件名通知
            if (message.substr(0, strlen(FILE_NAME_CMD)) == FILE_NAME_CMD) {
                std::lock_guard<std::mutex> lock(file_mutex);
                current_receiving_file = message.substr(strlen(FILE_NAME_CMD));
                file_buffers[current_receiving_file].clear();
                received_packets[current_receiving_file] = 0;
                received_packet_set[current_receiving_file].clear();
                std::cout << "\n开始接收文件: " << current_receiving_file << std::endl;
                continue;
            }

            // 处理文件结束通知
            if (message == FILE_END_CMD) {
                std::lock_guard<std::mutex> lock(file_mutex);
                if (!current_receiving_file.empty()) {
                    save_received_file(current_receiving_file, file_buffers[current_receiving_file]);
                    file_buffers.erase(current_receiving_file);
                    received_packets.erase(current_receiving_file);
                    received_packet_set.erase(current_receiving_file);
                    current_receiving_file.clear();
                    std::cout << std::endl;
                }
                continue;
            }

            // 处理ACK确认(服务端发送的ACK)
            if (message.find(PACKET_ACK_CMD) == 0) {
                continue; // ACK包由wait_for_ack处理
            }

            // 处理文件分包
            if (valread >= HEADER_SIZE) {
                PacketHeader* header = (PacketHeader*)buffer;
                if (header->magic == PACKET_MAGIC) {
                    handle_file_packet(buffer, valread);
                    continue;
                }
            }

            if (is_sending_file) {
                continue;
            }

            // 处理普通文本消息
            std::lock_guard<std::mutex> lock(cout_mutex);
            clear_line();
            std::cout << message << std::endl;
            std::cout << "> ";
            std::cout.flush();
        }
    }

    void start(const std::string& username) {
        if (!is_sending_file) {
            send_message(username);
        }
        std::thread(&ChatClient::receive_messages, this).detach();

        std::string input;
        while (running) {
            if (in_code_block) {
                if (!is_sending_file) {
                    std::cout << "代码块> ";
                    std::cout.flush();
                }
            } else {
                if (!is_sending_file) {
                    std::cout << "> ";
                    std::cout.flush();
                }
            }

            std::getline(std::cin, input);
            if (!running) break;

            // 处理代码块模式切换
            if (input == CODE_BLOCK_MARKER) {
                in_code_block = !in_code_block;
                if (!in_code_block) {
                    code_block_buffer += CODE_BLOCK_MARKER;
                    send_message(code_block_buffer);
                    code_block_buffer.clear();
                } else {
                    code_block_buffer = CODE_BLOCK_MARKER + std::string("\n");
                }
                continue;
            }

            if (input.substr(0, 10) == "/sendfile ") {
                std::string filename = input.substr(10);
                std::ifstream test_file(filename);
                if (!test_file.good()) {
                    std::cerr << "文件不存在或无法访问: " << filename << std::endl;
                    continue;
                }
                test_file.close();

                send_message("/sendfile " + filename);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                is_sending_file = true;
                send_file_packets(filename);
                is_sending_file = false;
                continue;
            }

            // 处理代码块内容
            if (in_code_block) {
                code_block_buffer += input + "\n";
                continue;
            }

            // 普通消息处理
            if (input == "/quit") {
                running = false;
                break;
            }

            std::lock_guard<std::mutex> lock(cout_mutex);
            send_message(input);
        }

        // 退出时发送退出消息
        if (running) {
            send_message("/quit");
        }
    }
};

int main(int argc, char* argv[]) {
    try {
        std::string ip = (argc > 1) ? argv[1] : "10.110.169.53"; // 默认使用本地回环地址
        int port = (argc > 2) ? std::stoi(argv[2]) : 8080;

        // 验证端口号
        if (port <= 0 || port > 65535) {
            std::cerr << "错误: 端口号必须在1-65535之间" << std::endl;
            return 1;
        }

        std::cout << "正在连接到 " << ip << ":" << port << "..." << std::endl;

        std::cout << "请输入用户名: ";
        std::string username;
        std::getline(std::cin, username);
        if (username.empty()) {
            std::cerr << "用户名不能为空" << std::endl;
            return 1;
        }

        ChatClient client(ip, port);
        client.start(username);
    } catch (const std::exception& e) {
        std::cerr << "错误: " << e.what() << std::endl;
        std::cout << "按任意键退出..." << std::endl;
        std::cin.get();
        return 1;
    }
    return 0;
}
