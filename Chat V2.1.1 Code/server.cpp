#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <vector>
#include <map>
#include <set>
#include <deque> // 用循环队列来缓存在缓冲区中记录时间戳
#include <string>
#include <sstream>
#include <thread>
#include <mutex>
#include <algorithm>
#include <chrono>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

// --- 协议定义 ---
enum PacketType { 
    TYPE_LOGIN=1, TYPE_TEXT=2, TYPE_FILE_HEADER=3, TYPE_FILE_CHUNK=4, 
    TYPE_SYSTEM=5, TYPE_CHECK_L=10086 
};

#pragma pack(push, 1)
struct PacketHeader { uint32_t length; uint32_t type; };
#pragma pack(pop)

// --- 密钥配置 ---
const std::string SERVER_VERSION = "DBD311EBDE5B214A54EFEB28DB774E3E9B665FF0D5EB61F3AEA5BC4E44B5264B2FBA3CFD49320402784A094248DCAD46C770966A841E0418FB4124AF9ED25A4E";
std::string ADMIN_KEY; 

// 限流参数
const int LIMIT_MSG_1S = 5;    // 1秒内最多5条
const int LIMIT_MSG_10S = 20;  // 10秒内最多20条
const int LIMIT_FILE_10S = 3;  // 10秒内最多5个文件传输
const int MAX_KICKS_PER_MIN = 5; // 1分钟内同IP最多5次违规

// --- 结构体 ---
struct ClientContext {
    SOCKET sock;
    std::string name, ip, room;
    bool checked;
    
    // 限流参数结构
    std::deque<time_t> msg_times;
    std::deque<time_t> file_times;

    ClientContext() : sock(INVALID_SOCKET), checked(false) {}
    ClientContext(SOCKET s, std::string n, std::string i, std::string r) 
        : sock(s), name(n), ip(i), room(r), checked(false) {}
};

struct AdminContext {
    SOCKET sock;
    std::string ip;
    AdminContext() : sock(INVALID_SOCKET) {}
    AdminContext(SOCKET s, std::string i) : sock(s), ip(i) {}
};

// --- 全局变量 ---
std::mutex g_mutex;
std::map<SOCKET, ClientContext> clients;
std::map<SOCKET, AdminContext> admins;
SOCKET g_console_sock = INVALID_SOCKET;
std::set<std::string> banned_ips;
std::set<std::string> pending_bans;
std::map<std::string, std::deque<time_t>> ip_violation_records; // IP违规记录

// --- 工具函数 ---
template <typename T>
std::string to_str(T value) {
    std::ostringstream os; os << value; return os.str();
}

void setup_console() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD dwMode = 0;
    if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &dwMode)) {
        dwMode |= 0x0004; SetConsoleMode(hOut, dwMode);
    }
    DWORD dwInMode = 0;
    if (hIn != INVALID_HANDLE_VALUE && GetConsoleMode(hIn, &dwInMode)) {
        dwInMode |= 0x0080; dwInMode &= ~0x0040; SetConsoleMode(hIn, dwInMode);
    }
}

void print_banner() {
    std::cout << "\033[96m"
        << "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n"
        << "┃       CHAT SERVER v2.1.1 (AntiSpam)    ┃\n"
        << "┃      [8080:Chat] [9001:Admin]          ┃\n"
        << "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\033[0m" << std::endl;
}

void server_log(const std::string& tag, const std::string& msg) {
    time_t now = time(0); char dt[64];
    strftime(dt, sizeof(dt), "%H:%M:%S", localtime(&now));
    std::string color = "\033[97m"; 
    if(tag == "[系统]") color = "\033[94m";
    if(tag == "[登录]") color = "\033[95m";
    if(tag == "[操作]") color = "\033[93m";
    if(tag == "[安全]") color = "\033[91m"; // Red
    
    std::string out = color + "[" + dt + "] " + tag + " " + msg + "\033[0m";
    std::cout << out << std::endl;
    
    if(g_console_sock != INVALID_SOCKET) {
        std::string cmsg = "\r" + out + "\nConsole > ";
        send(g_console_sock, cmsg.c_str(), (int)cmsg.size(), 0);
    }
}

void rotate_admin_key() {
    char tmp[16];
    sprintf(tmp, "%d", rand() % 900000 + 100000);
    ADMIN_KEY = tmp;
    std::string msg = "[系统] Admin Key Refreshed: " + ADMIN_KEY;
    std::cout << "\033[93m" << msg << "\033[0m" << std::endl;
    if(g_console_sock != INVALID_SOCKET) {
        std::string cmsg = "\r\033[93m" + msg + "\033[0m\nConsole > ";
        send(g_console_sock, cmsg.c_str(), (int)cmsg.size(), 0);
    }
}

void send_packet(SOCKET s, uint32_t type, const char* data, uint32_t len) {
    PacketHeader h;
    h.length = htonl(len);
    h.type = htonl(type);
    send(s, (char*)&h, sizeof(h), 0);
    if(len > 0) send(s, data, len, 0);
}

void send_packet_str(SOCKET s, uint32_t type, std::string msg) {
    send_packet(s, type, msg.c_str(), (uint32_t)msg.size());
}

void broadcast_room(const std::string& room, uint32_t type, const std::string& msg, SOCKET exclude = INVALID_SOCKET) {
    std::lock_guard<std::mutex> lk(g_mutex);
    for(auto it = clients.begin(); it != clients.end(); ++it) {
        if(it->second.room == room && it->second.checked && it->first != exclude) {
            send_packet(it->first, type, msg.c_str(), (uint32_t)msg.size());
        }
    }
}

void cleanup_socket(SOCKET s, int port) {
    std::unique_lock<std::mutex> lk(g_mutex);
    
    if (port == 8080 && clients.count(s)) {
        std::string n = clients[s].name;
        std::string r = clients[s].room;
        clients.erase(s);
        lk.unlock();
        broadcast_room(r, TYPE_SYSTEM, n + " 离开了房间。");
        server_log("[离线]", n);
    } 
    else if (port == 9001 && admins.count(s)) {
        admins.erase(s);
        lk.unlock();
    }
    else if (port == 7891 && s == g_console_sock) {
        g_console_sock = INVALID_SOCKET;
        lk.unlock();
        std::cout << "[系统] 控制台断开连接" << std::endl;
    }
    else lk.unlock();
    
    shutdown(s, SD_BOTH);
    closesocket(s);
}

void perform_kick_ip(std::string ip) {
    std::vector<SOCKET> to_kick;
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        for(auto it = clients.begin(); it != clients.end(); ++it) {
            if(it->second.ip == ip) to_kick.push_back(it->first);
        }
    }
    for(size_t i=0; i<to_kick.size(); ++i) {
        send_packet_str(to_kick[i], TYPE_SYSTEM, "该IP已被封禁。");
        Sleep(50);
        cleanup_socket(to_kick[i], 8080);
    }
}

// --- 自动禁用逻辑 ---
void register_ip_violation(std::string ip) {
    std::lock_guard<std::mutex> lk(g_mutex);
    
    time_t now = time(0);
    std::deque<time_t>& records = ip_violation_records[ip];
    records.push_back(now);

    // 清除60秒前的记录
    while(!records.empty() && records.front() < now - 60) {
        records.pop_front();
    }

    // 检查是否自动禁用
    if(records.size() >= MAX_KICKS_PER_MIN) {
        banned_ips.insert(ip);
        
        // 记录日志
        std::string log_msg = "IP " + ip + " 频繁违规 (" + to_str(records.size()) + "次/分), 自动添加到黑名单";
        // 因为我们在 mutex 内部所以不能再去 lock 和 server_log，只能直接打印
        std::cout << "\033[91m[安全] " << log_msg << "\033[0m" << std::endl;
        if(g_console_sock != INVALID_SOCKET) {
            std::string cmsg = "\r\033[91m[安全] " + log_msg + "\033[0m\nConsole > ";
            send(g_console_sock, cmsg.c_str(), (int)cmsg.size(), 0);
        }

        // 我们已经在执行此操作了，严禁再试
        // 如果我们已经是在 lock 内部所以不能再去 perform_kick_ip (也是不对)
        // 所以直接用需要的 socket 做个循环处理或手动删除
        std::vector<SOCKET> to_kick;
        for(auto it = clients.begin(); it != clients.end(); ++it) {
            if(it->second.ip == ip) to_kick.push_back(it->first);
        }
        
        // 临时解锁然后去执行? 但这样又不安全呀
        // 因为这时候安全代码已经执行所以我们可以直接关闭这些 socket 吗?不可能如此简单
        // 为了安全考量我们直接处理以及然后继续锁太复杂（可能会死锁）
        // *推荐*：perform_kick_ip 方法下会重新获取新的 mutex 并处理所有的操作
        
        // 不过我们已经锁了，所以我们不能直接去 cleanup_socket (也是不对的)
        // 换个方式，我们只对 IP 做标记但不立即
        // 违规点数是在独立的 check_spam 函数返回 false 导致 client_thread 停止
        // 所以同IP新连接重新尝试消息时会检测到 ban 了
        // 所以，我们可以后台一个线程去做操作了。
        std::thread([ip](){ 
            Sleep(100); // 等待前面操作完成
            perform_kick_ip(ip); 
        }).detach();
    }
}

// --- 限流检测算法 ---
// 返回 false 表示触发限流
bool check_spam(SOCKET s, bool is_file) {
    std::lock_guard<std::mutex> lk(g_mutex);
    if(clients.find(s) == clients.end()) return true;

    ClientContext& ctx = clients[s];
    time_t now = time(0);
    std::deque<time_t>& q = is_file ? ctx.file_times : ctx.msg_times;

    // 添加到当前时间
    q.push_back(now);

    // 清除超过10秒前的记录
    while(!q.empty() && q.front() < now - 10) {
        q.pop_front();
    }

    bool spam = false;
    
    if(is_file) {
        // 文件限流: 10秒内不超过3个
        if(q.size() > LIMIT_FILE_10S) spam = true;
    } else {
        // 消息限流
        // 1. 检查10秒限制
        if(q.size() > LIMIT_MSG_10S) spam = true;
        
        // 2. 检查1秒内消息数 (最多连续两个)
        int count_1s = 0;
        for(auto it = q.rbegin(); it != q.rend(); ++it) {
            if(*it >= now - 1) count_1s++;
            else break;
        }
        if(count_1s > LIMIT_MSG_1S) spam = true;
    }

    if(spam) {
        return false; // 判断触发
    }
    return true; // 合法
}

// --- 控制台逻辑 ---
void console_thread(SOCKET s) {
    std::string welcome = "\033[96m┏━━━━━━ ROOT CONSOLE ━━━━━━┓\n┃ 指令: agree, kick,   ┃\n┃       ban, list      ┃\n┗━━━━━━━━━━━━━━━━━━━━━━━━━┛\033[0m\nConsole > ";
    send(s, welcome.c_str(), (int)welcome.size(), 0);
    
    char buf[1024];
    while(true) {
        int r = recv(s, buf, sizeof(buf)-1, 0);
        if(r <= 0) break;
        buf[r] = 0;
        std::string cmd(buf);
        cmd.erase(std::remove(cmd.begin(), cmd.end(), '\n'), cmd.end());
        cmd.erase(std::remove(cmd.begin(), cmd.end(), '\r'), cmd.end());
        if(cmd.empty()) { send(s, "Console > ", 10, 0); continue; }

        std::string resp = "";

        if(cmd.find("agree ") == 0) {
            std::string ip = cmd.substr(6);
            bool found = false;
            {
                std::lock_guard<std::mutex> lk(g_mutex);
                if(pending_bans.count(ip)) {
                    pending_bans.erase(ip);
                    banned_ips.insert(ip);
                    found = true;
                }
            }
            if(found) {
                perform_kick_ip(ip);
                resp = "\033[92m[成功] IP [" + ip + "] 已添加到黑名单并踢出用户！\033[0m";
                server_log("[操作]", "控制台通过核准: " + ip);
            } else {
                resp = "\033[91m[失败] 未找到待核准 IP 的操作记录！\033[0m";
            }
        }
        else if(cmd.find("ban ") == 0) {
            std::string ip = cmd.substr(4);
            { std::lock_guard<std::mutex> lk(g_mutex); banned_ips.insert(ip); }
            perform_kick_ip(ip);
            resp = "\033[92m[强制] IP [" + ip + "] 已被封禁\033[0m";
        }
        else if(cmd.find("kick ") == 0) {
            std::string target = cmd.substr(5);
            SOCKET ts = INVALID_SOCKET;
            {
                std::lock_guard<std::mutex> lk(g_mutex);
                for(auto it = clients.begin(); it != clients.end(); ++it) {
                    if(it->second.name == target) { ts = it->first; break; }
                }
            } 
            if(ts != INVALID_SOCKET) {
                send_packet_str(ts, TYPE_SYSTEM, "您已被控制台踢出！");
                std::thread([ts](){ Sleep(50); cleanup_socket(ts, 8080); }).detach();
                resp = "\033[92m[成功] 已踢出: " + target + "\033[0m";
            } else {
                resp = "\033[91m[失败] 未找到用户！\033[0m";
            }
        }
        else if(cmd == "list") {
            std::lock_guard<std::mutex> lk(g_mutex);
            resp = "\n\033[93m=== 在线用户 ===\033[0m\n";
            for(auto it = clients.begin(); it != clients.end(); ++it) {
                resp += " [" + it->second.room + "] " + it->second.name + " (" + it->second.ip + ")\n";
            }
            resp += "\n\033[93m=== 待审查Ban ===\033[0m\n";
            if(pending_bans.empty()) resp += " (无)\n";
            for(auto s : pending_bans) resp += " - " + s + "\n";
            
            resp += "\n\033[91m=== 自动违规统计 ===\033[0m\n";
            for(auto& kv : ip_violation_records) {
                if(!kv.second.empty()) 
                    resp += " IP: " + kv.first + " (总违规: " + to_str(kv.second.size()) + "次)\n";
            }
        }
        else if(cmd.find("unban ") == 0) {
            std::string ip = cmd.substr(6);
            { std::lock_guard<std::mutex> lk(g_mutex); banned_ips.erase(ip); ip_violation_records.erase(ip); }
            resp = "IP 已从黑名单移除";
        }
        else {
            resp = "未知的命令: list, kick, ban, unban, agree";
        }

        resp += "\nConsole > ";
        send(s, resp.c_str(), (int)resp.size(), 0);
    }
    cleanup_socket(s, 7891);
}

// --- 管理员线程 ---
void admin_thread(SOCKET s, std::string ip) {
    char buf[1024]; bool auth = false;
    while(true) {
        int r = recv(s, buf, sizeof(buf)-1, 0);
        if(r <= 0) break;
        buf[r] = 0;
        std::string raw(buf);
        raw.erase(std::remove(raw.begin(), raw.end(), '\n'), raw.end());
        raw.erase(std::remove(raw.begin(), raw.end(), '\r'), raw.end());

        if(!auth) {
            if(raw == "auth " + ADMIN_KEY) {
                auth = true;
                { std::lock_guard<std::mutex> lk(g_mutex); admins[s] = AdminContext(s, ip); }
                send(s, "OK", 2, 0);
                server_log("[登录]", "Admin Login: " + ip);
                rotate_admin_key(); 
            } else { send(s, "FAIL", 4, 0); break; }
            continue;
        }

        std::string response = "执行成功！";
        
        if(raw.find("ban ") == 0) {
            std::string target_ip = raw.substr(4);
            if(g_console_sock == INVALID_SOCKET) {
                response = "\033[91m[失败] 控制台未连接，无法提交申请\033[0m";
            } else {
                { std::lock_guard<std::mutex> lk(g_mutex); pending_bans.insert(target_ip); }
                std::string req = "\r\033[93m[请求] Admin(" + ip + ") 申请封禁 IP: " + target_ip + "\n执行命令 'agree " + target_ip + "' 来批准\033[0m\nConsole > ";
                send(g_console_sock, req.c_str(), (int)req.size(), 0);
                response = "\033[93m[请求已提交] 已通知控制台操作员\033[0m";
                server_log("[操作]", "Admin(" + ip + ") -> Ban " + target_ip);
            }
        }
        else if(raw.find("kick ") == 0) {
            std::string target = raw.substr(5);
            SOCKET ts = INVALID_SOCKET;
            {
                std::lock_guard<std::mutex> lk(g_mutex);
                for(auto it = clients.begin(); it != clients.end(); ++it) {
                    if(it->second.name == target) { ts = it->first; break; }
                }
            } 
            if(ts != INVALID_SOCKET) {
                send_packet_str(ts, TYPE_SYSTEM, "您已被管理员踢出！");
                std::thread([ts](){ Sleep(50); cleanup_socket(ts, 8080); }).detach();
                response = "已踢出 " + target;
            } else response = "\033[91m未找到用户！\033[0m";
        }
        else if(raw == "rooms") {
            std::lock_guard<std::mutex> lk(g_mutex);
            std::map<std::string, int> room_counts;
            int total = 0;
            for(auto& c : clients) { if(c.second.checked) { room_counts[c.second.room]++; total++; } }
            
            response = "\033[96m┏━━━━ 房间统计 (Total: " + to_str(total) + ") ━━━━┓\n";
            for(auto& rc : room_counts) {
                response += "┃ [" + rc.first + "] " + to_str(rc.second) + " 人\n";
            }
            response += "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\033[0m";
        }
        else if(raw == "admins") {
            std::lock_guard<std::mutex> lk(g_mutex);
            response = "\033[95m=== Admin List ===\n";
            for(auto& a : admins) response += " - IP: " + a.second.ip + "\n";
            response += "\033[0m";
        }
        else if(raw.find("say ") == 0) {
            std::string msg = "\033[91m安全警告：" + raw.substr(4) + "\033[0m";
            std::lock_guard<std::mutex> lk(g_mutex);
            for(auto& c : clients) send_packet_str(c.first, TYPE_TEXT, msg);
        }
        else if(raw == "list") {
             std::lock_guard<std::mutex> lk(g_mutex);
             response = "当前在线: " + to_str(clients.size()) + " (使用 rooms 查看房间)";
        }
        
        std::string feedback = "\033[96m[Admin] " + response + "\033[0m\n";
        send(s, feedback.c_str(), (int)feedback.size(), 0);
    }
    cleanup_socket(s, 9001);
}

// --- 客户端线程 (8080) ---
void client_thread(SOCKET s, std::string ip) {
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        if(banned_ips.count(ip)) {
            send_packet_str(s, TYPE_SYSTEM, "\033[91m该IP已被封禁。\033[0m");
            closesocket(s); return;
        }
    }

    std::vector<char> buffer; char tmp[4096];
    while(true) {
        int r = recv(s, tmp, sizeof(tmp), 0);
        if(r <= 0) break;
        buffer.insert(buffer.end(), tmp, tmp + r);

        while(buffer.size() >= sizeof(PacketHeader)) {
            PacketHeader* h = (PacketHeader*)buffer.data();
            uint32_t len = ntohl(h->length);
            uint32_t type = ntohl(h->type);
            if(buffer.size() < sizeof(PacketHeader) + len) break;
            
            std::string body(buffer.data() + sizeof(PacketHeader), len);
            
            // --- 预处理登录逻辑 ---
            if(type == TYPE_LOGIN) {
                { std::lock_guard<std::mutex> lk(g_mutex); clients[s] = ClientContext(s, body, ip, "Lobby"); }
                std::string welcome = "欢迎进入聊天室 v2.2\n当前房间: [Lobby]  IP: " + ip;
                send_packet_str(s, TYPE_SYSTEM, welcome);
            }
            else if(type == TYPE_CHECK_L) {
                if(body.find(SERVER_VERSION) == 0) {
                    std::string name;
                    { std::lock_guard<std::mutex> lk(g_mutex); clients[s].checked = true; name = clients[s].name; }
                    broadcast_room("Lobby", TYPE_SYSTEM, name + " 加入了房间。");
                    server_log("[登录]", name + " (" + ip + ")");
                } else { 
                    server_log("[安全]", "客户端版本验证失败: " + ip);
                    cleanup_socket(s, 8080); return; 
                }
            }
            // --- 关键的限流检测逻辑 (针对 TYPE_TEXT 和 TYPE_FILE_HEADER) ---
            else if(type == TYPE_TEXT || type == TYPE_FILE_HEADER) {
                bool is_file = (type == TYPE_FILE_HEADER);
                
                // 1. 调用检查函数
                if(!check_spam(s, is_file)) {
                    server_log("[安���]", "检测到限流/刷屏行为: " + ip);
                    
                    // 2. 提示用户踢出
                    send_packet_str(s, TYPE_SYSTEM, "\033[91m[警告] 检测到限流/灌水现象，您将被踢出！\033[0m");
                    
                    // 3. 记录违规点数 (触发自动禁用IP逻辑)
                    register_ip_violation(ip);
                    
                    // 4. 关闭连接
                    cleanup_socket(s, 8080); 
                    return; // 结束线程
                }

                // --- 消息业务逻辑 ---
                if(type == TYPE_TEXT) {
                    std::string n, r_name;
                    { std::lock_guard<std::mutex> lk(g_mutex); n = clients[s].name; r_name = clients[s].room; }
                    
                    if(body.find("/join ") == 0) {
                        std::string new_room = body.substr(6);
                        if(!new_room.empty()) {
                            broadcast_room(r_name, TYPE_SYSTEM, n + " 离开了房间。");
                            { std::lock_guard<std::mutex> lk(g_mutex); clients[s].room = new_room; }
                            send_packet_str(s, TYPE_SYSTEM, "切换房间成功: [" + new_room + "]");
                            broadcast_room(new_room, TYPE_SYSTEM, n + " 加入了房间。", s);
                        }
                    }
                    else if(body == "/who") {
                        std::string user_list = "\033[93m=== [" + r_name + "] 在线人员 ===\n";
                        {
                            std::lock_guard<std::mutex> lk(g_mutex);
                            for(auto& c : clients) {
                                if(c.second.room == r_name) user_list += " - " + c.second.name + "\n";
                            }
                        }
                        send_packet_str(s, TYPE_SYSTEM, user_list + "\033[0m");
                    }
                    else {
                        broadcast_room(r_name, TYPE_TEXT, n + ": " + body);
                    }
                }
                else if(type == TYPE_FILE_HEADER) {
                    // 文件头部信息转发
                    std::string r_name; { std::lock_guard<std::mutex> lk(g_mutex); r_name = clients[s].room; }
                    broadcast_room(r_name, type, body, s);
                }
            }
            else if(type == TYPE_FILE_CHUNK) {
                // 文件块通过普通速度转发，因为每一个独立文件会有很多块）所以不使用分开的频率限制
                // 所以只转发
                std::string r_name; { std::lock_guard<std::mutex> lk(g_mutex); r_name = clients[s].room; }
                broadcast_room(r_name, type, body, s);
            }

            buffer.erase(buffer.begin(), buffer.begin() + sizeof(PacketHeader) + len);
        }
    }
    cleanup_socket(s, 8080);
}

int main() {
    setup_console();
    print_banner();
    srand((unsigned)time(0));
    WSADATA w; WSAStartup(MAKEWORD(2,2), &w);
    
    rotate_admin_key();

    SOCKET s8080 = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a1; a1.sin_family = AF_INET; a1.sin_port = htons(8080); a1.sin_addr.s_addr = INADDR_ANY;
    bind(s8080, (sockaddr*)&a1, sizeof(a1)); listen(s8080, 10);

    SOCKET s9001 = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a2; a2.sin_family = AF_INET; a2.sin_port = htons(9001); a2.sin_addr.s_addr = INADDR_ANY;
    bind(s9001, (sockaddr*)&a2, sizeof(a2)); listen(s9001, 10);

    SOCKET s7891 = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a3; a3.sin_family = AF_INET; a3.sin_port = htons(7891); a3.sin_addr.s_addr = INADDR_ANY;
    bind(s7891, (sockaddr*)&a3, sizeof(a3)); listen(s7891, 10);

    server_log("[系统]", "服务器已启动 (Anti-Spam 模块开启)！");

    while(true) {
        fd_set fds; FD_ZERO(&fds);
        FD_SET(s8080, &fds); FD_SET(s9001, &fds); FD_SET(s7891, &fds);
        
        if(select(0, &fds, 0, 0, 0) > 0) {
            if(FD_ISSET(s8080, &fds)) {
                sockaddr_in addr; int l=sizeof(addr); SOCKET c = accept(s8080, (sockaddr*)&addr, &l);
                std::thread(client_thread, c, inet_ntoa(addr.sin_addr)).detach();
            }
            if(FD_ISSET(s9001, &fds)) {
                sockaddr_in addr; int l=sizeof(addr); SOCKET c = accept(s9001, (sockaddr*)&addr, &l);
                std::thread(admin_thread, c, inet_ntoa(addr.sin_addr)).detach();
            }
            if(FD_ISSET(s7891, &fds)) {
                SOCKET c = accept(s7891, 0, 0);
                if(g_console_sock != INVALID_SOCKET) { send(c, "Busy.\n", 6, 0); closesocket(c); }
                else { g_console_sock = c; std::thread(console_thread, c).detach(); }
            }
        }
    }
    return 0;
}
