#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <fstream>
#include <atomic>
#include <sstream>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

// --- 协议 ---
enum PacketType { TYPE_LOGIN=1, TYPE_TEXT=2, TYPE_FILE_HEADER=3, TYPE_FILE_CHUNK=4, TYPE_SYSTEM=5, TYPE_CHECK_L=10086 };
struct PacketHeader {
	uint32_t len;
	uint32_t type;
};

// --- 验证密钥 (必须与服务端一致) ---
const std::string SERVER_VERSION = "DBD311EBDE5B214A54EFEB28DB774E3E9B665FF0D5EB61F3AEA5BC4E44B5264B2FBA3CFD49320402784A094248DCAD46C770966A841E0418FB4124AF9ED25A4E";

// --- 全局变量 ---
SOCKET g_sock = INVALID_SOCKET;
SOCKET g_admin_sock = INVALID_SOCKET;
std::atomic<bool> g_running(true);
std::string g_srv_ip;
std::string g_name;

// --- 辅助 ---
template <typename T>
std::string to_str(T value) {
	std::ostringstream os;
	os << value;
	return os.str();
}

void setup_console() {
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
	DWORD dwMode = 0;
	if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &dwMode)) {
		dwMode |= 0x0004;
		SetConsoleMode(hOut, dwMode);
	}
	DWORD dwInMode = 0;
	if (hIn != INVALID_HANDLE_VALUE && GetConsoleMode(hIn, &dwInMode)) {
		dwInMode |= 0x0080;
		dwInMode &= ~0x0040;
		SetConsoleMode(hIn, dwInMode);
	}
}

void draw_prompt() {
	std::cout << "\033[92m[" << g_name << "]\033[0m > " << std::flush;
}

void draw_bar(long long cur, long long tot) {
	int w = 30;
	float p = (float)cur/tot;
	int pos = (int)(w * p);
	std::cout << "\r\033[93m发送中: [";
	for(int i=0; i<w; ++i) std::cout << (i<pos ? "=" : (i==pos ? ">" : " "));
	std::cout << "] " << int(p*100) << "%\033[0m" << std::flush;
}

void send_pkt(uint32_t t, const char* d, uint32_t l) {
	PacketHeader h;
	h.len = htonl(l);
	h.type = htonl(t);
	send(g_sock, (char*)&h, sizeof(h), 0);
	if(l > 0) send(g_sock, d, l, 0);
}

void upload_file(std::string path) {
	std::ifstream f(path.c_str(), std::ios::binary|std::ios::ate);
	if(!f) {
		std::cout << "\n\033[91m文件不存在！\033[0m\n";
//		draw_prompt();

		return;
	}
	long long sz = f.tellg();
	f.seekg(0);

	std::string fname = path;
	size_t last_slash = path.find_last_of("\\/");
	if (last_slash != std::string::npos) fname = path.substr(last_slash + 1);

	std::string head = fname + "|" + to_str(sz);
	send_pkt(TYPE_FILE_HEADER, head.c_str(), (uint32_t)head.size());

	char buf[4096];
	long long sent = 0;
	while(sent < sz) {
		f.read(buf, 4096);
		int n = (int)f.gcount();
		send_pkt(TYPE_FILE_CHUNK, buf, n);
		sent += n;
		draw_bar(sent, sz);
		Sleep(1);
	}
	std::cout << "\n发送完成。\n";
//	draw_prompt();
}

void recv_thread() {
	std::vector<char> buf;
	char tmp[4096];
	std::ofstream fs;
	long long f_tot=0, f_cur=0;
	bool f_active=false;

	while(g_running) {
		int r = recv(g_sock, tmp, sizeof(tmp), 0);
		if(r <= 0) break;
		buf.insert(buf.end(), tmp, tmp + r);

		while(buf.size() >= sizeof(PacketHeader)) {
			PacketHeader* h = (PacketHeader*)buf.data();
			uint32_t l = ntohl(h->len), t = ntohl(h->type);
			if(buf.size() < sizeof(PacketHeader) + l) break;

			std::string body(buf.data()+sizeof(PacketHeader), l);

			std::cout << "\r\033[K";
			if(t == TYPE_SYSTEM) std::cout << "\033[96m[系统] " << body << "\033[0m\n";
			else if(t == TYPE_TEXT) std::cout << body << "\n";
			else if(t == TYPE_FILE_HEADER) {
				size_t p = body.find_last_of('|');
				std::string name = "recv_" + body.substr(0, p);
				f_tot = atoll(body.substr(p+1).c_str());
				fs.open(name.c_str(), std::ios::binary);
				f_active = true;
				f_cur = 0;
				std::cout << "\033[93m[文件] 接收中: " << name << "\033[0m\n";
			} else if(t == TYPE_FILE_CHUNK && f_active) {
				fs.write(body.c_str(), l);
				f_cur += l;
				if(f_cur >= f_tot) {
					fs.close();
					f_active = false;
					std::cout << "\033[92m[文件] 接收完毕。\033[0m\n";
				}
			}

			buf.erase(buf.begin(), buf.begin() + sizeof(PacketHeader) + l);
			draw_prompt();
		}
	}
	std::cout << "\n\033[91m与服务器断开连接。\033[0m\n";
	exit(0);
}

void admin_recv_thread() {
	char buf[2048];
	while(g_admin_sock != INVALID_SOCKET) {
		int r = recv(g_admin_sock, buf, sizeof(buf)-1, 0);
		if(r <= 0) break;
		buf[r] = 0;
		std::cout << "\r\033[K" << buf << "";
//		draw_prompt();
	}
}

void enter_admin_mode(std::string key) {
	if(g_admin_sock != INVALID_SOCKET) {
		std::cout << "已经是管理员了。\n";
		draw_prompt();
		return;
	}

	g_admin_sock = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in a;
	a.sin_family=AF_INET;
	a.sin_port=htons(9001);
	a.sin_addr.s_addr=inet_addr(g_srv_ip.c_str());

	if(connect(g_admin_sock, (sockaddr*)&a, sizeof(a)) != 0) {
		std::cout << "\033[91m连接管理端口失败。\033[0m\n";
		draw_prompt();
		closesocket(g_admin_sock);
		g_admin_sock = INVALID_SOCKET;
		return;
	}

	std::string cmd = "auth " + key + "\n";
	send(g_admin_sock, cmd.c_str(), (int)cmd.size(), 0);

	char buf[16];
	int r = recv(g_admin_sock, buf, sizeof(buf)-1, 0);
	if(r > 0) {
		buf[r] = 0;
		if(std::string(buf).find("OK") != std::string::npos) {
			std::cout << "\033[92m[Admin] 权限获取成功。\033[0m\n";
			std::thread(admin_recv_thread).detach();
		} else {
			std::cout << "\033[91m[Admin] 密码错误。\033[0m\n";
			closesocket(g_admin_sock);
			g_admin_sock = INVALID_SOCKET;
		}
	}
	draw_prompt();
}

int main() {
	setup_console();
	WSADATA w;
	WSAStartup(MAKEWORD(2,2), &w);

	std::cout << "\033[96m=== CLIENT v2.1.1 ===\033[0m\n";
	std::cout << "服务器 IP (默认 127.0.0.1): ";
	std::getline(std::cin, g_srv_ip);
	if(g_srv_ip.empty()) g_srv_ip = "127.0.0.1";

	g_sock = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in a;
	a.sin_family=AF_INET;
	a.sin_port=htons(8080);
	a.sin_addr.s_addr=inet_addr(g_srv_ip.c_str());
	if(connect(g_sock, (sockaddr*)&a, sizeof(a)) != 0) {
		std::cout << "\033[91m无法连接到服务器。\033[0m\n";
		return 1;
	}

	std::cout << "输入昵称: ";
	std::getline(std::cin, g_name);
	send_pkt(TYPE_LOGIN, g_name.c_str(), (uint32_t)g_name.size());

	// --- 使用新的密钥进行握手验证 ---
	std::string v = SERVER_VERSION + g_name;
	send_pkt(TYPE_CHECK_L, v.c_str(), (uint32_t)v.size());

	std::thread(recv_thread).detach();

	std::cout << "\n\033[93m指令: /admin <key> | /join <房间> | /sendfile <路径>\033[0m\n";
	draw_prompt();

	std::string line;
	while(std::getline(std::cin,line)) {
		if(line.empty()) {
			draw_prompt();
			continue;
		}

		if(line.find("/admin ") == 0) {
			std::string key = line.substr(7);
			enter_admin_mode(key);
		} else if(line.find("/sendfile ") == 0) {
			upload_file(line.substr(10));
		} else {
			bool sent_as_admin = false;
			if(g_admin_sock != INVALID_SOCKET) {
				// 检查是否为管理员指令
				if(line.find("kick ") == 0 || line.find("say ") == 0 ||
				        line.find("unban ") == 0 || line == "list" ||
				        line.find("ban ") == 0 || line == "rooms" || line == "admins") {

					line += "\n";
					send(g_admin_sock, line.c_str(), (int)line.size(), 0);
					sent_as_admin = true;
				}
			}

			if(!sent_as_admin) {
				send_pkt(TYPE_TEXT, line.c_str(), (uint32_t)line.size());
			}
		}
		draw_prompt();
	}
	return 0;
}

