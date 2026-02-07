#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <thread>
#include <atomic>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

// --- 放在 main 函数之前 ---
// --- 请放在 main 函数之前 ---
void setup_console() {
    // 1. 获取控制台句柄
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    
    // 2. 启用颜色支持 (Windows 10+)
    DWORD dwMode = 0;
    if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &dwMode)) {
        dwMode |= 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
        SetConsoleMode(hOut, dwMode);
    }

    // 3. 修复输入模式 (防止选中文字后程序暂停)
    DWORD dwInMode = 0;
    if (hIn != INVALID_HANDLE_VALUE && GetConsoleMode(hIn, &dwInMode)) {
        dwInMode |= 0x0080; // ENABLE_EXTENDED_FLAGS
        dwInMode &= ~0x0040; // 禁用快速编辑模式(可选，防止鼠标点一下就暂停)
        SetConsoleMode(hIn, dwInMode);
    }
}

int main() {
	setup_console();
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode; GetConsoleMode(hOut, &mode); SetConsoleMode(hOut, mode | 0x0004);
    
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);

    std::string ip;
    std::cout << "\033[95m=== ROOT CONSOLE CLIENT ===\033[0m\n";
    std::cout << "Target IP (Default 127.0.0.1): ";
    std::getline(std::cin, ip);
    if (ip.empty()) ip = "127.0.0.1";

    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr; addr.sin_family = AF_INET; addr.sin_port = htons(7891);
    addr.sin_addr.s_addr = inet_addr(ip.c_str());

    if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) {
        std::cout << "\033[91m连接失败。请确认服务器已启动且端口 7891 开放。\033[0m\n";
        return 1;
    }

    std::atomic<bool> run(true);
    // 接收线程
    std::thread([&]() {
        char buf[4096];
        while (run) {
            int r = recv(s, buf, sizeof(buf) - 1, 0);
            if (r <= 0) break;
            buf[r] = 0;
            // 清除当前行并输出接收到的内容
            std::cout << "\r" << buf << std::flush;
        }
        run = false;
        std::cout << "\n[系统] 连接断开。\n";
        exit(0);
    }).detach();

    std::string line;
    while (run && std::getline(std::cin, line)) {
        if (line == "exit") break;
        line += "\n";
        send(s, line.c_str(), (int)line.size(), 0);
        Sleep(10); // 防止输出混乱
    }

    closesocket(s);
    WSACleanup();
    return 0;
}

