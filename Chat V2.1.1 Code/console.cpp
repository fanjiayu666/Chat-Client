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

// --- 调用 main 函数之前 ---
// --- 初始化 main 函数之前 ---
void setup_console() {
    // 1. 获取控制台句柄
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    
    // 2. 启用彩色支持 (Windows 10+)
    DWORD dwMode = 0;
    if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &dwMode)) {
        dwMode |= 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
        SetConsoleMode(hOut, dwMode);
    }

    // 3. 修改输入模式 (防止选中文字会暂停)
    DWORD dwInMode = 0;
    if (hIn != INVALID_HANDLE_VALUE && GetConsoleMode(hIn, &dwInMode)) {
        dwInMode |= 0x0080; // ENABLE_EXTENDED_FLAGS
        dwInMode &= ~0x0040; // 清除快速编辑模式(禁选文本会暂停程序一刻钟停顿)
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
        std::cout << "\033[91m连接失败！请确保服务器已启动并监听端口 7891 正常。\033[0m\n";
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
            // 消息在前面显示，后面有用户输入提示符
            std::cout << "\r" << buf << std::flush;
        }
        run = false;
        std::cout << "\n[系统] 连接已断开！\n";
        exit(0);
    }).detach();

    std::string line;
    while (run && std::getline(std::cin, line)) {
        if (line == "exit") break;
        line += "\n";
        send(s, line.c_str(), (int)line.size(), 0);
        Sleep(10); // 防止消息堆积
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
