#include "CCrash.h"
#include "CDebugger.h"
#include "CFuzz.h"

#include <iostream>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

namespace CppFuzz {

CCrash::CCrash(string ip, int port, string fuzzerId) {
    m_ip = ip;
    m_port = port;
    m_fuzzerId = fuzzerId;

    Connect();
}

CCrash::~CCrash() {
    WSACleanup();
}

void CCrash::Reset() {
    m_log = "";
    m_hash = "";
}

void CCrash::Connect() {
    cout << "[+] Connect to crash server: " << m_ip << ":" << m_port << endl;

    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);

    m_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    struct sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(sockaddr_in));
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.S_un.S_addr = inet_addr(m_ip.c_str());
    serverAddress.sin_port = htons(m_port);

    if (connect(m_sock, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR) {
        cout << "[-] Connect to server failed!" << endl;
        Sleep(INFINITE);
    }

    // |--fuzzer id (2 bytes)--|--socket type (10 byte)--|
    string handShake = m_fuzzerId + "CppSocket";
    if (send(m_sock, handShake.c_str(), handShake.length(), 0) == SOCKET_ERROR) {
        cout << "[-] Send hand shake failed!" << endl;
        Sleep(INFINITE);
    }
}

void CCrash::Send() {
    string crashData = m_log + "\n" + m_hash;
    if (send(m_sock, crashData.c_str(), crashData.length(), 0) == SOCKET_ERROR) {
        cout << "[-] Send crash data failed!" << endl;
        Sleep(INFINITE);
    }
}

void CCrash::AddLog(string log) {
    m_log += log;
}

void CCrash::PrintLog() {
    cout << m_log << endl;
    cout << m_hash << endl;
}

string CCrash::CalcHash(string data) {
    unsigned int hash = 0;
    for (char& ch : data) {
        hash = hash * 101  +  ch;
    }

    stringstream ssHash;
    ssHash << setfill ('0') << setw(sizeof(int)*2) << hex << hash;
    return ssHash.str();
}

void CCrash::GetHash(string callStack) {
    string fstCallStack;
    string sndCallStack;
    istringstream ssCallStack(callStack);
    string line;    

    int i = 0;
    for (int i = 0; getline(ssCallStack, line); i++) {
        if (i < 5) {
            fstCallStack += line;
        } else if (i < 10) {
            sndCallStack += line;
        }
    }

    //cout << fstCallStack << "\n" << sndCallStack << endl;
    m_hash = "hashBegin." + CalcHash(fstCallStack) + "." + CalcHash(sndCallStack) + ".hashEnd";
}

} // namespace CppFuzz
