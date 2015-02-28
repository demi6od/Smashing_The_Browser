#ifndef CCRASH_H
#define CCRASH_H

#include <winsock2.h>
#include <string>

namespace CppFuzz {

class CFuzz;

class CCrash {
public:
    CCrash(std::string ip, int port, std::string fuzzerId);
    ~CCrash();

    void Connect();
    void Send();
    void Reset();
    void GetHash(std::string callStack);
    std::string CalcHash(std::string data);
    void AddLog(std::string);
    void PrintLog();

private:
    std::string m_ip;
    int m_port;
    SOCKET m_sock;

    std::string m_fuzzerId;

    std::string m_log;
    std::string m_hash;
};

} // namespace CppFuzz

#endif // CCRASH_H
