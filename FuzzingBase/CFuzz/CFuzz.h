#ifndef CPPFUZZ_H
#define CPPFUZZ_H

#include "CDebugger.h"

namespace CppFuzz {

class CFuzz {
public:
    friend class CDebugger;
    friend class CDebugEventHandler;

    CFuzz(std::string symPath, DWORD dwTimeout, std::string ip, int port, std::string fuzzerId);
    ~CFuzz() = default;

    void SetHook(char *pHookModule, char *pHookApi, char *pHookCode , bool bHook);
    void Run(LPCWSTR pExePath, LPTSTR pCmd);

private:
    CDebugger *m_pDebugger;

    bool m_bHook;
    char m_pHookModule[255];
    char m_pHookApi[255];
    char m_pHookCode[255];

    std::string m_fuzzerId;
};

} // namespace CppFuzz

#endif // CPPFUZZ_H
