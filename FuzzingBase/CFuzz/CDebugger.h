#ifndef CDEBUGGER_H
#define CDEBUGGER_H

#include "CCrash.h"
#include "CDebugEventHandler.h"
#include "CSymbols.h"
#include "CDisassembler.h"
#include <vector>

namespace CppFuzz {

class CFuzz;

class CDebugger {
public:
    friend class CDebugEventHandler;

    CDebugger(std::string symPath, DWORD dwTimeout, std::string ip, int port, std::string fuzzerId);
    ~CDebugger() = default;

    void SetFuzz(CFuzz* pFuzz);

    void SetStartArg(LPCWSTR pExePath, LPTSTR pArg);
    void Start();
    void Reset();
    void Monitor();

    void Attach(DWORD dwProcessId);
    bool Detach();
    void DebugLoop();
    
    void UpdateContext(DWORD dwThreadId);
    void PrintContext(DWORD dwThreadId);
    void PrintCallStack(DWORD dwThreadId, DWORD dwProcessId);
    void PrintDisAsm(DWORD dwProcessId, DWORD_PTR dwAddress);
    void DumpCrash(DWORD dwThreadId, DWORD dwProcessId, DWORD_PTR dwAddress);

    void Hook(DWORD dwProcessId);

private:
    CFuzz *m_pFuzz;
    CDebugEventHandler *m_pEventHandler;
    CCrash *m_pCrash;
    CDisassembler *m_pDisassembler;

    bool m_bActive;
    bool m_bKillOnExit;

    std::vector<DWORD> m_vProcessIds;
    HANDLE m_hFile;
    CONTEXT m_context;

    LPCWSTR m_pExePath;
    LPTSTR m_pArg;

    DWORD m_dwTimeout;

    // Hook
    bool m_bModuleLoad;
    char m_pModulePath[MAX_PATH];
    DWORD64 m_dwBaseOfDll;

    CSymbols *m_pSymbols;
    std::string m_symPath;
};

} // namespace CppFuzz

#endif // CDEBUGGER_H
