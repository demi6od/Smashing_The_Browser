#pragma comment(lib, "DbgHelp.lib")

#include "CDebugger.h"
#include "CFuzz.h"
#include "DbgHelp.h"
#include <sstream>
#include <iomanip>

using namespace std;

namespace CppFuzz {

CDebugger::CDebugger(string symPath, DWORD dwTimeout, string ip, int port, string fuzzerId)
    : m_symPath(symPath), m_bKillOnExit(true), m_bActive(false), m_bModuleLoad(false), m_dwTimeout(dwTimeout) {
    m_pEventHandler = new CDebugEventHandler();
    m_pEventHandler->SetDebugger(this);

    m_pCrash = new CCrash(ip, port, fuzzerId);
    m_pSymbols = new CSymbols(symPath);
    m_pDisassembler = new CDisassembler();
}

void CDebugger::SetFuzz(CFuzz* pFuzz) {
    m_pFuzz = pFuzz;
}

void CDebugger::SetStartArg(LPCWSTR pExePath, LPTSTR pArg) {
    m_pExePath = pExePath;
    m_pArg = pArg;
}

void CDebugger::Monitor() {
    cout << "[+] Monitor with timeout: " << m_dwTimeout << endl;
    while (true) {
        Sleep(m_dwTimeout);

        cout << "[+] Timeout, resume debugger!" << endl;
        Detach();
    }
}

void CDebugger::Reset() {
    m_vProcessIds.clear();
    m_pCrash->Reset();
}

void CDebugger::Start() {
    // Reset debugger status
    Reset();

    STARTUPINFO startInfo;
    PROCESS_INFORMATION processInfo;

    ZeroMemory(&startInfo, sizeof(startInfo));
    startInfo.cb = sizeof(startInfo);
    ZeroMemory(&processInfo, sizeof(processInfo));

    bool bSuccess = CreateProcess(m_pExePath, m_pArg, NULL, NULL, false, DEBUG_PROCESS, NULL, NULL, &startInfo, &processInfo);
    if (bSuccess) {
        cout << "[+] Start debugging process: " << m_pExePath << endl;
    } else {
        cout << "[-] Could not start debugging process: " << m_pExePath << " Error = " << GetLastError() << endl;
    }

    m_bActive = true;
    DebugSetProcessKillOnExit(m_bKillOnExit);

    return DebugLoop();
}

void CDebugger::Attach(DWORD dwProcessId) {
    cout << "[+] Debugger attach to pid:" << dwProcessId << endl;

    m_bActive = DebugActiveProcess(dwProcessId);
    if (m_bActive) {
        bool bSuccess = DebugSetProcessKillOnExit(m_bKillOnExit);
        DebugLoop();
    } else {
        cout << "[-] Attach failed!" << endl;
    }
}

bool CDebugger::Detach() {
    cout << "\n[+] Detach debugger!" << endl;

    for (auto dwProcessId : m_vProcessIds) {
        cout << "[+] Detach pid: " << dwProcessId << endl;
        DebugActiveProcessStop(dwProcessId);

        // Terminate process
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
        TerminateProcess(hProcess, 0);
    }

    m_bActive = false;
    return m_bActive;
}

void CDebugger::DebugLoop() {
    DEBUG_EVENT DebugEvt = { 0 };
    LPDEBUG_EVENT lpDebugEvt = &DebugEvt;

    while (m_bActive) { 
        WaitForDebugEvent(lpDebugEvt, 60 * 1000); 
        m_pEventHandler->SetContinueStatus(DBG_EXCEPTION_NOT_HANDLED);

        switch (lpDebugEvt->dwDebugEventCode) { 
            case EXCEPTION_DEBUG_EVENT: 
                m_pEventHandler->OnException(lpDebugEvt);
                break;
            case CREATE_THREAD_DEBUG_EVENT: 
                m_pEventHandler->OnCreateThreadDebugEvent(lpDebugEvt);
                break;
            case CREATE_PROCESS_DEBUG_EVENT: 
                m_pEventHandler->OnCreateProcessDebugEvent(lpDebugEvt);
                break;
            case EXIT_THREAD_DEBUG_EVENT: 
                m_pEventHandler->OnExitThreadDebugEvent(lpDebugEvt);
                break;
            case EXIT_PROCESS_DEBUG_EVENT: 
                m_pEventHandler->OnExitProcessDebugEvent(lpDebugEvt);
                break;
            case LOAD_DLL_DEBUG_EVENT: 
                m_pEventHandler->OnLoadDllDebugEvent(lpDebugEvt);
                break;
            case UNLOAD_DLL_DEBUG_EVENT: 
                m_pEventHandler->OnUnloadDllDebugEvent(lpDebugEvt);
                break;
            case OUTPUT_DEBUG_STRING_EVENT: 
                m_pEventHandler->OnOutputDebugStringEvent(lpDebugEvt);
                break;
            case RIP_EVENT:
                m_pEventHandler->OnRipEvent(lpDebugEvt);
                break;
            default:
                cout << "[*] Unknown debug event!" << endl;
        } 

        ContinueDebugEvent(lpDebugEvt->dwProcessId, lpDebugEvt->dwThreadId, m_pEventHandler->GetContinueStatus());
    }
}

void CDebugger::UpdateContext(DWORD dwThreadId) {
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, dwThreadId);

    m_context.ContextFlags = CONTEXT_ALL;
    bool bSuccess = GetThreadContext(hThread, &m_context);
    if (!bSuccess) {
        cout << "[-] Could not get context for thread. Error = " << GetLastError() << endl;
    }
}

void CDebugger::PrintContext(DWORD dwThreadId) {
    stringstream ssContext;

    UpdateContext(dwThreadId);
    ssContext << uppercase << hex 
        << "eax = 0x" << setfill('0') << setw(8) << m_context.Eax 
        << " \nebx = 0x" << setfill('0') << setw(8) << m_context.Ebx 
        << " \necx = 0x" << setfill('0') << setw(8) << m_context.Ecx
        << " \nedx = 0x" << setfill('0') << setw(8) << m_context.Edx 
        << " \nesp = 0x" << setfill('0') << setw(8) << m_context.Esp 
        << " \nebp = 0x" << setfill('0') << setw(8) << m_context.Ebp
        << " \nesi = 0x" << setfill('0') << setw(8) << m_context.Esi 
        << " \nedi = 0x" << setfill('0') << setw(8) << m_context.Edi 
        << " \neip = 0x" << setfill('0') << setw(8) << m_context.Eip 
        << " " << endl;

    m_pCrash->AddLog("\nRegisters:\n" + ssContext.str());
}

void CDebugger::PrintCallStack(DWORD dwThreadId, DWORD dwProcessId) {
    STACKFRAME64 stackFrame = { 0 };
    const DWORD_PTR dwMaxFrames = 50;

    UpdateContext(dwThreadId);

    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Mode = AddrModeFlat;

    DWORD dwMachineType = IMAGE_FILE_MACHINE_I386;
    stackFrame.AddrPC.Offset = m_context.Eip;
    stackFrame.AddrFrame.Offset = m_context.Ebp;
    stackFrame.AddrStack.Offset = m_context.Esp;

    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, dwThreadId);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

    m_pSymbols->RefreshSymbols(hProcess);

    // Print call stack
    stringstream ssCallStack;
    for (int i = 0; i < dwMaxFrames; ++i) {
        bool bSuccess = StackWalk64(dwMachineType, hProcess, hThread, &stackFrame,
            (dwMachineType == IMAGE_FILE_MACHINE_I386 ? nullptr : &m_context), nullptr,
            SymFunctionTableAccess64, SymGetModuleBase64, nullptr);
        if (!bSuccess || stackFrame.AddrPC.Offset == 0) {
            cout <<  "StackWalk64 finished." << endl;
            break;
        }

        IMAGEHLP_MODULE64 module = {0};
        module.SizeOfStruct = sizeof(module);
        SymGetModuleInfo64(hProcess, (DWORD64)stackFrame.AddrPC.Offset, &module);

        //SymLoadModuleEx(hProcess, NULL, module.LoadedImageName, NULL, module.BaseOfImage,  0,  NULL, 0);
        //cout << "modulePath: " << module.LoadedImageName << ", baseofdll: " << module.BaseOfImage << ", symbol: " << module.LoadedPdbName << endl;
        PSYMBOL_INFO pSymInfo = m_pSymbols->SymbolFromAddress(stackFrame.AddrPC.Offset);
        if (pSymInfo) {
            ssCallStack << "#" << dec << i << " " <<  module.ModuleName << "!" << pSymInfo->Name << endl;
        } else {
            ssCallStack << "#" << dec << i << " " <<  module.ModuleName << "!" << "unknown" << endl;
        }

        delete pSymInfo;
    }

    m_pCrash->GetHash(ssCallStack.str());
    m_pCrash->AddLog("\nCall Stack\n" + ssCallStack.str());
}

void CDebugger::PrintDisAsm(DWORD dwProcessId, DWORD_PTR dwAddress) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    string disasm = m_pDisassembler->Disassemble(hProcess, dwAddress);
    m_pCrash->AddLog("\nCode:\n" + disasm);
}

void CDebugger::DumpCrash(DWORD dwThreadId, DWORD dwProcessId, DWORD_PTR dwAddress) {
    PrintContext(dwThreadId);
    PrintDisAsm(dwProcessId, dwAddress);
    PrintCallStack(dwThreadId, dwProcessId);

    m_pCrash->Send();
    m_pCrash->PrintLog();
}

void CDebugger::Hook(DWORD dwProcessId) {
    if (!m_pFuzz->m_bHook) {
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

    // Load symbol
    m_pSymbols->RefreshSymbols(hProcess);
    SymLoadModuleEx(hProcess, NULL, m_pModulePath, NULL, m_dwBaseOfDll,  0,  NULL, 0);
    cout << "mod: " << m_pModulePath << "addr: " << m_dwBaseOfDll << endl;

    // Find api address
    PSYMBOL_INFO pSymInfo = m_pSymbols->SymbolFromName(m_pFuzz->m_pHookApi);
    if (pSymInfo) {
        cout << "[+] Address of " << pSymInfo->Name << ": " << pSymInfo->Address << endl;
    } else {
        cout << "[-] Address of " << m_pFuzz->m_pHookApi << " not found!" << endl;
        return;
    }

    unsigned int iHookAddr = (unsigned int)pSymInfo->Address;

    // Hook api address
    SIZE_T iWriteBytes;

    bool bSuccess = WriteProcessMemory(hProcess, (void*)iHookAddr, (void*)m_pFuzz->m_pHookCode, sizeof(m_pFuzz->m_pHookCode), &iWriteBytes);
    if (bSuccess) {
        cout << "[+] Hook success at" << iHookAddr << endl;
    } else {
        cout << "[-] Hook failed at" << iHookAddr << endl;
    }
}

} // namespace CppFuzz
