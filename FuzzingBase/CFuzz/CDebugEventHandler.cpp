#include "CDebugger.h"
#include "CDebugEventHandler.h"
#include "CFuzz.h"

using namespace std;

namespace CppFuzz {

CDebugEventHandler::CDebugEventHandler(): m_dwContinueStatus(DBG_EXCEPTION_NOT_HANDLED) {
}

void CDebugEventHandler::SetDebugger(CDebugger* pDebugger) {
    m_pDebugger = pDebugger;
}

DWORD CDebugEventHandler::GetContinueStatus() {
    return m_dwContinueStatus;
}

void CDebugEventHandler::SetContinueStatus(DWORD dwContinueStatus) {
    m_dwContinueStatus = dwContinueStatus;
}

// Debug event call back
void CDebugEventHandler::OnException(const LPDEBUG_EVENT lpDebugEvt) {
    //cout << "\n[+] OnException" << endl;

    auto &exception = lpDebugEvt->u.Exception;
    /*
    cout << "First chance exception: " << exception.dwFirstChance 
        << "\nException code: " << hex << exception.ExceptionRecord.ExceptionCode
        << "\nException flags: " << exception.ExceptionRecord.ExceptionFlags
        << "\nException address: " << exception.ExceptionRecord.ExceptionAddress
        << "\nNumber parameters (associated with exception): " << exception.ExceptionRecord.NumberParameters
        << "\ntid: " << lpDebugEvt->dwThreadId
        << "\npid: " << lpDebugEvt->dwProcessId << endl;
    */

    string exceptionType;
    switch(lpDebugEvt->u.Exception.ExceptionRecord.ExceptionCode) { 
        case EXCEPTION_BREAKPOINT: 
            exceptionType = "EXCEPTION_BREAKPOINT";
            SetContinueStatus(DBG_CONTINUE);
            break;
        case EXCEPTION_ACCESS_VIOLATION: 
            exceptionType = "EXCEPTION_ACCESS_VIOLATION";
            break;
        case EXCEPTION_STACK_OVERFLOW: 
            exceptionType = "EXCEPTION_STACK_OVERFLOW";
            break;
        case EXCEPTION_GUARD_PAGE: 
            exceptionType = "EXCEPTION_GUARD_PAGE";
            break;
        case EXCEPTION_ILLEGAL_INSTRUCTION: 
            exceptionType = "EXCEPTION_ILLEGAL_INSTRUCTION";
            break;
        case 0xC0000409: 
            exceptionType = "STACK_BUFFER_OVERRUN";
            break;
        case 0xC0000374: 
            exceptionType = "HEAP_CORRUPTION";
            break;
        case 0xE06D7363: 
            exceptionType = "CPP_EXCEPTION";
            break;
        default:
            exceptionType = "OTHER_EXCEPTION";
            break;
    } 

    if (exceptionType != "OTHER_EXCEPTION") {
        cout << "[+] " << exceptionType << endl;
    }

    if (!exception.dwFirstChance) {
        cout << exceptionType << endl;
        m_pDebugger->m_pCrash->AddLog("Caught a " + exceptionType + " in process\n");
        m_pDebugger->DumpCrash(lpDebugEvt->dwThreadId, lpDebugEvt->dwProcessId,
            (DWORD_PTR)exception.ExceptionRecord.ExceptionAddress);

        m_pDebugger->Detach();
    }
}

void CDebugEventHandler::OnCreateProcessDebugEvent(const LPDEBUG_EVENT lpDebugEvt) {
    cout << "\n[+] OnCreateProcessDebugEvent" << endl;

    auto &info = lpDebugEvt->u.CreateProcessInfo;
    cout << "Handle (image file): " << info.hFile << "\nHandle (process): " << info.hProcess
        << "\nHandle (main thread): " << info.hThread << "\nImage base address: " << info.lpBaseOfImage
        << "\nDebug info file offset: " << info.dwDebugInfoFileOffset << "\nDebug info size: " << info.nDebugInfoSize
        << "\nTLS base: " << info.lpThreadLocalBase << "\nStart address: " << info.lpStartAddress << endl;

    m_pDebugger->m_vProcessIds.push_back(lpDebugEvt->dwProcessId);
    m_pDebugger->m_hFile = info.hFile;

    // Hook api for new process
    if (m_pDebugger->m_bModuleLoad) {
        m_pDebugger->Hook(lpDebugEvt->dwProcessId);
    }
}

void CDebugEventHandler::OnCreateThreadDebugEvent(const LPDEBUG_EVENT lpDebugEvt) { 
    /*
    cout << "\n[+] OnCreateThreadDebugEvent" << endl;

    auto &info = lpDebugEvt->u.CreateThread;
    cout << "Handle: " << info.hThread << "\nTLS base: " << info.hThread 
        << "\nStart address: " << info.lpStartAddress << endl;
    */
}

void CDebugEventHandler::OnLoadDllDebugEvent(const LPDEBUG_EVENT lpDebugEvt) {
    auto &info = lpDebugEvt->u.LoadDll;
    char strName[MAX_PATH] = { 0 };
    (void)GetFinalPathNameByHandleA(info.hFile, strName, sizeof(strName), FILE_NAME_NORMALIZED);
    string moduleName(strName);
    //cout << "\n[+] OnLoadDllDebugEvent: " << moduleName << endl;

    // Hook dll api
    if (!m_pDebugger->m_bModuleLoad && moduleName.find(m_pDebugger->m_pFuzz->m_pHookModule) != string::npos) {
        m_pDebugger->m_bModuleLoad = true;

        strcpy_s(m_pDebugger->m_pModulePath, sizeof(m_pDebugger->m_pModulePath), strName);
        m_pDebugger->m_dwBaseOfDll = (DWORD64)info.lpBaseOfDll;
        m_pDebugger->Hook(lpDebugEvt->dwProcessId);
    }
}

void CDebugEventHandler::OnExitThreadDebugEvent(const LPDEBUG_EVENT lpDebugEvt) {
    //cout << "\n[+] OnExitThreadDebugEvent" << endl;
}

void CDebugEventHandler::OnExitProcessDebugEvent(const LPDEBUG_EVENT lpDebugEvt) {
    cout << "\n[+] OnExitProcessDebugEvent" << endl;
}

void CDebugEventHandler::OnUnloadDllDebugEvent(const LPDEBUG_EVENT lpDebugEvt) {
    //cout << "\n[+] OnUnloadDllDebugEvent" << endl;
}

void CDebugEventHandler::OnOutputDebugStringEvent(const LPDEBUG_EVENT lpDebugEvt) {
    cout << "\n[+] OnOutputDebugStringEvent" << endl;
}

void CDebugEventHandler::OnRipEvent(const LPDEBUG_EVENT lpDebugEvt) {
    cout << "\n[+] OnRipEvent" << endl;
}

} // namespace CppFuzz
