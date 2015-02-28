#ifndef CDEBUGEVENTHANDLER_H
#define CDEBUGEVENTHANDLER_H

#include <string>
#include <iostream>
#include <windows.h>

namespace CppFuzz {

class CDebugger;
class CFuzz;

enum DebugEvents {
    //General events
    eException = EXCEPTION_DEBUG_EVENT,
    eCreateThread = CREATE_THREAD_DEBUG_EVENT,
    eCreateProcess = CREATE_PROCESS_DEBUG_EVENT,
    eExitThread = EXIT_THREAD_DEBUG_EVENT,
    eExitProcess = EXIT_PROCESS_DEBUG_EVENT,
    eLoadDll = LOAD_DLL_DEBUG_EVENT,
    eUnloadDll = UNLOAD_DLL_DEBUG_EVENT,
    eDebugString = OUTPUT_DEBUG_STRING_EVENT,
    eRipEvent = RIP_EVENT,
};

enum DebugExceptions {                     
    eAccessViolation = EXCEPTION_ACCESS_VIOLATION,
    eDataTypeMisalignment = EXCEPTION_DATATYPE_MISALIGNMENT,
    eBreakpoint = EXCEPTION_BREAKPOINT,
    eSingleStep = EXCEPTION_SINGLE_STEP,
    eArrayBoundsExceeded = EXCEPTION_ARRAY_BOUNDS_EXCEEDED,
    eFltDenormal = EXCEPTION_FLT_DENORMAL_OPERAND,
    eFltDivideByZero = EXCEPTION_FLT_DIVIDE_BY_ZERO,
    eFltInexactResult = EXCEPTION_FLT_INEXACT_RESULT,
    eFltInvalidOperation = EXCEPTION_FLT_INVALID_OPERATION,
    eFltOverflow = EXCEPTION_FLT_OVERFLOW,
    eFltStackCheck = EXCEPTION_FLT_STACK_CHECK,
    eFltUnderflow = EXCEPTION_FLT_UNDERFLOW,
    eIntDivideByZero = EXCEPTION_INT_DIVIDE_BY_ZERO,
    eIntOverflow = EXCEPTION_INT_OVERFLOW,
    ePrivilegedInstruction = EXCEPTION_PRIV_INSTRUCTION,
    ePageError = EXCEPTION_IN_PAGE_ERROR,
    eIllegalInstruction = EXCEPTION_ILLEGAL_INSTRUCTION,
    eNoncontinuableException = EXCEPTION_NONCONTINUABLE_EXCEPTION,
    eStackOverflow = EXCEPTION_STACK_OVERFLOW,
    eInvalidDisposition = EXCEPTION_INVALID_DISPOSITION,
    eGuardPage = EXCEPTION_GUARD_PAGE,
    eInvalidHandle = EXCEPTION_INVALID_HANDLE,
};

class CDebugEventHandler {
public:
    CDebugEventHandler();
    ~CDebugEventHandler() = default;

    void SetDebugger(CDebugger* debugger);
    DWORD GetContinueStatus();
    void SetContinueStatus(DWORD dwContinueStatus);

    virtual void OnException(const LPDEBUG_EVENT lpDebugEvt);

    virtual void OnCreateProcessDebugEvent(const LPDEBUG_EVENT lpDebugEvt);
    virtual void OnCreateThreadDebugEvent(const LPDEBUG_EVENT lpDebugEvt);
    virtual void OnLoadDllDebugEvent(const LPDEBUG_EVENT lpDebugEvt);

    virtual void OnExitThreadDebugEvent(const LPDEBUG_EVENT lpDebugEvt);
    virtual void OnExitProcessDebugEvent(const LPDEBUG_EVENT lpDebugEvt);
    virtual void OnUnloadDllDebugEvent(const LPDEBUG_EVENT lpDebugEvt);
    virtual void OnOutputDebugStringEvent(const LPDEBUG_EVENT lpDebugEvt);
    virtual void OnRipEvent(const LPDEBUG_EVENT lpDebugEvt);

private:
    CDebugger *m_pDebugger;
    DWORD m_dwContinueStatus;
};

} // namespace CppFuzz

#endif // CDEBUGEVENTHANDLER_H
