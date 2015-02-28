#include "CSymbols.h"

using namespace std;

namespace CppFuzz {

CSymbols::CSymbols(string symPath) :  m_hProcess(NULL), m_symPath(symPath) {
    SymSetOptions(SYMOPT_CASE_INSENSITIVE | SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME);
}

CSymbols::~CSymbols() {
    SymCleanup(m_hProcess);
}

void CSymbols::RefreshSymbols(HANDLE hProcess) {
    if (m_hProcess) {
        SymCleanup(m_hProcess);
    }

    m_hProcess = hProcess;
    bool bSuccess = SymInitialize(m_hProcess, m_symPath.c_str(), true);
    if (bSuccess) {
        cout << "[+] Symbol load success at " << m_symPath << endl;
    } else {
        cout << "[-] Symbol load failed at " << m_symPath << endl;
    }
}

PSYMBOL_INFO CSymbols::SymbolFromAddress(DWORD64 dwAddress) {
    char *pBuffer = new char[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char)];
    PSYMBOL_INFO pSymInfo = (PSYMBOL_INFO)pBuffer;

    pSymInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymInfo->MaxNameLen = MAX_SYM_NAME;
    DWORD64 dwDisplacement = 0;

    bool bSuccess = SymFromAddr(m_hProcess, dwAddress, &dwDisplacement, pSymInfo);
    if (!bSuccess) {
        delete pSymInfo;
        return NULL;
    }

    return pSymInfo;
}

PSYMBOL_INFO CSymbols::SymbolFromName(char *pName) {
    char *pBuffer = new char[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char)
        + sizeof(ULONG64) - 1 / sizeof(ULONG64)];
    PSYMBOL_INFO pSymInfo = (PSYMBOL_INFO)pBuffer;

    pSymInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymInfo->MaxNameLen = MAX_SYM_NAME;

    bool bSuccess = SymFromName(m_hProcess, pName, pSymInfo);
    if (!bSuccess) {
        delete pSymInfo;
        return NULL;
    }

    return pSymInfo;
}

} // namespace CppFuzz
