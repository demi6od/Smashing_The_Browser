#ifndef CSYMBOLS_H
#define CSYMBOLS_H

#include <windows.h>
#include <string>
#include <iostream>
#include <Dbghelp.h>

#pragma comment(lib, "Dbghelp.lib")

namespace CppFuzz {

class CSymbols {
public:
    CSymbols(std::string symPath);
    ~CSymbols();

    void RefreshSymbols(HANDLE hProcess);
    PSYMBOL_INFO SymbolFromAddress(DWORD64 dwAddress);
    PSYMBOL_INFO SymbolFromName(char *pName);

private:
    HANDLE m_hProcess;
    std::string m_symPath;
};

} // namespace CppFuzz

#endif // CSYMBOLS_H
