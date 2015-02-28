#ifndef CDISASSEMBLER_H
#define CDISASSEMBLER_H

#include "BeaEngine.h"
#include <array>
#include <windows.h>

namespace CppFuzz {

typedef int(__stdcall *pDisasm)(LPDISASM pDisAsm);

class CDisassembler {
public:
    CDisassembler();
    ~CDisassembler();

    std::string Disassemble(HANDLE hProcess, DWORD_PTR dwAddress, size_t ulInstructionsToDisassemble = 15);

private:
    HMODULE m_hDll;
    pDisasm m_pDisasm;

    DISASM m_disassembler;
    std::array<char, 4096> m_opcodes;

    bool TransferOpcodes(HANDLE hProcess, DWORD_PTR dwAddress);
};

} // namespace CppFuzz

#endif // CDISASSEMBLER_H
