#include "CDisassembler.h"

#include <string>
#include <sstream>
#include <iostream>

using namespace std;

namespace CppFuzz {

CDisassembler::CDisassembler() {
#ifdef _M_IX86
    m_disassembler.Archi = 0;
    m_hDll = LoadLibrary(L"BeaEngine_x86.dll");
    m_pDisasm = (pDisasm)GetProcAddress(m_hDll, "_Disasm@4");
#elif defined _M_AMD64
    m_disassembler.Archi = 64;
    m_hDll = LoadLibrary(L"BeaEngine_x64.dll");
    m_pDisasm = (pDisasm)GetProcAddress(m_hDll, "Disasm");
#else
#error "Unsupported architecture"
#endif
}

CDisassembler::~CDisassembler() {
    if (m_hDll != nullptr) {
        FreeLibrary(m_hDll);
    }
}

string CDisassembler::Disassemble(HANDLE hProcess, DWORD_PTR dwAddress, size_t ulInstructionsToDisassemble /*= 15*/) {
    // Read opcodes from debugee
    bool bSuccess = TransferOpcodes(hProcess, dwAddress);
    if (!bSuccess) {
        return "Invalid disasm address!\n";
    }

    stringstream ssDisasm;
    m_disassembler.EIP = (UIntPtr)m_opcodes.data();
    while (ulInstructionsToDisassemble > 0) {
        // Disassemble opcode
        int iDisasmLength = m_pDisasm(&m_disassembler);
        if (iDisasmLength != UNKNOWN_OPCODE) {
            ssDisasm << "0x" << uppercase << hex << dwAddress << " " << m_disassembler.CompleteInstr << endl;
            m_disassembler.EIP += iDisasmLength;
            dwAddress += iDisasmLength;
        } else {
            cout << "[-] Error: Reached unknown opcode in disassembly." << endl;
            break;
        }

        ulInstructionsToDisassemble--;
    }

    return ssDisasm.str();
}

bool CDisassembler::TransferOpcodes(HANDLE hProcess, DWORD_PTR dwAddress) {
    SIZE_T ulOpcodesRead = 0;
    bool bSuccess = ReadProcessMemory(hProcess, (LPCVOID)dwAddress, m_opcodes.data(), m_opcodes.size(), &ulOpcodesRead);
    return bSuccess;
}

} // namespace CppFuzz
