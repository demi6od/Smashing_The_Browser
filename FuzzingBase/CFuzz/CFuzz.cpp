#include "CFuzz.h"
#include <tchar.h>
#include "pugixml.hpp"

using namespace std;
using namespace CppFuzz;

namespace CppFuzz {

DWORD WINAPI StartMonitor(LPVOID lpDebugger) {
    cout << "[+] Start monitor" << endl;
    ((CDebugger*)lpDebugger)->Monitor();
    return 0;
}

CFuzz::CFuzz(string symPath, DWORD dwTimeout, string ip, int port, string fuzzerId) {
    m_fuzzerId = fuzzerId;
    m_pDebugger = new CDebugger(symPath, dwTimeout, ip, port, fuzzerId);
    m_pDebugger->SetFuzz(this);
}

void CFuzz::SetHook(char *pHookModule, char *pHookApi, char *pHookCode, bool bHook) {
    strcpy_s(m_pHookModule, sizeof(m_pHookModule), pHookModule);
    strcpy_s(m_pHookApi, sizeof(m_pHookApi), pHookApi);
    strcpy_s(m_pHookCode, sizeof(m_pHookCode), pHookCode);

    m_bHook = bHook;
}

void CFuzz::Run(LPCWSTR pExePath, LPTSTR pCmd) {
    // Start monitor thread
    cout << "[+] Create monitor thread" << endl;
    DWORD dwThreadId;
    HANDLE hThread = CreateThread(NULL, 0, StartMonitor, m_pDebugger, 0, &dwThreadId);
    if (hThread == NULL) {
        cout << "[-] Create thread failed!" << endl;
    }

    m_pDebugger->SetStartArg(pExePath, pCmd);
    while (true) {
        m_pDebugger->Start();
    }
}

} // namespace CppFuzz

int _tmain(int argc, _TCHAR* argv[]) {
    pugi::xml_document doc;
    if (!doc.load_file("config.xml")) {
        cout << "[-] Can not parse config xml file!" << endl;
        return -1;
    }

    string symPath = doc.child("symPath").child_value();
    cout << "[+] symPath: " << symPath << endl;

    string timeout = doc.child("timeout").child_value();
    cout << "[+] timeout: " << timeout << endl;
    DWORD dwTimeout = (DWORD)stoi(timeout);

    string ip = doc.child("ip").child_value();
    cout << "[+] ip: " << ip << endl;

    string port = doc.child("port").child_value();
    cout << "[+] port: " << port << endl;

    string fuzzerId = doc.child("id").child_value();
    cout << "[+] fuzzerId: " << fuzzerId << endl;

    CFuzz *pFuzz = new CFuzz(symPath, dwTimeout * 60 * 1000, ip, stoi(port), fuzzerId);
    //pFuzz->SetHook("jscript9", "StrToDbl<unsigned short>", "\x68\x0c\x0c\x0c\x0c\xc3", false);
    //pFuzz->SetHook("chrome_child", "v8::internal::Runtime_StringParseFloat", "\x68\x0c\x0c\x0c\x0c\xc3", true);
    //pFuzz->SetHook("chrome_child", "__asan_report_error", "\x68\x00\x00\x00\x00\xc3", true);

    string appPath = doc.child("appPath").child_value();
    wstring appPathW = wstring(appPath.begin(), appPath.end());
    cout << "[+] appPath: " << appPath << endl;

    string appName = appPath.substr(appPath.rfind("\\") + 1);
    cout << "[+] appName: " << appName << endl;

    string startArg = doc.child("startArg").child_value();
    cout << "[+] startArg: " << startArg << endl;

    string serverPath = doc.child("serverPath").child_value();
    string serverUrl = "http://" + ip + serverPath;
    cout << "[+] serverUrl: " << serverUrl << endl;

    string cmd = appName + " " + startArg + " " + serverUrl + fuzzerId + ".html";
    wstring cmdW = wstring(cmd.begin(), cmd.end());
    cout << "[+] cmd: " << cmd << endl;

    pFuzz->Run(appPathW.c_str(), (LPTSTR)cmdW.c_str());

    return 0;
}

