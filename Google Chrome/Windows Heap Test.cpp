// Windows Heap Test.cpp : Defines the entry point for the console application.

#include "stdafx.h"
#include <windows.h>
#include <iostream>

using namespace std;

int _tmain(int argc, _TCHAR* argv[]) {
    cout << "[+] Start" << endl;

    int debug = 0;
    cout << "[+] Wait for debug" << endl;
    cin >> debug;

	// Copy the hardware information to the SYSTEM_INFO structure. 
	SYSTEM_INFO siSysInfo;	
	GetSystemInfo(&siSysInfo);

	// Display the contents of the SYSTEM_INFO structure. 
	cout << "[+] Hardware information:" << endl;
	cout << "Page size: 0x" << hex << siSysInfo.dwPageSize << endl;
	cout << "VirtualAlloc Allocation granularity : 0x" << hex << siSysInfo.dwAllocationGranularity << endl;

	LPVOID lpvResult[10];
    HANDLE hHeap[10];
    HANDLE hHeapBlock[10];
    HANDLE hDefaultHeapBlock[10];
    HANDLE hLargeHeapBlock[10];

    unsigned int virtualSize = 0x100000;
    unsigned int heapSize = 0x10000;
    unsigned int heapBlockSize = 0x1000;
    unsigned int largeHeapBlockSize = 0x100000;
    unsigned int heapBlockHeadLen = 0x8;
    unsigned int largeHeapBlockHeadLen = 0x20;
    unsigned int base = 0;

    cout << "\n[+] VirtualAlloc" << endl;
    for (int i = 0; i < 10; i++) {
        lpvResult[i] = VirtualAlloc((LPVOID)base, virtualSize, MEM_COMMIT, PAGE_READWRITE);
        cout << i << ": " << lpvResult[i] << endl;
    }

    cout << "\n[+] HeapCreate" << endl;
    for (int i = 0; i < 10; i++) {
        hHeap[i] = HeapCreate(base, heapSize, 0); 
        cout << i << ": " << hHeap[i] << endl;
    }

    cout << "\n[+] HeapAlloc" << endl;
    for (int i = 0; i < 10; i++) {
        hHeapBlock[i] = HeapAlloc(hHeap[0], 0, heapBlockSize - heapBlockHeadLen);
        cout << i << ": " << hHeapBlock[i] << endl;
    }

    cout << "\n[+] Default HeapAlloc" << endl;
    for (int i = 0; i < 10; i++) {
        hDefaultHeapBlock[i] = HeapAlloc(GetProcessHeap(), 0, heapBlockSize - heapBlockHeadLen);
        cout << i << ": " << hDefaultHeapBlock[i] << endl;
    }

    cout << "\n[+] Large HeapAlloc" << endl;
    for (int i = 0; i < 10; i++) {
        hLargeHeapBlock[i] = HeapAlloc(GetProcessHeap(), 0, largeHeapBlockSize - largeHeapBlockHeadLen);
        cout << i << ": " << hLargeHeapBlock[i] << endl;
    }
        
    cout << "\n[+] End" << endl;
	return 0;
}

