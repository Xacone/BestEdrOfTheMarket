#pragma once

#include <iostream>
#include <Windows.h>
#include <DbgHelp.h>

#pragma comment(lib, "Dbghelp.lib")

void GetFunctionInfo(HANDLE& processHandle, DWORD_PTR& address) {

    SYMBOL_INFO symbolInfo;
    DWORD64 displacement;

    memset(&symbolInfo, 0, sizeof(SYMBOL_INFO));
    symbolInfo.SizeOfStruct = sizeof(SYMBOL_INFO);
    symbolInfo.MaxNameLen = MAX_SYM_NAME;

    if (SymFromAddr(processHandle, address, &displacement, &symbolInfo)) {
        if (symbolInfo.Name != NULL) {
            std::cout << "Nearest function name: " << symbolInfo.Name << std::endl;
        }
        else {
            std::cerr << "Function name is NULL." << std::endl;
        }
    }

}