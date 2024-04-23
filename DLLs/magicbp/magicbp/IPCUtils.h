#pragma once

#pragma once
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <string>
#include <sstream>
#include <iomanip>

std::string formatRipToJson(const void* data);

std::string formatRspToJson(const void* data);

void sendMsgThroughBeotmNamedPipe(const char* data, SIZE_T, LPWSTR);