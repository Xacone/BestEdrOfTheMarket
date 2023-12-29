#pragma once

#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <DbgHelp.h>

bool IsThreadSuspended(HANDLE hThread);
PPEB getHandledProcessPeb(HANDLE);