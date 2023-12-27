#pragma once

#include <Windows.h>
#include <winternl.h>

PPEB getHandledProcessPeb(HANDLE);