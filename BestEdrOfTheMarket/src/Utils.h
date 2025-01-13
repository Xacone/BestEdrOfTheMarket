#include <unordered_set>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <chrono>
#include <thread>
#include <atomic>
#include <string>
#include <queue>
#include <csignal>

#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/screen.hpp>
#include <ftxui/screen/color.hpp>
#include <ftxui/component/captured_mouse.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/component_options.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/screen/screen.hpp>
#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/dom/flexbox_config.hpp>

#include <yara.h>

typedef struct _KERNEL_STRUCTURED_BUFFER {
    ULONG bufSize;
    char procName[15];
    UINT32 pid;
    BYTE* buffer;
} KERNEL_STRUCTURED_BUFFER, * PKERNEL_STRUCTURED_BUFFER;

typedef struct _KERNEL_STRUCTURED_NOTIFICATION {

    union {
        struct {
            unsigned char ProcVadCheck : 1;
            unsigned char StackBaseVadCheck : 1;
            unsigned char CallingProcPidCheck : 1;
            unsigned char SeAuditInfoCheck : 1;
            unsigned char ImageLoadPathCheck : 1;
            unsigned char ObjectCheck : 1;
            unsigned char RegCheck : 1;
            unsigned char SyscallCheck : 1;
        };
        unsigned char method;
    };

    union {
        struct {
            unsigned char ShadowStackCheck : 1;
            unsigned char Reserved : 7; // Align
        };
        unsigned char method2;
    };

    ULONG64 scoopedAddress;
    BOOLEAN isPath;
    HANDLE pid;
    ULONG bufSize;
    char procName[15];
    char targetProcName[15];

    union {
        struct {
            unsigned char Critical : 1;
            unsigned char Warning : 1;
            unsigned char Info : 1;
            unsigned char Reserved : 5; // Align
        };
        unsigned char Level;
    };

    char* msg;
} KERNEL_STRUCTURED_NOTIFICATION, * PKERNEL_STRUCTURED_NOTIFICATION;

typedef struct _PROCESS_IDENTITY {

    char* dosName;
    HANDLE processHandle;

} PROCESS_IDENTITY, * PPROCESS_IDENTITY;

//std::string QueryDosDevicePath(const std::string&);
