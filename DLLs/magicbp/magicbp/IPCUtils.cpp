#include "pch.h"
#include "IPCUtils.h"

#include <iostream>
#include <mutex>

std::mutex mtx;

std::string formatRipToJson(const void* data) {

    std::ostringstream oss;

    if (data != nullptr) {
        oss << "{ ";
        oss << "\"RIP\": \"" << data << "\"";
        oss << " }";

    }

    return oss.str();
}

// New 03/03/2024
//std::string formatRipToJson(const void* data) {
//    std::ostringstream oss;
//    oss << "{ ";
//    if (data != nullptr) {
//        const char* charData = reinterpret_cast<const char*>(data);
//        oss << "\"RIP\": \"" << charData << "\"";
//    }
//    oss << " }";
//    return oss.str();
//}


std::string formatRspToJson(const void* data) {

    std::ostringstream oss;
    oss << "{ ";
    oss << "\"RSP\": \"" << data << "\"";
    oss << " }";

    return oss.str();
}

//HANDLE g_mutex = CreateMutex(NULL, FALSE, NULL);

void sendMsgThroughBeotmNamedPipe(const char* data, SIZE_T size, LPWSTR channelName) {

    //WaitForSingleObject(g_mutex, INFINITE);

    HANDLE hPipe = CreateFile((LPWSTR)channelName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    DWORD mode = PIPE_WAIT;
    SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr);

    if (hPipe != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        WriteFile(hPipe, data, static_cast<DWORD>(size), &bytesWritten, NULL);
        CloseHandle(hPipe);

    }

    //ReleaseMutex(g_mutex);
}
