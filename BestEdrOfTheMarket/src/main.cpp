#include "Utils.h"

#pragma comment(lib, "ftxui-component.lib")
#pragma comment(lib, "ftxui-dom.lib")
#pragma comment(lib, "ftxui-screen.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libyara.lib")

using namespace ftxui;
using namespace std;

#define BEOTM_RETRIEVE_DATA_BUFFER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define BEOTM_RETRIEVE_DATA_FILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define BEOTM_RETRIEVE_DATA_BYTE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define END_THAT_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x216, METHOD_BUFFERED, FILE_ANY_ACCESS)

UINT32 curPid;

YR_COMPILER* compiler;
YR_RULES* rules;
YR_SCANNER* scanner = nullptr;
int yara_rules_count = 0;

std::queue<char*> g_bytesEvents;
std::queue<char*> g_fileEvents;

HANDLE hBeotmDevice;

std::mutex security_event_mutex;
std::atomic<bool> should_update(false);

std::vector<std::string> tab_values{
    "Detection Events (0)",
    "About"
};
int tab_selected = 0;
auto tab_toggle = Toggle(&tab_values, &tab_selected);

std::vector<std::string> tab_1_menu_items{
};

auto screen = ScreenInteractive::Fullscreen();

int tab_1_selected = 0;
auto tab_1_menu = Menu(&tab_1_menu_items, &tab_1_selected);

std::unordered_set<std::string> benignFSPaths;

std::string startupAsciiTitle = R"(

                          .           .   .        .           .          /         :  .
                    . .        .  .      /.   .      .    .     .     .  / .      . ' .
                        .  +       .    /     .          .          .   /      .
                       .            .  /         .            .        *   .         .     .
                      .   .      .    *     .     .    .      .   .       .  .
                          .           .           .           .           .         +  .
                  . .        .  .       .   .  ,-._  .    .     .     .    .      .   .
                                              /   |)
                 .   +      .          ___/\_'--._|"...__/\__.._._/~\        .         .   .
                       .          _.--'      o/o "@                  `--./\          .   .
                           /~~\/~\           '`  /(___                     `-/~\_            .
                 .      .-'                 /`--'_/   \                          `-/\_
                  _/\.-'                   /\        , \                           __/~\/\-.__
                  ____            _     _____ ____  ____     ___   __   _____ _
                 | __ )  ___  ___| |_  | ____|  _ \|  _ \   / _ \ / _| |_   _| |__   ___
                 |  _ \ / _ \/ __| __| |  _| | | | | |_) | | | | | |     | | | '_ \ / _ \
                 | |_) |  __/\__ \ |_  | |___| |_| |  _ <  | |_| |  _|   | | | | | |  __/
                 |____/_\___||___/\__| |_____|____/|_| \_\  \___/|_|     |_| |_| |_|\___|   
                 |  \/  | __ _ _ __| | _____| |_                                         
                 | |\/| |/ _` | '__| |/ / _ \ __|                                        
                 | |  | | (_| | |  |   <  __/ |_                                    
                 |_|  |_|\__,_|_|  |_|\_\___|\__|                                                               


                                                Version 3              
        
                             https://github.com/Xacone/BestEdrOfTheMarket/
   
                                     @Yazidou - github.com/Xacone 



                               "A ses yeux, j'serai toujours le plus fort,
                                         ce sont des faibles"
)";

std::vector<std::string> detectEventsDetails;

std::vector<std::string> SplitLines(const std::string& str) {
    std::stringstream ss(str);
    std::string line;
    std::vector<std::string> lines;
    while (std::getline(ss, line)) {
        lines.push_back(line);
    }
    return lines;
}

std::wstring GetFullPath(const std::wstring& relativePath) {
    WCHAR fullPath[MAX_PATH];

    DWORD result = GetFullPathNameW(relativePath.c_str(), MAX_PATH, fullPath, nullptr);
    if (result == 0) {
        std::wcerr << L"Failed to get full path. Error: " << GetLastError() << std::endl;
        return L"";
    }

    return std::wstring(fullPath);
}

std::string QueryDosDevicePath(const std::string& devicePath) {
    char driveLetter = 'A';
    char deviceName[256];
    char targetPath[1024];
    DWORD result;

    for (driveLetter = 'A'; driveLetter <= 'Z'; ++driveLetter) {
        std::string drive = std::string(1, driveLetter) + ":";
        result = QueryDosDeviceA(drive.c_str(), deviceName, 256);
        if (result != 0) {
            if (devicePath.find(deviceName) == 0) {
                std::string fullPath = drive + devicePath.substr(strlen(deviceName));
                return fullPath;
            }
        }
    }
    return "";
}


int yr_callback_function_file(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
    if (message == CALLBACK_MSG_RULE_MATCHING) {

        std::lock_guard<std::mutex> lock(security_event_mutex);

        KERNEL_STRUCTURED_NOTIFICATION* notif = (PKERNEL_STRUCTURED_NOTIFICATION)user_data;
        UINT32 pid = (UINT32)notif->pid;

        if (pid == curPid) {
            return CALLBACK_CONTINUE;
        }

        DWORD bytesReturned;
        BOOL endRes = DeviceIoControl(
            hBeotmDevice,
            END_THAT_PROCESS,
            &pid,
            sizeof(pid),
            nullptr,
            0,
            &bytesReturned,
            nullptr
        );

        time_t now = time(0);
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        char date_time[80];
        strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", &timeinfo);

        std::string date_time_str = date_time;
        std::string method = "Method: In-Memory Loaded Image Analysis";

        std::string msgCatch;
        std::string details;

        if (endRes) {

            msgCatch = std::to_string(tab_1_menu_items.size()) + " - [!] " + date_time_str + " | " + method + " | YARA rule Identifier: " + std::string(((YR_RULE*)message_data)->identifier) + " | Process was terminated";

            details = "Date & Time: " + date_time_str +
                " | PID: " + std::to_string(pid) +
                " | Method: In-Memory Loaded Image Analysis" +
                " | YARA rule Identifier: " + std::string(((YR_RULE*)message_data)->identifier) +
                " | Process was terminated successfully.";
        }
        else {

            msgCatch = std::to_string(tab_1_menu_items.size()) + " - [!] " + date_time_str + " | Memory Mapped Image | Identified: " + std::string(((YR_RULE*)message_data)->identifier) + " | (!) Failed to kill process";

            details = "Date & Time: " + date_time_str +
                " | PID: " + std::to_string(pid) +
                " | Method: In-Memory Loaded Image Analysis" +
                " | YARA rule Identifier: " + std::string(((YR_RULE*)message_data)->identifier) +
                " | (!) Process termination failed.";
        }

        tab_1_menu_items.push_back(msgCatch.c_str());
        detectEventsDetails.push_back(details);

        tab_values[0] = "Detection Events (" + std::to_string(tab_1_menu_items.size()) + ")";

        auto tab_toggle = Toggle(&tab_values, &tab_selected);
        screen.PostEvent(Event::Custom);

        return 1;

    }

    if (message == CALLBACK_MSG_SCAN_FINISHED) {
        char* fileName = (char*)user_data;

        if (benignFSPaths.find(fileName) == benignFSPaths.end()) {

            //printf("[+] Adding to benignFSPaths: %s\n", fileName);
            benignFSPaths.insert(fileName);

            return CALLBACK_CONTINUE;
        }
    }

    return CALLBACK_CONTINUE;
}

int yr_callback_function_byte_stream(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data
)
{
    if (message == CALLBACK_MSG_RULE_MATCHING) {

        PKERNEL_STRUCTURED_BUFFER structBuffer = (PKERNEL_STRUCTURED_BUFFER)user_data;

        UINT32 pid = (UINT32)structBuffer->pid;
        char* procName = structBuffer->procName;

        if (pid == curPid) {
            return CALLBACK_CONTINUE;
        }

        DWORD bytesReturned;
        BOOL endRes = DeviceIoControl(
            hBeotmDevice,
            END_THAT_PROCESS,
            &pid,
            sizeof(pid),
            nullptr,
            0,
            &bytesReturned,
            nullptr
        );

        time_t now = time(0);
        struct tm timeinfo;
        localtime_s(&timeinfo, &now);
        char date_time[80];
        strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", &timeinfo);

        std::string date_time_str = date_time;
        std::string msgCatch;
        std::string details;

        std::string method = "";

        {
            //std::lock_guard<std::mutex> lock(security_event_mutex);

            std::string rule_identifier = std::string(((YR_RULE*)message_data)->identifier);

            if (endRes) {

                msgCatch = std::to_string(tab_1_menu_items.size()) +
                    " - [!] [Alert] | " + date_time_str +
                    " | " + std::string(structBuffer->procName) +
                    " | Byte Stream Analysis | Identified: " + rule_identifier +
                    "\n\n | Process with PID " + std::to_string(pid) + " has been terminated.";

                details = "Date & Time: " + date_time_str +
                    " | " + std::string(structBuffer->procName) +
                    " | PID: " + std::to_string(pid) +
                    " | Method: Byte Stream Analysis" +
                    " | YARA rule Identifier: " + rule_identifier +
                    " | Process was terminated successfully.";
            }
            else {

                msgCatch = std::to_string(tab_1_menu_items.size()) +
                    " - [!] [Alert] | " + date_time_str +
                    " | " + std::string(structBuffer->procName) +
                    " | Byte Stream Analysis | Identified: " + rule_identifier +
                    "\n\n | (!) Failed to terminate process with PID " + std::to_string(pid);

                details = "Date & Time: " + date_time_str +
                    " | PID: " + std::to_string(pid) +
                    " | " + std::string(structBuffer->procName) +
                    " | Method: Byte Stream Analysis" +
                    " | YARA rule Identifier: " + rule_identifier +
                    " | (!) Process termination failed.";
            }

            detectEventsDetails.push_back(details);
            tab_1_menu_items.push_back(msgCatch.c_str());
            tab_values[0] = "Detection Events (" + std::to_string(tab_1_menu_items.size()) + ")";
            should_update = true;

            //std::lock_guard<std::mutex> unlock(security_event_mutex);
        }

        auto tab_toggle = Toggle(&tab_values, &tab_selected);
        screen.PostEvent(Event::Custom);
    }

    return CALLBACK_CONTINUE;
}

UINT lastNotifiedStackSpoofPid = 0;

int Notify(PKERNEL_STRUCTURED_NOTIFICATION notif, char* msg) {

    time_t now = time(0);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    char date_time[80];
    strftime(date_time, sizeof(date_time), "%Y-%m-%d %H:%M:%S", &timeinfo);

    UINT32 pid = (UINT32)notif->pid;

    if (pid == curPid) {
        return 0;
    }

    std::string date_time_str = date_time;
    std::string msgCatch;
    std::string details;
    std::string targetedProc = "";
    std::string method;

    if (notif->ProcVadCheck) {
        method = "Method: Process VAD Tree Inspection";
    }
    else if (notif->StackBaseVadCheck) {
        method = "Method: Stack Base + VAD Inspection";
    }
    else if (notif->CallingProcPidCheck) {
        method = "Method: Calling Process PID Inspection";
    }
    else if (notif->SeAuditInfoCheck) {
        method = "Method: Process Audit Info Inspection";
    }
    else if (notif->ImageLoadPathCheck) {
        method = "Method: Image Load Path Inspection";
    }
    else if (notif->ObjectCheck) {
        method = "Method: Object Operation Inspection";
        targetedProc = " -> " + std::string(notif->targetProcName) + " ";
    }
    else if (notif->RegCheck) {
        method = "Method: Registry Operation Inspection";
    }
    else if (notif->SyscallCheck) {
        method = "Method: Syscall Integrity Inspection";
    }
    else if (notif->ShadowStackCheck) {

        if (lastNotifiedStackSpoofPid == pid) {
            return 0;
        }

        lastNotifiedStackSpoofPid = pid;
        method = "Method: Shadow Stack Inspection";
    }

    if (notif->Critical) {

        try {
            DWORD bytesReturned;
            BOOL endRes = DeviceIoControl(
                hBeotmDevice,
                END_THAT_PROCESS,
                &pid,
                sizeof(pid),
                nullptr,
                0,
                &bytesReturned,
                nullptr
            );

            {
                if (endRes) {

                    msgCatch = std::to_string(tab_1_menu_items.size()) +
                        " - [!] [Alert] | " + date_time_str +
                        " | " + notif->procName +
                        " | " + method +
                        " | " + (char*)msg;

                    msgCatch += " | Process with PID " + std::to_string(pid) + " has been terminated.";

                    details = "Date & Time: " + date_time_str +
                        " | " + notif->procName +
                        " | " + method +
                        " | " + (char*)msg +
                        " | PID: " + std::to_string(pid);

                    details += " | Process was terminated.";
                }
                else {

                    msgCatch = std::to_string(tab_1_menu_items.size()) +
                        " - [!] [Alert] | " + date_time_str +
                        " | " + notif->procName +
                        " | " + method +
                        " | " + (char*)msg +
                        " | (!) Failed to terminate process with PID " + std::to_string(pid);

                    details = "Date & Time: " + date_time_str +
                        " | " + notif->procName +
                        " | " + method +
                        " | " + (char*)msg +
                        " | PID: " + std::to_string(pid) +
                        " | (!) Process termination failed.";
                }

                detectEventsDetails.push_back(details);
                tab_1_menu_items.push_back(msgCatch.c_str());
                tab_values[0] = "Detection Events (" + std::to_string(tab_1_menu_items.size()) + ")";
                should_update = true;
            }
        }
        catch (std::exception& e) {
            std::cerr << "[!] Exception caught: " << e.what() << std::endl;
        }

    }
    else if (notif->Warning) {

        msgCatch = std::to_string(tab_1_menu_items.size()) +
            " - [*] [Warning] | " + date_time_str +
            " | " + method +
            " | " + notif->procName +
            " | " + (char*)msg;

        details = "Date & Time: " + date_time_str +
            " | " + notif->procName +
            " | " + method +
            " | " + (char*)msg +
            " | PID: " + std::to_string(pid);

        detectEventsDetails.push_back(details);
        tab_1_menu_items.push_back(msgCatch.c_str());
        tab_values[0] = "Detection Events (" + std::to_string(tab_1_menu_items.size()) + ")";
        should_update = true;

    }

    auto tab_toggle = Toggle(&tab_values, &tab_selected);
    screen.PostEvent(Event::Custom);

}

void setConsoleColor(WORD color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

VOID InitYara(char* yaraRulesPath) {

    if (yr_initialize() != ERROR_SUCCESS) {
        std::cerr << "Failed to initialize Yara\n";
        system("pause");
    }

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        std::cerr << "Failed to create Yara compiler\n";
        system("pause");
        return;
    }

    std::string rules_directory = yaraRulesPath;

    for (const auto& entry : std::filesystem::directory_iterator(rules_directory)) {

        if (entry.is_regular_file() && entry.path().extension() == ".yar") {

            FILE* rule_file;

            if (fopen_s(&rule_file, entry.path().string().c_str(), "r") != 0) {
                std::cerr << "Failed to open Yara rule: " << entry.path().string() << "\n";
                system("pause");
                continue;
            }

            if (rule_file == NULL) {
                std::cerr << "Failed to open Yara rule: " << entry.path().string() << "\n";
                system("pause");
                continue;
            }

            yara_rules_count += 1;

            setConsoleColor(FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            printf("\t [+] Adding Yara rule: %s\n", entry.path().string().c_str());
            setConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

            if (yr_compiler_add_file(compiler, rule_file, NULL, entry.path().string().c_str()) != ERROR_SUCCESS) {
                std::cerr << "Failed to add Yara rule: " << entry.path().string() << "\n";
                system("pause");
                fclose(rule_file);
                continue;
            }

            fclose(rule_file);
        }
    }

    int result = yr_compiler_get_rules(compiler, &rules);

    if (result != 0) {
        std::cerr << "Error retrieving compiled rules" << std::endl;
        system("pause");
        yr_compiler_destroy(compiler);
        yr_finalize();
        return;
    }

    int scan_res = yr_scanner_create(rules, &scanner);

    if (scan_res != 0 || scanner == nullptr) {
        std::cerr << "Error while creating a scanner" << std::endl;
        system("pause");
        return;
    }
}

auto detail_panel_content = [&]() {

    if (!detectEventsDetails.empty()) {
        return paragraph(detectEventsDetails.at(tab_1_selected));
    }

    return paragraph(" ") | center;

    };

auto tab_1_container = Container::Vertical({
    Renderer(tab_1_menu, [&] {

        auto main_panel = vbox({
            text("Detection Events:") | bold | color(Color::Red),
            tab_1_menu->Render() | frame | border | size(HEIGHT, EQUAL, 60),
        });

        auto details_panel = vbox({
            text("Details:") | bold | color(Color::Yellow),
            detail_panel_content() | border | size(HEIGHT, EQUAL, 10),
            });

        return vbox({
            main_panel | flex,
            details_panel,
        }) | border;

        /*return tab_1_menu->Render() |
               size(HEIGHT, GREATER_THAN, 10) |
               frame | vscroll_indicator | focus | color(Color::Red);*/
    })
    });

void ConsumeIOCTLData(LPCWSTR deviceName, DWORD ioctlCode, int sleepDurationMs) {

    hBeotmDevice = CreateFileW(
        deviceName,
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hBeotmDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open device: " << GetLastError() << std::endl;
        exit(-1);
        ;
    }

    DWORD bufferSize = 1024 * 1024;
    BYTE* buffer = (BYTE*)malloc(bufferSize);
    if (!buffer) {
        std::cerr << "Failed to allocate buffer" << std::endl;
        CloseHandle(hBeotmDevice);
        return;
    }

    const int maxRetries = 1000000000;
    int retryCount = 0;

    while (retryCount < maxRetries) {

        DWORD bytesReturned = 0;
        BOOL result = DeviceIoControl(
            hBeotmDevice,
            ioctlCode,
            nullptr,
            0,
            buffer,
            bufferSize,
            &bytesReturned,
            nullptr
        );

        if (result) {

            if (ioctlCode == BEOTM_RETRIEVE_DATA_BYTE) {

                if (bytesReturned < sizeof(KERNEL_STRUCTURED_BUFFER)) {
                    std::cerr << "Invalid buffer size returned" << std::endl;
                    break;
                }

                KERNEL_STRUCTURED_BUFFER* structuredBuffer = (PKERNEL_STRUCTURED_BUFFER)buffer;
                BYTE* bufferData = (BYTE*)(buffer + sizeof(KERNEL_STRUCTURED_BUFFER));

                yr_rules_scan_mem(
                    rules,
                    bufferData,
                    structuredBuffer->bufSize,
                    0,
                    (YR_CALLBACK_FUNC)yr_callback_function_byte_stream,
                    (void*)structuredBuffer,
                    0
                );

            }
            else if (ioctlCode == BEOTM_RETRIEVE_DATA_BUFFER) {

                std::cout << "Buffer" << std::endl;

            }
            else if (ioctlCode == BEOTM_RETRIEVE_DATA_FILE) {

                if (bytesReturned < sizeof(KERNEL_STRUCTURED_NOTIFICATION)) {
                    std::cerr << "Invalid buffer size returned" << std::endl;
                    break;
                }

                if (buffer && bufferSize > 0) {

                    PKERNEL_STRUCTURED_NOTIFICATION notif = (PKERNEL_STRUCTURED_NOTIFICATION)buffer;
                    char* msg = (char*)(buffer + sizeof(KERNEL_STRUCTURED_NOTIFICATION));

                    if (msg != NULL) {

                        if (notif->isPath) {

                            std::string litFileName = msg;
                            std::string fullPath = QueryDosDevicePath(litFileName);

                            if (benignFSPaths.find(fullPath) != benignFSPaths.end()) {
                                continue;
                            }

                            int fileScanRes = yr_rules_scan_file(
                                rules,
                                fullPath.c_str(),
                                0,
                                (YR_CALLBACK_FUNC)yr_callback_function_file,
                                (void*)notif,
                                0
                            );
                        }
                        else {

                            Notify(notif, msg);
                        }
                    }
                }
            }
        }

        Sleep(sleepDurationMs);
    }

    free(buffer);
    CloseHandle(hBeotmDevice);
}

std::string GetLastErrorAsString() {
    DWORD errorMessageID = GetLastError();
    if (errorMessageID == 0)
        return std::string();

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    std::string message(messageBuffer, size);

    LocalFree(messageBuffer);

    return message;
}

SC_HANDLE hService;
SC_HANDLE hSCManager;

void UninstallBeotmDriver() {
    if (hService) {
        SERVICE_STATUS status;
        if (ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
            std::wcout << L"Service stopped successfully." << std::endl;
        }
        else {
            std::wcout << L"Failed to stop service. Error: " << GetLastError() << std::endl;
        }

        if (DeleteService(hService)) {
            std::wcout << L"Service deleted successfully." << std::endl;
        }
        else {
            std::wcout << L"Failed to delete service. Error: " << GetLastError() << std::endl;
        }

        CloseServiceHandle(hService);
        hService = nullptr;
    }

    if (hSCManager) {
        CloseServiceHandle(hSCManager);
        hSCManager = nullptr;
    }
}


bool InstallBeotmDriver(
    const std::wstring& drvName,
    const std::wstring& drvPath
) {

    hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (!hSCManager) {
        std::wcout << L"Failed to open service control manager. Error: " << GetLastError() << std::endl;
        return false;
    }

    hService = CreateServiceW(
        hSCManager,
        drvName.c_str(),
        drvName.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        drvPath.c_str(),
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );


    if (!hService) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            std::wcout << L"Service already exists, opening existing service..." << std::endl;
            hService = OpenService(hSCManager, drvName.c_str(), SERVICE_START);
            if (!hService) {
                std::wcerr << L"Failed to open existing service. Error: " << GetLastError() << std::endl;
                CloseServiceHandle(hSCManager);
                return false;
            }
        }
        else {
            std::wcerr << L"Failed to create service. Error: " << GetLastError() << std::endl;
            CloseServiceHandle(hSCManager);
            return false;
        }
    }

    if (!StartService(hService, 0, nullptr)) {
        if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            std::wcerr << L"Failed to start service. Error: " << GetLastError() << std::endl;
            std::cerr << GetLastErrorAsString() << std::endl;

            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return false;
        }
    }

    std::wcout << L"Driver installed and started successfully!" << std::endl;

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return true;

}

void SignalHandler(int signal) {
    if (signal == SIGINT) {
        std::wcout << L"Ctrl+C detected. Uninstalling driver..." << std::endl;
        UninstallBeotmDriver();
        exit(0);
    }
}

VOID ShowUI() {

    auto screen = ScreenInteractive::Fullscreen();

    auto tab_container = Container::Tab(
        {
            tab_1_container,
            //Renderer([] { return text("Tab 2 Content"); }),
            //Renderer([] { return text("Tab 3 Content"); }),
            Renderer([&] {
                if (tab_values[tab_selected] == "About") {
                    auto lines = SplitLines(startupAsciiTitle);
                    std::vector<Element> ascii_elements;
                    for (const auto& line : lines) {
                        ascii_elements.push_back(text(line));
                    }
                    return vbox(ascii_elements) | center | xflex | yflex;
                }
                return text("");
            }),
        },
        &tab_selected);


    auto container = Container::Vertical({
    tab_toggle,
    tab_container,
        });

    auto renderer = Renderer(container, [&] {
        return vbox({
                   tab_toggle->Render(),
                   separator(),
                   tab_container->Render() | size(HEIGHT, LESS_THAN, 40),
            }) |
            border;
        });

    std::thread threadByte([]() {
        ConsumeIOCTLData(L"\\\\.\\Beotm", BEOTM_RETRIEVE_DATA_BYTE, 5);
        });

    std::thread threadFile([]() {
        ConsumeIOCTLData(L"\\\\.\\Beotm", BEOTM_RETRIEVE_DATA_FILE, 5);
        });

    try {
        screen.Loop(renderer);
    }
    catch (const std::exception& e) {
        std::cerr << "[!] Exception caught: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "[!] Unknown exception caught" << std::endl;
    }

    auto event_handler = CatchEvent(tab_1_container, [&](Event event) {
        if (event == Event::ArrowUp) {
            tab_1_selected = (tab_1_selected > 0) ? tab_1_selected - 1 : tab_1_menu_items.size() - 1;
            return true;
        }
        if (event == Event::ArrowDown) {
            tab_1_selected = (tab_1_selected + 1) % tab_1_menu_items.size();
            return true;
        }
        return false;
        });

    std::thread refresh_thread([&screen]() {
        while (true) {
            std::this_thread::sleep_for(10ms);
            screen.PostEvent(Event::Custom);
        }
        });

    threadByte.join();
    threadFile.join();
}

int main(int argc, char* argv[]) {

    std::signal(SIGINT, SignalHandler);

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <path to driver> <path to YARA rules directory>\n";
        return 1;
    }

    std::wstring driverPath = std::wstring(argv[1], argv[1] + strlen(argv[1]));
    std::wstring yaraRulesPath = std::wstring(argv[2], argv[2] + strlen(argv[2]));
    std::wstring driverName = L"BeotmDrv";

    std::wstring fullPath = GetFullPath(driverPath);

    if (!InstallBeotmDriver(driverName, fullPath)) {
        std::wcerr << L"Failed to install driver." << std::endl;
        std::cerr << GetLastErrorAsString() << std::endl;
        return 1;
    }

    curPid = static_cast<UINT32>(GetCurrentProcessId());

    printf("[*] Loading YARA rules...\n");

    InitYara(argv[2]);

    printf("[*] %d Yara Rules Loaded & Compiled\n", yara_rules_count);
    system("pause");

    ShowUI();

    return 0;
}