#include <Windows.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <atomic>
#include <queue>
#include <thread>
#include <mutex>
#include "SharedDefines.h"

constexpr auto DEVICE_NAME_PATH = L"C:\\sysmon_link.txt";
std::atomic<bool> g_KeepRunning{ true };
std::queue<MONITOR_EVENT> g_EventQueue;
std::mutex g_QueueMutex;
std::condition_variable g_QueueCV;
FILE* g_LogFile = nullptr;


BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType) {
    if (dwCtrlType == CTRL_C_EVENT || dwCtrlType == CTRL_CLOSE_EVENT) {
        std::wcout << L"\n[!] CTRL+C detected. Stopping monitor and cleaning up...\n";
        g_KeepRunning = false;
        return TRUE;
    }
    return FALSE;
}

static bool IsAppRunningAsAdmin();
std::wstring GetDriverDescriptorName();
HANDLE OpenDriverDescriptor(std::wstring&);
std::wstring GetTagetNameFromUser();
void PrintEvent(const MONITOR_EVENT&);
void LogEvent(const wchar_t* format, ...);
void LoggerWorkerThread();


int main() {

    if (!IsAppRunningAsAdmin()) {
        std::wcerr << L"[!] Please restart app with admin privileges [!]" << std::endl;
        system("pause");
        return 1;
    }


    // Opening driver descriptor
    auto DriverDescriptorName = GetDriverDescriptorName();
    if (DriverDescriptorName.empty()) {
        std::wcerr << L"[-] Failed to read: " << DEVICE_NAME_PATH << std::endl;
        system("pause");
        return 2;
    }

    std::wcout << "[?] Device descriptor path: " << DriverDescriptorName << L" [?]\n";

    auto DriverDescriptorHandle = OpenDriverDescriptor(DriverDescriptorName);
    if (DriverDescriptorHandle == INVALID_HANDLE_VALUE) {
        std::wcerr << "[-] Unable to open device handle, Error code: " << GetLastError() << std::endl;
        system("pause");
        return 3;
    }

    // Setting target name
    auto targetName = GetTagetNameFromUser();
    if (targetName.empty()) {
        std::wcerr << "[-] No process to watch was specified [-]";
        system("pause");
        return 4;
    }

    DWORD bytesReturned;
    auto SetTargetResult = DeviceIoControl(DriverDescriptorHandle,
        IOCTL_SET_TARGET_NAME,
        (LPVOID)targetName.c_str(),
        (DWORD)((targetName.length() + 1) * sizeof(wchar_t)),
        NULL,
        0, 
        &bytesReturned, 
        NULL
    );

    if (!SetTargetResult) {
        std::cerr << "[-] Error: Could not set target process name [-]" << std::endl;
        CloseHandle(DriverDescriptorHandle);
        system("pause");
        return 5;
    }

    std::wcout << L"[+] Monitoring started for: " << targetName << L"\n";

    PSHARED_MEMORY_BUFFER sharedBuffer = nullptr;
    auto GetMappingOfSharedBufferResult = DeviceIoControl(
        DriverDescriptorHandle,
        IOCTL_MAP_MEMORY,
        NULL,
        0,
        &sharedBuffer,
        sizeof(PVOID),
        &bytesReturned,
        NULL
    );
    
    if (!GetMappingOfSharedBufferResult || sharedBuffer == nullptr) {
        std::wcout << L"[-] Failed to map shared memory. Error code: " << GetLastError() << L"\n";
        CloseHandle(DriverDescriptorHandle);
        system("pause");
        return 6;
    }

    if (_wfopen_s(&g_LogFile, L"sysmon_log.txt", L"w, ccs=UTF-8") != 0) {
        std::wcerr << L"[-] Warning: Failed to open log file at sysmon_log.txt\n";
        std::wcerr << L"[?] Consider having good memory to remember all events :)\n";
    }
    else {
        std::wcout << L"[+] Log file successfully created: sysmon_log.txt\n";
    }

    std::thread loggerThread(LoggerWorkerThread);

    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
        std::wcerr << L"[-] Failed to set console control handler for CTRL + C event.\n";
        DeviceIoControl(DriverDescriptorHandle, IOCTL_UNMAP_MEMORY, NULL, 0, NULL, 0, &bytesReturned, NULL);
        CloseHandle(DriverDescriptorHandle);
        system("pause");
        return 7;
    }

    while (g_KeepRunning) {

        if (sharedBuffer->DroppedEvents > 0) {
            std::wcerr << "[-] Buffer overflow detected [-]" << L"\n";
            std::wcout << L" Dropped " << sharedBuffer->DroppedEvents << L" events." << L"\n";
            InterlockedExchange((volatile LONG*)&sharedBuffer->DroppedEvents, 0);
        }

        bool pushedAny = false;

        while (sharedBuffer->ReadIndex != sharedBuffer->WriteIndex) {
            auto event = sharedBuffer->Events[sharedBuffer->ReadIndex];

            sharedBuffer->ReadIndex = (sharedBuffer->ReadIndex + 1) % MAX_EVENTS;

            {
                std::lock_guard<std::mutex> lock(g_QueueMutex);
                g_EventQueue.push(event);
            }
            pushedAny = true;
        }
        if (pushedAny) {
            g_QueueCV.notify_one();
        }
        Sleep(5);
    }

    g_QueueCV.notify_all();
    if (loggerThread.joinable()) {
        loggerThread.join();
    }

    if (g_LogFile) {
        fclose(g_LogFile);
    }

    std::wcout << L"\n[+] Unmapping shared memory...\n";
    DeviceIoControl(DriverDescriptorHandle, IOCTL_UNMAP_MEMORY, NULL, 0, NULL, 0, &bytesReturned, NULL);
    std::wcout << L"[+] Closing driver handle..." << std::endl;
    CloseHandle(DriverDescriptorHandle);
    return 0;
}

static bool IsAppRunningAsAdmin() {
    bool isElevated = false;
    HANDLE token = nullptr;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);

        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isElevated = elevation.TokenIsElevated != 0;
        }
        CloseHandle(token);
    }
    return isElevated;
}

std::wstring GetDriverDescriptorName() {
    std::ifstream DriverDescriptorFile(DEVICE_NAME_PATH, std::ios::binary);
    if (!DriverDescriptorFile.is_open()) {
        return L"";
    }

    std::wstring DriverDescriptorName;
    wchar_t wideCharacter;
    while (DriverDescriptorFile.read(reinterpret_cast<char*>(&wideCharacter), sizeof(wchar_t))) {
        
        if (wideCharacter == 0xFEFF) continue;
        if (wideCharacter == L'\0' || wideCharacter == L'\r' || wideCharacter == L'\n') {
            break;
        }
        DriverDescriptorName.push_back(wideCharacter);
    }
    DriverDescriptorFile.close();
    return DriverDescriptorName;
}

HANDLE OpenDriverDescriptor(std::wstring& deviceName) {
    HANDLE hDevice = CreateFileW(deviceName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    return hDevice;
}

std::wstring GetTagetNameFromUser() {
    std::string targetName;
    std::wcout << L"Enter target process name: ";
    std::getline(std::cin, targetName);
    std::wstring targetNameW(targetName.begin(), targetName.end());
    return targetNameW;
}

void PrintEvent(const MONITOR_EVENT& event) {
    SYSTEMTIME sysTime{};
    FileTimeToSystemTime((FILETIME*)&event.TimeStamp, &sysTime);
    printf("[%02d:%02d.%03d] PID: %lu | ", 
        sysTime.wMinute, 
        sysTime.wSecond, 
        sysTime.wMilliseconds, 
        event.ProcessId
    );

    switch (event.Type) {

        case EProcessCreate: {
            LogEvent(L"[PROCESS] Created: %ws | Parent: %lu | Cmd: %ws\n",
                event.Data.Process.ImageName,
                event.Data.Process.ParentPid,
                event.Data.Process.CommandLine
            );
            break;
        }
        case EProcessExit: {
            LogEvent(L"[PROCESS] Terminated\n");
            break;
        }
        case EThreadCreate: {
            LogEvent(L"[THREAD] Created | TID: %lu\n", event.Data.Thread.ThreadId);
            break;
        }
        case EThreadExit: {
            LogEvent(L"[THREAD] Terminated | TID: %lu\n", event.Data.Thread.ThreadId);
            break;
        }
        case EFilePreCreate: {
            LogEvent(L"[FILE] Wants to create: %ws\n", event.Data.File.FilePath);
            break;
        }
        case EFilePostCreate: {
            if (event.Data.File.Status == 0) {
                LogEvent(L"[FILE] Successfully created: %ws\n", event.Data.File.FilePath);
            }
            else {
                LogEvent(L"[FILE] Failed to create (0x%08X): %ws\n", event.Data.File.Status, event.Data.File.FilePath);
            }
            break;
        }
        case EFilePreOpen: {
            LogEvent(L"[FILE] Wants to open: %ws\n", event.Data.File.FilePath);
            break;
        }
        case EFilePostOpen: {
            if (event.Data.File.Status == 0) {
                LogEvent(L"[FILE] Successfully opened: %ws\n", event.Data.File.FilePath);
            }
            else {
                LogEvent(L"[FILE] Failed to open (0x%08X): %ws\n", event.Data.File.Status, event.Data.File.FilePath);
            }
            break;
        }
        case EFilePreRead: {
            LogEvent(L"[FILE] Wants to read: %ws\n", event.Data.File.FilePath);
            break;
        }
        case EFilePostRead: {
            if (event.Data.File.Status == 0) {
                LogEvent(L"[FILE] Successfully read: %ws\n", event.Data.File.FilePath);
            }
            else {
                LogEvent(L"[FILE] Failed to read (0x%08X): %ws\n", event.Data.File.Status, event.Data.File.FilePath);
            }
            break;
        }
        case EFilePreWrite: {
            LogEvent(L"[FILE] Wants to write: %ws\n", event.Data.File.FilePath);
            break;
        }
        case EFilePostWrite: {
            if (event.Data.File.Status == 0) {
                LogEvent(L"[FILE] Successfully write: %ws\n", event.Data.File.FilePath);
            }
            else {
                LogEvent(L"[FILE] Failed to write (0x%08X): %ws\n", event.Data.File.Status, event.Data.File.FilePath);
            }
            break;
        }
        case EFileUnknown: {
            LogEvent(L"[FILE] Unkown operation: %ws\n", event.Data.File.FilePath);
            break;
        }
        case ERegistryPreOpenKey: {
            LogEvent(L"[REGISTRY] Wants to OPEN KEY: %ws\n", event.Data.Registry.Path);
            break;
        }
        case ERegistryPostOpenKey: {
            if (event.Data.Registry.Status == 0) {
                LogEvent(L"[REGISTRY] Successfully OPENED KEY: %ws\n", event.Data.Registry.Path);
            }
            else {
                LogEvent(L"[REGISTRY] Failed to OPEN KEY (0x%08X): %ws\n", event.Data.Registry.Status, event.Data.Registry.Path);
            }
            break;
        }
        case ERegistryPreDeleteKey: {
            LogEvent(L"[REGISTRY] Wants to DELETE KEY (Folder): %ws\n", event.Data.Registry.Path);
            break;
        }
        case ERegistryPostDeleteKey: {
            if (event.Data.Registry.Status == 0) {
                LogEvent(L"[REGISTRY] Successfully DELETED KEY: %ws\n", event.Data.Registry.Path);
            }
            else {
                LogEvent(L"[REGISTRY] Failed to DELETE KEY (0x%08X): %ws\n", event.Data.Registry.Status, event.Data.Registry.Path);
            }
            break;
        }
        case ERegistryPreEnumerateValue: {
            LogEvent(L"[REGISTRY] Wants to ENUMERATE VALUE (Index %lu) in: %ws\n", event.Data.Registry.DwordData, event.Data.Registry.Path);
            break;
        }
        case ERegistryPostEnumerateValue: {
            if (event.Data.Registry.Status == 0) {
                LogEvent(L"[REGISTRY] ENUMERATE VALUE success (Index %lu): %ws\n", event.Data.Registry.DwordData, event.Data.Registry.Path);
            }
            else {
                LogEvent(L"[REGISTRY] ENUMERATE VALUE end/failed (0x%08X): %ws\n", event.Data.Registry.Status, event.Data.Registry.Path);
            }
            break;
        }
        case ERegistryPreCreateValue: {
            LogEvent(L"[REGISTRY] Wants to create value: %ws\\%ws\n", event.Data.Registry.Path, event.Data.Registry.ValueName);
            break;
        }
        case ERegistryPostCreateValue: {
            if (event.Data.Registry.Status == 0) {
                LogEvent(L"[REGISTRY] Successfully created value: %ws\\%ws\n", event.Data.Registry.Path, event.Data.Registry.ValueName);
            }
            else {
                LogEvent(L"[REGISTRY] Failed to create value (0x%08X): %ws\\%ws\n", event.Data.Registry.Status, event.Data.Registry.Path, event.Data.Registry.ValueName);
            }
            break;
        }
        case ERegistryPreSetValue: {
            LogEvent(L"[REGISTRY] Wants to set value: %ws\\%ws", event.Data.Registry.Path, event.Data.Registry.ValueName);
            if (event.Data.Registry.DataType == REG_DWORD) {
                LogEvent(L" (DWORD: %lu)\n", event.Data.Registry.DwordData);
            }
            else if (event.Data.Registry.DataType == REG_SZ || event.Data.Registry.DataType == REG_EXPAND_SZ) {
                LogEvent(L" (STRING: %ws)\n", event.Data.Registry.StringData);
            }
            else {
                LogEvent(L" (Type: %lu, Size: %lu bytes)\n", event.Data.Registry.DataType, event.Data.Registry.DataSize);
            }
            break;
        }
        case ERegistryPostSetValue: {
            if (event.Data.Registry.Status == 0) {
                LogEvent(L"[REGISTRY] Successfully set value: %ws\\%ws\n", event.Data.Registry.Path, event.Data.Registry.ValueName);
            }
            else {
                LogEvent(L"[REGISTRY] Failed to set value (0x%08X): %ws\\%ws\n", event.Data.Registry.Status, event.Data.Registry.Path, event.Data.Registry.ValueName);
            }
            break;
        }
        case ERegistryPreGetValue:
        case ERegistryPreQueryValueKey: {
            LogEvent(L"[REGISTRY] Wants to query value: %ws\\%ws\n", event.Data.Registry.Path, event.Data.Registry.ValueName);
            break;
        }
        case ERegistryPostGetValue:
        case ERegistryPostQueryValueKey: {
            if (event.Data.Registry.Status == 0) {
                LogEvent(L"[REGISTRY] Successfully queried value: %ws\\%ws", event.Data.Registry.Path, event.Data.Registry.ValueName);
                if (event.Data.Registry.DataType == REG_DWORD) {
                    LogEvent(L" (DWORD: %lu)\n", event.Data.Registry.DwordData);
                }
                else if (event.Data.Registry.DataType == REG_SZ || event.Data.Registry.DataType == REG_EXPAND_SZ) {
                    LogEvent(L" (STRING: %ws)\n", event.Data.Registry.StringData);
                }
                else {
                    LogEvent(L" (Type: %lu, Size: %lu bytes)\n", event.Data.Registry.DataType, event.Data.Registry.DataSize);
                }
            }
            else {
                LogEvent(L"[REGISTRY] Failed to query value (0x%08X): %ws\\%ws\n", event.Data.Registry.Status, event.Data.Registry.Path, event.Data.Registry.ValueName);
            }
            break;
        }
        case ERegistryPreEnumerateValue:
        case ERegistryPreEnumerateKey: {
            LogEvent(L"[REGISTRY] Wants to enumerate (Index %lu) in: %ws\n", event.Data.Registry.DwordData, event.Data.Registry.Path);
            break;
        }
        case ERegistryPostEnumerateValue:
        case ERegistryPostEnumerateKey: {
            if (event.Data.Registry.Status == 0) {
                LogEvent(L"[REGISTRY] Emuneration success (Index %lu): %ws\n", event.Data.Registry.DwordData, event.Data.Registry.Path);
            }
            else {
                LogEvent(L"[REGISTRY] Emuneration end/failed (0x%08X): %ws\n", event.Data.Registry.Status, event.Data.Registry.Path);
            }
            break;
        }
        case ERegistryPreQueryMultipleValueKey: {
            LogEvent(L"[REGISTRY] Wants to query multiple values (%lu entries) in: %ws\n", event.Data.Registry.DataSize, event.Data.Registry.Path);
            break;
        }
        case ERegistryPostQueryMultipleValueKey: {
            if (event.Data.Registry.Status == 0) {
                LogEvent(L"[REGISTRY] Successfully queried multiple values in: %ws\n", event.Data.Registry.Path);
            }
            else {
                LogEvent(L"[REGISTRY] Failed to query multiple values (0x%08X) in: %ws\n", event.Data.Registry.Status, event.Data.Registry.Path);
            }
            break;
        }
        case ERegistryPreCreateKey: {
            LogEvent(L"[REGISTRY] Wants to create key: %ws\n", event.Data.Registry.Path);
            break;
        }
        case ERegistryPostCreateKey: {
            if (event.Data.Registry.Status == 0) {
                LogEvent(L"[REGISTRY] Successfully created key: %ws\n", event.Data.Registry.Path);
            }
            else {
                LogEvent(L"[REGISTRY] Failed to create key (0x%08X): %ws\n", event.Data.Registry.Status, event.Data.Registry.Path);
            }
            break;
        }
        case ERegistryPreDeleteValue: {
            LogEvent(L"[REGISTRY] Wants to delete value: %ws\\%ws\n", event.Data.Registry.Path, event.Data.Registry.ValueName);
            break;
        }
        case ERegistryPostDeleteValue: {
            if (event.Data.Registry.Status == 0) {
                LogEvent(L"[REGISTRY] Successfully deleted value: %ws\\%ws\n", event.Data.Registry.Path, event.Data.Registry.ValueName);
            }
            else {
                LogEvent(L"[REGISTRY] Failed to delete value (0x%08X): %ws\\%ws\n", event.Data.Registry.Status, event.Data.Registry.Path, event.Data.Registry.ValueName);
            }
            break;
        }
        case ERegistryUnknown: {
            LogEvent(L"[REGISTRY] Unknown event (Action ID: %lu): %ws\n", event.Data.Registry.DwordData, event.Data.Registry.Path);
            break;
        }
        default: {
            LogEvent(L"[UNKNOWN] Unrecognized Event Type ID: %d\n", event.Type);
            break;
        }
    }
}

void LogEvent(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);

    vwprintf(format, args);

    if (g_LogFile) {
        vfwprintf(g_LogFile, format, args);
    }

    va_end(args);
}

void LoggerWorkerThread() {
    while (g_KeepRunning || !g_EventQueue.empty()) {
        std::unique_lock<std::mutex> lock(g_QueueMutex);

        g_QueueCV.wait(lock, [] { return !g_EventQueue.empty() || !g_KeepRunning; });

        while (!g_EventQueue.empty()) {
            MONITOR_EVENT ev = g_EventQueue.front();
            g_EventQueue.pop();

            lock.unlock();
            PrintEvent(ev);
            lock.lock();
        }
    }
}