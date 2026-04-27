#include <Windows.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <atomic>
#include "SharedDefines.h"

constexpr auto DEVICE_NAME_PATH = L"C:\\sysmon_link.txt";;
std::atomic<bool> g_KeepRunning{ true };

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

        while (sharedBuffer->ReadIndex != sharedBuffer->WriteIndex) {
            auto event = sharedBuffer->Events[sharedBuffer->ReadIndex];

            sharedBuffer->ReadIndex = (sharedBuffer->ReadIndex + 1) % MAX_EVENTS;

            PrintEvent(event);
        }
        Sleep(5);
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
    std::wifstream DriverDescriptorFile(DEVICE_NAME_PATH, std::ios::binary);
    if (!DriverDescriptorFile.is_open()) {
        return L"";
    }

    std::wstring DriverDescriptorName;
    std::getline(DriverDescriptorFile, DriverDescriptorName);
    DriverDescriptorFile.close();
    return DriverDescriptorName;
}

HANDLE OpenDriverDescriptor(std::wstring& deviceName) {
    HANDLE hDevice = CreateFileW(deviceName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Error: Could not open driver. GetLastError: " << GetLastError() << "\n";
    }
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
            wprintf(L"[PROCESS] Created: %ws | Parent: %lu | Cmd: %ws\n",
                event.Data.Process.ImageName,
                event.Data.Process.ParentPid,
                event.Data.Process.CommandLine
            );
            break;
        }
        case EProcessExit: {
            wprintf(L"[PROCESS] Terminated\n");
            break;
        }
        case EThreadCreate: {
            wprintf(L"[THREAD] Created | TID: %lu\n", event.Data.Thread.ThreadId);
            break;
        }
        case EThreadExit: {
            wprintf(L"[THREAD] Terminated | TID: %lu\n", event.Data.Thread.ThreadId);
            break;
        }
        case EFilePreCreate: {
            wprintf(L"[FILE] Wants to create: %ws\n", event.Data.File.FilePath);
            break;
        }
        case EFilePostCreate: {
            if (event.Data.File.Status == 0) {
                wprintf(L"[FILE] Successfully created: %ws\n", event.Data.File.FilePath);
            }
            else {
                wprintf(L"[FILE] Failed to create (0x%08X): %ws\n", event.Data.File.Status, event.Data.File.FilePath);
            }
            break;
        }
        case EFilePreOpen: {
            wprintf(L"[FILE] Wants to open: %ws\n", event.Data.File.FilePath);
            break;
        }
        case EFilePostOpen: {
            if (event.Data.File.Status == 0) {
                wprintf(L"[FILE] Successfully opened: %ws\n", event.Data.File.FilePath);
            }
            else {
                wprintf(L"[FILE] Failed to open (0x%08X): %ws\n", event.Data.File.Status, event.Data.File.FilePath);
            }
            break;
        }
        case EFilePreRead: {
            wprintf(L"[FILE] Wants to read: %ws\n", event.Data.File.FilePath);
            break;
        }
        case EFilePostRead: {
            if (event.Data.File.Status == 0) {
                wprintf(L"[FILE] Successfully read: %ws\n", event.Data.File.FilePath);
            }
            else {
                wprintf(L"[FILE] Failed to read (0x%08X): %ws\n", event.Data.File.Status, event.Data.File.FilePath);
            }
            break;
        }
        case EFilePreWrite: {
            wprintf(L"[FILE] Wants to write: %ws\n", event.Data.File.FilePath);
            break;
        }
        case EFilePostWrite: {
            if (event.Data.File.Status == 0) {
                wprintf(L"[FILE] Successfully write: %ws\n", event.Data.File.FilePath);
            }
            else {
                wprintf(L"[FILE] Failed to write (0x%08X): %ws\n", event.Data.File.Status, event.Data.File.FilePath);
            }
            break;
        }
        case EFileUnknown: {
            wprintf(L"[FILE] Unkown operation: %ws\n", event.Data.File.FilePath);
            break;
        }
        case ERegistryPreCreateValue: {
            wprintf(L"[REGISTRY] Wants to create value: %ws\\%ws\n", event.Data.Registry.Path, event.Data.Registry.ValueName);
            break;
        }
        case ERegistryPostCreateValue: {
            if (event.Data.Registry.Status == 0) {
                wprintf(L"[REGISTRY] Successfully created value: %ws\\%ws\n", event.Data.Registry.Path, event.Data.Registry.ValueName);
            }
            else {
                wprintf(L"[REGISTRY] Failed to create value (0x%08X): %ws\\%ws\n", event.Data.Registry.Status, event.Data.Registry.Path, event.Data.Registry.ValueName);
            }
            break;
        }
        case ERegistryPreSetValue: {
            wprintf(L"[REGISTRY] Wants to set value: %ws\\%ws", event.Data.Registry.Path, event.Data.Registry.ValueName);
            if (event.Data.Registry.DataType == REG_DWORD) {
                wprintf(L" (DWORD: %lu)\n", event.Data.Registry.DwordData);
            }
            else if (event.Data.Registry.DataType == REG_SZ || event.Data.Registry.DataType == REG_EXPAND_SZ) {
                wprintf(L" (STRING: %ws)\n", event.Data.Registry.StringData);
            }
            else {
                wprintf(L" (Type: %lu, Size: %lu bytes)\n", event.Data.Registry.DataType, event.Data.Registry.DataSize);
            }
            break;
        }
        case ERegistryPostSetValue: {
            if (event.Data.Registry.Status == 0) {
                wprintf(L"[REGISTRY] Successfully set value: %ws\\%ws\n", event.Data.Registry.Path, event.Data.Registry.ValueName);
            }
            else {
                wprintf(L"[REGISTRY] Failed to set value (0x%08X): %ws\\%ws\n", event.Data.Registry.Status, event.Data.Registry.Path, event.Data.Registry.ValueName);
            }
            break;
        }
        case ERegistryPreGetValue:
        case ERegistryPreQueryValueKey: {
            wprintf(L"[REGISTRY] Wants to query value: %ws\\%ws\n", event.Data.Registry.Path, event.Data.Registry.ValueName);
            break;
        }
        case ERegistryPostGetValue:
        case ERegistryPostQueryValueKey: {
            if (event.Data.Registry.Status == 0) {
                wprintf(L"[REGISTRY] Successfully queried value: %ws\\%ws", event.Data.Registry.Path, event.Data.Registry.ValueName);
                if (event.Data.Registry.DataType == REG_DWORD) {
                    wprintf(L" (DWORD: %lu)\n", event.Data.Registry.DwordData);
                }
                else if (event.Data.Registry.DataType == REG_SZ || event.Data.Registry.DataType == REG_EXPAND_SZ) {
                    wprintf(L" (STRING: %ws)\n", event.Data.Registry.StringData);
                }
                else {
                    wprintf(L" (Type: %lu, Size: %lu bytes)\n", event.Data.Registry.DataType, event.Data.Registry.DataSize);
                }
            }
            else {
                wprintf(L"[REGISTRY] Failed to query value (0x%08X): %ws\\%ws\n", event.Data.Registry.Status, event.Data.Registry.Path, event.Data.Registry.ValueName);
            }
            break;
        }
        case ERegistryPreEnumerateValue:
        case ERegistryPreEnumerateKey: {
            wprintf(L"[REGISTRY] Wants to enumerate (Index %lu) in: %ws\n", event.Data.Registry.DwordData, event.Data.Registry.Path);
            break;
        }
        case ERegistryPostEnumerateValue:
        case ERegistryPostEnumerateKey: {
            if (event.Data.Registry.Status == 0) {
                wprintf(L"[REGISTRY] Emuneration success (Index %lu): %ws\n", event.Data.Registry.DwordData, event.Data.Registry.Path);
            }
            else {
                wprintf(L"[REGISTRY] Emuneration end/failed (0x%08X): %ws\n", event.Data.Registry.Status, event.Data.Registry.Path);
            }
            break;
        }
        case ERegistryPreQueryMultipleValueKey: {
            wprintf(L"[REGISTRY] Wants to query multiple values (%lu entries) in: %ws\n", event.Data.Registry.DataSize, event.Data.Registry.Path);
            break;
        }
        case ERegistryPostQueryMultipleValueKey: {
            if (event.Data.Registry.Status == 0) {
                wprintf(L"[REGISTRY] Successfully queried multiple values in: %ws\n", event.Data.Registry.Path);
            }
            else {
                wprintf(L"[REGISTRY] Failed to query multiple values (0x%08X) in: %ws\n", event.Data.Registry.Status, event.Data.Registry.Path);
            }
            break;
        }
        case ERegistryPreCreateKey: {
            wprintf(L"[REGISTRY] Wants to create key: %ws\n", event.Data.Registry.Path);
            break;
        }
        case ERegistryPostCreateKey: {
            if (event.Data.Registry.Status == 0) {
                wprintf(L"[REGISTRY] Successfully created key: %ws\n", event.Data.Registry.Path);
            }
            else {
                wprintf(L"[REGISTRY] Failed to create key (0x%08X): %ws\n", event.Data.Registry.Status, event.Data.Registry.Path);
            }
            break;
        }
        case ERegistryPreDeleteValue: {
            wprintf(L"[REGISTRY] Wants to delete value: %ws\\%ws\n", event.Data.Registry.Path, event.Data.Registry.ValueName);
            break;
        }
        case ERegistryPostDeleteValue: {
            if (event.Data.Registry.Status == 0) {
                wprintf(L"[REGISTRY] Successfully deleted value: %ws\\%ws\n", event.Data.Registry.Path, event.Data.Registry.ValueName);
            }
            else {
                wprintf(L"[REGISTRY] Failed to delete value (0x%08X): %ws\\%ws\n", event.Data.Registry.Status, event.Data.Registry.Path, event.Data.Registry.ValueName);
            }
            break;
        }
        case ERegistryUnknown: {
            wprintf(L"[REGISTRY] Unknown event (Action ID: %lu): %ws\n", event.Data.Registry.DwordData, event.Data.Registry.Path);
            break;
        }
        default: {
            wprintf(L"[UNKNOWN] Unrecognized Event Type ID: %d\n", event.Type);
            break;
        }
    }
}
