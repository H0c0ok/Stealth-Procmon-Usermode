#include <Windows.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include "SharedDefines.h"

constexpr auto DEVICE_NAME_PATH = L"C:\\sysmon_link.txt";;

static bool IsAppRunningAsAdmin();
std::wstring GetDriverDescriptorName();
HANDLE OpenDriverDescriptor(std::wstring&);
std::wstring GetTagetNameFromUser();
void PrintEvent(const MONITOR_EVENT&);

int main(int argc, char* argv[]) {

    if (!IsAppRunningAsAdmin) {
        std::wcerr << L"[!] Please restart app with admin privileges [!]" << std::endl;
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
        return 1;
    }

    while (true) {

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

    // TODO: somehow check for CTRL + C
    DeviceIoControl(DriverDescriptorHandle, IOCTL_UNMAP_MEMORY, NULL, 0, NULL, 0, &bytesReturned, NULL);
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
        // TODO: registry events
    }
}
