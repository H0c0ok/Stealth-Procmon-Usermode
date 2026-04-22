#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include "SharedDefines.h"

#define DEVICE_NAME "\\\\.\\SysMon_A8F9_B2C4"


bool DEBUG = false;

int main(int argc, char* argv[]) {

    if (argc == 2) {
        if (std::string(argv[1]) == "DEBUG") {
            DEBUG = true;
        }
    }

    std::string targetName = "text.exe";
    std::getline(std::cin, targetName);
    std::wstring targetNameW(targetName.begin(), targetName.end());

    // Opening driver descriptor
    HANDLE hDevice = CreateFileA(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Error: Could not open driver. GetLastError: " << GetLastError() << "\n";
        return 1;
    }

    // Setting target name 
    
    DWORD bytesReturned;
    if (!DeviceIoControl(hDevice, IOCTL_SET_TARGET_NAME, (LPVOID)targetNameW.c_str(),
        (DWORD)((targetNameW.length() + 1) * sizeof(wchar_t)), NULL, 0, &bytesReturned, NULL)) {
        std::cerr << "[-] Error: Could not set target process name.\n";
        CloseHandle(hDevice);
        return 1;
    }
    std::wcout << L"[+] Monitoring started for: " << targetNameW << L"\n";

    // Mapping shared memory
    PSHARED_MEMORY_BUFFER pBuffer = NULL;
    if (!DeviceIoControl(hDevice, IOCTL_MAP_MEMORY, NULL, 0, &pBuffer, sizeof(PVOID), &bytesReturned, NULL)) {
        std::cerr << "[-] Error: Shared memory mapping failed.\n";
        CloseHandle(hDevice);
        return 1;
    }

    (DEBUG == true) ? std::cout << "[+] Shared memory mapped at: " << pBuffer << "\n" : std::cout << std::endl;

    ULONG localReadIndex = 0;
    std::cout << "[*] Press Ctrl+C to stop monitoring...\n";

    try {
        while (true) {
            if (localReadIndex != pBuffer->WriteIndex) {
                MONITOR_EVENT& ev = pBuffer->Events[localReadIndex];

                std::wcout << ev.Message << L"\n";

                localReadIndex = (localReadIndex + 1) % MAX_EVENTS;
            }
            else {
                Sleep(20);
            }
            if (GetKeyState(VK_ESCAPE) & 0x8000) break;
        }
    }
    catch (...) {
        std::cerr << "[-] Unexpected error during monitoring.\n";
    }

    if (!DeviceIoControl(hDevice, IOCTL_UNMAP_MEMORY, NULL, 0, NULL, 0, &bytesReturned, NULL)) {
        std::cerr << "[-] Warning: Failed to unmap memory via IOCTL.\n";
    }
    else {
        std::cout << "[+] Memory unmapped successfully.\n";
    }

    CloseHandle(hDevice);
    return 0;
}