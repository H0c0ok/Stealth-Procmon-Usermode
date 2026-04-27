#pragma once
#include <Windows.h>
#include <winioctl.h>

#define IOCTL_MAP_MEMORY   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNMAP_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_TARGET_PID  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_TARGET_NAME CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_EVENT_MESSAGE 256
#define MAX_EVENTS 1024

typedef enum _MONITOR_EVENT_TYPE {
    EProcessCreate,
    EProcessExit,
    EFilePreCreate,
    EFilePostCreate,
    EFilePreOpen,
    EFilePostOpen,
    EFilePreRead,
    EFilePostRead,
    EFilePreWrite,
    EFilePostWrite,
    EFileUnknown,
    ERegistryPreCreateValue,
    ERegistryPostCreateValue,
    ERegistryPreSetValue,
    ERegistryPostSetValue,
    ERegistryPreGetValue,
    ERegistryPostGetValue,
    ERegistryPreEnumerateValue,
    ERegistryPostEnumerateValue,
    ERegistryPreEnumerateKey,
    ERegistryPostEnumerateKey,
    ERegistryPreQueryValueKey,
    ERegistryPostQueryValueKey,
    ERegistryPreQueryMultipleValueKey,
    ERegistryPostQueryMultipleValueKey,
    ERegistryPreCreateKey,
    ERegistryPostCreateKey,
    ERegistryPreDeleteValue,
    ERegistryPostDeleteValue,
    ERegistryUnknown,
    EThreadCreate,
    EThreadExit
} MONITOR_EVENT_TYPE;

typedef struct _MONITOR_EVENT {
    LARGE_INTEGER TimeStamp;
    ULONG ProcessId;
    MONITOR_EVENT_TYPE Type;
    union {
        struct {
            ULONG ParentPid;
            UCHAR IsInherited;
            WCHAR ImageName[128];
            WCHAR CommandLine[128];
        } Process;

        struct {
            NTSTATUS Status;
            ULONG_PTR Information;
            WCHAR FilePath[256];
        } File;

        struct {
            NTSTATUS Status;
            ULONG DataType;
            ULONG DataSize;
            ULONG DwordData;
            WCHAR Path[128];
            WCHAR ValueName[64];
            WCHAR StringData[128];
        } Registry;

        struct {
            ULONG ThreadId;
        } Thread;

    } Data;
} MONITOR_EVENT, * PMONITOR_EVENT;

typedef struct _SHARED_MEMORY_BUFFER {
    volatile ULONG WriteIndex; // index for driver itself
    volatile ULONG ReadIndex; // index for user-mode application
    volatile ULONG DroppedEvents; // Counter for missed events
    MONITOR_EVENT Events[MAX_EVENTS];
} SHARED_MEMORY_BUFFER, * PSHARED_MEMORY_BUFFER;

