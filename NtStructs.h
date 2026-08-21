#ifndef NT_STRUCTS_H
#define NT_STRUCTS_H

#include <windows.h>
#include <winternl.h> // Contains some base NT structures

// Function pointer definition for NtQueryInformationProcess
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// We need a partial definition of RTL_USER_PROCESS_PARAMETERS to reach the CommandLine
typedef struct _RTL_USER_PROCESS_PARAMETERS_PARTIAL {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS_PARTIAL, *PRTL_USER_PROCESS_PARAMETERS_PARTIAL;

// We need a partial definition of the PEB to reach the ProcessParameters
typedef struct _PEB_PARTIAL {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PRTL_USER_PROCESS_PARAMETERS_PARTIAL ProcessParameters;
} PEB_PARTIAL, *PPEB_PARTIAL;

#endif