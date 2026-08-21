#include <iostream>
#include <windows.h>
#include <vector>
#include "ProcessEnumerator.h"
#include <atomic>
#include "EtwMonitor.h"


/*

compile instructions - x86_64-w64-mingw32-g++ -std=c++17 -Wall -Wextra -static main.cpp ProcessEnumerator.cpp -o ThreatDetectionEngine.exe
x86_64-w64-mingw32-g++ -std=c++17 -Wall -Wextra -static main.cpp ProcessEnumerator.cpp -o ThreatDetectionEngine.exe -lwintrust



x86_64-w64-mingw32-g++ -std=c++17 -Wall -Wextra -static main.cpp ProcessEnumerator.cpp -o ThreatDetectionEngine.exe -lwintrust -ladvapi32

x86_64-w64-mingw32-g++ -std=c++17 -Wall -Wextra -static main.cpp ProcessEnumerator.cpp -o ThreatDetectionEngine.exe -lwintrust -ladvapi32 -municode


x86_64-w64-mingw32-g++ -std=c++17 -Wall -Wextra -static main.cpp ProcessEnumerator.cpp EtwMonitor.cpp -o ThreatDetectionEngine.exe -lwintrust -ladvapi32 -ltdh -lole32 -municode

To use compile instruction - 
x86_64-w64-mingw32-g++ -std=c++17 -Wall -Wextra -static main.cpp ProcessEnumerator.cpp EtwMonitor.cpp -o ThreatDetectionEngine.exe -lwintrust -ladvapi32 -ltdh -lole32 -municode

*/


#define SERVICE_NAME L"ThreatDetectionEngine"

// Global variables for Service status
// FIX: Modern C++17 zero-initialization syntax
SERVICE_STATUS        g_ServiceStatus = {}; 
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;
std::atomic<bool> g_IsBootstrapped = false;

// Forward declarations
void WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
void WINAPI ServiceCtrlHandler(DWORD CtrlCode);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

// FIX: Commenting out parameter names to satisfy API contract without triggering unused warnings
int wmain(int /*argc*/, wchar_t* /*argv*/[]) {
    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        {(LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONW)ServiceMain},
        {NULL, NULL}
    };

    if (StartServiceCtrlDispatcherW(ServiceTable) == FALSE) {
        std::wcout << L"Failed to start Service Control Dispatcher. (Are you running this as a service?)" << std::endl;
        return GetLastError();
    }

    return 0;
}

// FIX: Commented out unused parameter names
void WINAPI ServiceMain(DWORD /*argc*/, LPTSTR* /*argv*/) {
    g_StatusHandle = RegisterServiceCtrlHandlerW(SERVICE_NAME, ServiceCtrlHandler);
    if (g_StatusHandle == NULL) return;

    ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
    
    // The exact structural fix you caught earlier
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS; 
    
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        g_ServiceStatus.dwControlsAccepted = 0;
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        g_ServiceStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // FIX: Store the handle and explicitly close it to prevent a resource leak.
    HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    if (hThread != NULL) {
        CloseHandle(hThread); // The thread keeps running, we just release the tracking pointer.
    }

    WaitForSingleObject(g_ServiceStopEvent, INFINITE);

    CloseHandle(g_ServiceStopEvent);
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    g_ServiceStatus.dwWin32ExitCode = 0;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

void WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
    switch (CtrlCode) {
        case SERVICE_CONTROL_STOP:
            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            SetEvent(g_ServiceStopEvent);
            break;
        default:
            break;
    }
}

// --- THIS IS THE TASK 17 NAMED PIPE SERVER LOGIC THAT WAS MISSING ---
// This is the basic logic of IPC communication between session0 service and client.pp
// Replaced below with project related logic

/*
DWORD WINAPI ServiceWorkerThread(LPVOID) { //(LPVOID lpParam)
    LPCWSTR pipeName = L"\\\\.\\pipe\\ThreatDetectionPipe";
    
    // Setup the OVERLAPPED structure for asynchronous I/O
    OVERLAPPED os = {};
    os.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (os.hEvent == NULL) return ERROR_SUCCESS;

    HANDLE hEvents[2] = { g_ServiceStopEvent, os.hEvent };

    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0) {
        
        // Command the Kernel to create the IPC Pipe in memory
        HANDLE hPipe = CreateNamedPipeW(
            pipeName,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, 
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 512, 512, 0, NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        // Wait asynchronously for a client to connect
        ConnectNamedPipe(hPipe, &os);
        
        // Sleep until either the Service stops OR a client connects
        DWORD waitResult = WaitForMultipleObjects(2, hEvents, FALSE, INFINITE);

        if (waitResult == WAIT_OBJECT_0) {
            CloseHandle(hPipe);
            break; 
        } 
        else if (waitResult == WAIT_OBJECT_0 + 1) {
            // A Client connected! Read their command.
            wchar_t buffer[128] = {0};
            DWORD bytesTransferred;

            if (GetOverlappedResult(hPipe, &os, &bytesTransferred, FALSE)) {
                if (ReadFile(hPipe, buffer, sizeof(buffer) - sizeof(wchar_t), &bytesTransferred, NULL)) {
                    buffer[bytesTransferred / sizeof(wchar_t)] = L'\0'; 
                    
                    std::wstring response = L"Engine ACK: Received command [";
                    response += buffer;
                    response += L"] from Session 0!";

                    WriteFile(hPipe, response.c_str(), response.size() * sizeof(wchar_t), &bytesTransferred, NULL);
                    // --- NEW ARCHITECTURAL FIX ---
                    // Force the Service to wait until the Client successfully reads the message
                    FlushFileBuffers(hPipe);
                }
            }
            DisconnectNamedPipe(hPipe); 
        }
        
        CloseHandle(hPipe);
        ResetEvent(os.hEvent); 
    }

    CloseHandle(os.hEvent);
    return ERROR_SUCCESS;
}
*/


DWORD WINAPI BootstrapThread(LPVOID lpParam) {
    ProcessEnumerator* pEngineCore = (ProcessEnumerator*)lpParam;
    
    // Command the NT Kernel to deprioritize this thread
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);

    // THE FIX: Call the encapsulated state manager we built in Task 25!
    pEngineCore->InitializeBaseline();

    // The baseline is complete. Signal the Named Pipe.
    g_IsBootstrapped = true;
    
    return ERROR_SUCCESS;
}



DWORD WINAPI ServiceWorkerThread(LPVOID /*lpParam*/) {
    LPCWSTR pipeName = L"\\\\.\\pipe\\ThreatDetectionPipe";
    ProcessEnumerator engineCore;
    EtwMonitor etwMonitor;
    etwMonitor.Start(&engineCore);
    
    // --- THE EDR CORE ---
    // Instantiated OUTSIDE the loop. This guarantees the SHA-256 hash cache 
    // stays alive in memory for as long as the computer is turned on.

    // --- START THE BACKGROUND BOOTSTRAPPER ---
    g_IsBootstrapped = false;
    HANDLE hBootstrap = CreateThread(NULL, 0, BootstrapThread, &engineCore, 0, NULL);
    if (hBootstrap != NULL) {
        CloseHandle(hBootstrap); // We release the handle; the thread lives autonomously
    }
    // --------------------------------------------------
    
    OVERLAPPED os = {};
    os.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (os.hEvent == NULL) return ERROR_SUCCESS;

    HANDLE hEvents[2] = { g_ServiceStopEvent, os.hEvent };

    while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0) {
        
        HANDLE hPipe = CreateNamedPipeW(
            pipeName,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, 
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 1024, 1024, 0, NULL // Increased buffer sizes slightly for larger reports
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            Sleep(1000);
            continue;
        }

        ConnectNamedPipe(hPipe, &os);
        DWORD waitResult = WaitForMultipleObjects(2, hEvents, FALSE, INFINITE);

        if (waitResult == WAIT_OBJECT_0) {
            CloseHandle(hPipe);
            break; 
        } 
        else if (waitResult == WAIT_OBJECT_0 + 1) {
            wchar_t buffer[256] = {0};
            DWORD bytesTransferred;

            if (GetOverlappedResult(hPipe, &os, &bytesTransferred, FALSE)) {
                if (ReadFile(hPipe, buffer, sizeof(buffer) - sizeof(wchar_t), &bytesTransferred, NULL)) {
                    buffer[bytesTransferred / sizeof(wchar_t)] = L'\0'; 
                    
                    std::wstring commandStr(buffer);
                    std::wstring response;

                    // --- THE COMMAND ROUTER ---
                    if (commandStr == L"SCAN_MEMORY") {
                        
                        if (!g_IsBootstrapped) {
                            response = L"[!] Engine is currently bootstrapping the baseline cache. Please try again shortly.";
                        } else {
                            // Securely grab a locked copy of the live ETW-fed snapshot
                            std::vector<ProcessNode> safeSnapshot = engineCore.GetSafeSnapshotCopy();
                            
                            size_t totalSuspiciousRegions = 0;
                            size_t suspiciousModules = 0;
                            size_t activeProcesses = 0;
                            size_t terminatedProcesses = 0;
                            size_t totalProcessesTracked = safeSnapshot.size();

                            for (const auto& proc : safeSnapshot) {
                                if (proc.state == ProcessState::Running) {
                                    activeProcesses++;
                                } else if (proc.state == ProcessState::Terminated) {
                                    terminatedProcesses++;
                                }
                                
                                for (const auto& memRegion : proc.memoryRegions) {
                                    if (memRegion.isSuspicious) totalSuspiciousRegions++;
                                }
                                for (const auto& mod : proc.modules) {
                                    if (mod.isSuspicious) suspiciousModules++;
                                }
                            }

                            response = L"\n[+] LIVE TELEMETRY REPORT (ETW & MEMORY ENGINE)\n";
                            response += L"    Total Processes in Scope:  " + std::to_wstring(totalProcessesTracked) + L"\n";
                            response += L"    Active (Running):          " + std::to_wstring(activeProcesses) + L"\n";
                            response += L"    Terminated (Tombstoned):   " + std::to_wstring(terminatedProcesses) + L"\n";
                            response += L"    Suspicious Memory Regions: " + std::to_wstring(totalSuspiciousRegions) + L"\n";
                            response += L"    Suspicious DLLs/Modules:   " + std::to_wstring(suspiciousModules) + L"\n";
                            response += L"    SHA-256 Signature Cache:   Warm (Active)\n";
                            response += L"    Kernel Telemetry Stream:   Synchronized (ETW)";
                        }
                    }
                    else {
                        response = L"[-] Error: Unknown Command [";
                        response += commandStr;
                        response += L"]";
                    }

                    WriteFile(hPipe, response.c_str(), response.size() * sizeof(wchar_t), &bytesTransferred, NULL);
                    FlushFileBuffers(hPipe); // Safely wait for the Client to read
                }
            }
            DisconnectNamedPipe(hPipe); 
        }
        
        CloseHandle(hPipe);
        ResetEvent(os.hEvent); 
    }

    CloseHandle(os.hEvent);
    return ERROR_SUCCESS;
}




/*
Big explanation on the following statement line in main:
SERVICE_TABLE_ENTRYW ServiceTable[] = {
        {(LPWSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTIONW)ServiceMain},
        {NULL, NULL}
    };

SERVICE_TABLE_ENTRYW ServiceTable[] = An array of structs of type SERVICE_TABLE_ENTRYW
This struct contains variables for name of the service to be run in this service process
and a long pointer to ServiceMain function.

#define SERVICE_NAME L"ThreatDetectionEngine"
This is the variable holding the service name.
SERVICE_NAME is not the executable name;
it is the Logical Service Name registered inside the Windows Registry.
Executable Name: ThreatDetectionEngine.exe (The physical file on disk).

Service Name: ThreatDetectionEngine (The name the Service Control Manager (SCM) uses to identify
it when you run commands like sc start ThreatDetectionEngine).

(LPWSTR) Cast: Because C++ is strictly typed, we cast our string to LPWSTR (Long Pointer to Wide String) so the Win32 API accepts it without complaining.

We know the struct type so the array of struct ServiceTable[] contains first member as the 
struct and the struct with values is given as {varValue1, varValue2}. In the particular struct
type, the variables are mapped acccording to the definition. The missing piece of another struct
filled to the array as {NULL, NULL} has a clear explanation.

Yes, the {NULL, NULL} would still be absolutely necessary. (Note: If you included the NULL row, you would actually have to declare the bound as [2] to fit both structs).

Here is the fundamental reason why:
When you pass ServiceTable to the Windows API function (StartServiceCtrlDispatcherW),
the Windows OS does not know—and cannot see—the C++ array bounds you typed in your code.

In C and C++, when you pass an array to a function, the array "decays" into a raw memory pointer.
The Windows OS only receives the starting memory address of the very first element.
It has absolutely no idea if the array holds 1 item, 2 items, or 100 items.

Because Windows only has a starting address and no length, it relies entirely on walking
forward through memory, row by row, until it physically hits that {NULL, NULL} sentinel value.
If you declared the bound as [1] and omitted the NULL row, Windows would read your first service,
step forward to the next block of memory (which would just be whatever random, uninitialized
data happened to be sitting on the application stack next to your array), misinterpret that
garbage data as a service entry, and instantly crash the engine.

Additional explanation.
So, first member of this struct SERVICE_TABLE_ENTRYW is a long pointer to wstring to SERVICE_NAME.
The macro defined in this file above.

LPSERVICE_MAIN_FUNCTIONW LpserviceMainFunctionw;
The caps LPSERVICE_MAIN_FUNCTION is a long pointer to a function name as above.
The function itself does not return anything and expects 2 arguments which are
numberofArguments and double pointer to argumentVector strings. LPWSTR *vectors.

"The null-terminated argument strings passed to the service by the call to the StartService function that started the service. If there are no arguments, this parameter can be NULL." So *vectors (not docu variable name)
is like main(argc, *argv[])

Additional explanation
The Final Mystery: Why {NULL, NULL}?
You didn't mention the second row in the table, but it is critical.
Why do we pass an empty struct of {NULL, NULL} at the end?

This is a classic C-programming concept called a Null-Terminated Array (or Sentinel Value).
When you pass ServiceTable to the StartServiceCtrlDispatcherW function,
Windows doesn't know how big your array is. One executable can actually host multiple different
services at the same time (this is exactly what svchost.exe does!).

The Windows SCM loops through your array row by row. It needs a way to know when to stop looking.
When it hits a row where the Service Name is NULL, it says: "Ah, I have reached the end of the list,"
and stops parsing memory. If you forget the {NULL, NULL}, Windows will keep reading random computer
memory out of bounds until the engine crashes.

*/