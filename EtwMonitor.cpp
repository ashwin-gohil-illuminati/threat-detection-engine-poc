#include "EtwMonitor.h"
#include <iostream>
#include <fstream>
#include "ProcessEnumerator.h"

// GUID for Microsoft-Windows-Kernel-Process provider
// {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}
/*
In the Windows NT ecosystem, GUID does not stand for "Group User ID". It stands for Globally Unique Identifier.
It is a 128-bit (16-byte) integer used by the Windows Kernel to universally identify everything from hardware
drivers to COM objects to ETW Providers. Microsoft guarantees that no two GUIDs generated in the world will
ever be the same.

The hex values and the nested curly braces are directly tied to how the Windows C API defines the GUID struct
in memory. Under the hood in guiddef.h, the struct looks exactly like this:

typedef struct _GUID {
    unsigned long  Data1;    // 4 bytes (32-bit integer)
    unsigned short Data2;    // 2 bytes (16-bit integer)
    unsigned short Data3;    // 2 bytes (16-bit integer)
    unsigned char  Data4[8]; // 8 bytes (Array of 8 characters/bytes)
} GUID;

The hex addresses in the struct can be seen by quering as = C:\WORK>logman query providers
which gives a huge list of values for many providers or services. In there I searched and caught the
values used to fill the GUID struct.
Microsoft-Windows-Kernel-Process         {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}

The constructor:
Notice the colon : after the constructor's parentheses.
Everything between that colon and the opening curly brace { is the Initializer List.

Why do we use this?
If you assign variables inside the curly braces (like we did with m_SessionName),
C++ actually creates the variables first using default junk memory, and then overwrites
that memory with your new values.
By using the Initializer List (: m_SessionHandle(0)), you instruct the C++ compiler to
initialize those variables with the exact correct value at the exact microsecond the object is created in RAM.
It bypasses the double-write penalty and is the professional standard for high-performance C++.

1. Direct Initialization vs. Assignment
In C++, there is a strict difference between giving a variable a value the moment it is born
(Initialization) and changing its value after it already exists (Assignment).

Assignment (= inside the { }):
If you wrote m_SessionHandle = 0; inside the constructor's curly braces,
the C++ compiler first allocates RAM for m_SessionHandle filled with random,
leftover garbage data. A fraction of a millisecond later, your = operator executes
and overwrites that garbage data with 0. (This is technically a double-write).

Direct Initialization (( ) before the { }):
The syntax you pointed out—m_SessionHandle(0)—is called Direct Initialization
inside a Member Initializer List. This tells the C++ compiler: "When you carve out the RAM
to create this object, do not use garbage memory. Put exactly 0 into that memory slot at the
exact moment of creation."

The struct in CleanOrphanedSessions as EVENT_TRACE_PROPERTIES is well defined but for the last variable
for filename we need extra memory and the filename value will be at the trailing end of the struct where
the offset will be assigned just before the string value. 

*/

static const GUID KernelProcessProviderGuid = 
{ 0x22fb2cd6, 0x0e7b, 0x422b, { 0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16 } };

EtwMonitor::EtwMonitor() : m_SessionHandle(0), m_TraceHandle(INVALID_PROCESSTRACE_HANDLE), m_hEtwThread(NULL), m_IsRunning(false) {
    m_SessionName = L"ThreatEngine_ETW_Session";
}

EtwMonitor::~EtwMonitor() {
    Stop();
}

void EtwMonitor::CleanOrphanedSessions() {
    // ETW Sessions survive program crashes! We must ensure our named session is dead before starting.
    EVENT_TRACE_PROPERTIES* pProperties = (EVENT_TRACE_PROPERTIES*)malloc(sizeof(EVENT_TRACE_PROPERTIES) + 1024);
    ZeroMemory(pProperties, sizeof(EVENT_TRACE_PROPERTIES) + 1024);
    pProperties->Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES) + 1024;
    
    ControlTraceW(0, m_SessionName.c_str(), pProperties, EVENT_TRACE_CONTROL_STOP);
    free(pProperties);
}

bool EtwMonitor::Start(ProcessEnumerator* pEnum) {
    CleanOrphanedSessions();

    // 1. Configure the ETW Session Properties
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (m_SessionName.length() + 1) * sizeof(wchar_t);
    EVENT_TRACE_PROPERTIES* pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    ZeroMemory(pSessionProperties, bufferSize);

    pSessionProperties->Wnode.BufferSize = bufferSize;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->Wnode.ClientContext = 1; // Use QPC (High resolution timer)
    pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE; // We want live events, not a file
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    // 2. Start the Trace Controller
    ULONG status = StartTraceW(&m_SessionHandle, m_SessionName.c_str(), pSessionProperties);
    free(pSessionProperties);

    if (status != ERROR_SUCCESS) return false;

    // 3. Enable the specific Kernel Process Provider
    status = EnableTraceEx2(
        m_SessionHandle,
        &KernelProcessProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0, // Any keyword
        0, 0, NULL
    );

    if (status != ERROR_SUCCESS) {
        Stop();
        return false;
    }

    // 4. Configure the Consumer to listen to the session we just created
    EVENT_TRACE_LOGFILEW m_TraceLog;
    ZeroMemory(&m_TraceLog, sizeof(EVENT_TRACE_LOGFILEW));
    m_TraceLog.LoggerName = (LPWSTR)m_SessionName.c_str();
    m_TraceLog.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    m_TraceLog.EventRecordCallback = EventRecordCallback;
    m_TraceLog.Context = pEnum; 

    m_TraceHandle = OpenTraceW(&m_TraceLog);
    if (m_TraceHandle == INVALID_PROCESSTRACE_HANDLE) {
        Stop();
        return false;
    }

    // 5. Spawn the background thread to actually process the events
    m_IsRunning = true;
    m_hEtwThread = CreateThread(NULL, 0, EtwThreadProc, this, 0, NULL);

    return true;
}

void EtwMonitor::Stop() {
    if (!m_IsRunning) return;
    m_IsRunning = false;

    if (m_TraceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(m_TraceHandle);
        m_TraceHandle = INVALID_PROCESSTRACE_HANDLE;
    }

    CleanOrphanedSessions();

    if (m_hEtwThread) {
        WaitForSingleObject(m_hEtwThread, 1000);
        CloseHandle(m_hEtwThread);
        m_hEtwThread = NULL;
    }
}

DWORD WINAPI EtwMonitor::EtwThreadProc(LPVOID lpParam) {
    EtwMonitor* pMonitor = (EtwMonitor*)lpParam;
    
    // This is a BLOCKING call. It sits here forever, pumping events to EventRecordCallback
    ProcessTrace(&pMonitor->m_TraceHandle, 1, 0, 0);
    
    return 0;
}

void WINAPI EtwMonitor::EventRecordCallback(PEVENT_RECORD EventRecord) {
    
    DWORD processId = EventRecord->EventHeader.ProcessId;
    USHORT eventId = EventRecord->EventHeader.EventDescriptor.Id;

    ProcessEnumerator* engine = (ProcessEnumerator*)EventRecord->UserContext;

    // We are only interested in Event ID 1 (Process Start) and Event ID 2 (Process Stop) for now
    if (eventId == 1 || eventId == 2) {
        
        DWORD truePid = GetEventUInt32Property(EventRecord, L"ProcessId");
        // Extract the executable name using our TDH helper
        std::wstring imageName = GetEventStringProperty(EventRecord, L"ImageName");

        // <-- ADD THIS: Route the live event directly into the baseline tree!
        if (engine != nullptr && truePid != 0) {
            engine->ApplyEtwEvent(truePid, imageName, (eventId == 1));
        }
        
        std::ofstream logFile("C:\\EtwLog.txt", std::ios::app);
        if (logFile.is_open()) {
            if (eventId == 1) {
                logFile << "[+] PROCESS START -> PID: " << processId << " | Image: " << std::string(imageName.begin(), imageName.end()) << std::endl;
            } else if (eventId == 2) {
                logFile << "[-] PROCESS STOP  -> PID: " << processId << " | Image: " << std::string(imageName.begin(), imageName.end()) << std::endl;
            }
            logFile.close();
        }
    }
}


std::wstring EtwMonitor::GetEventStringProperty(PEVENT_RECORD pEvent, LPCWSTR propertyName) {
    PROPERTY_DATA_DESCRIPTOR desc;
    ZeroMemory(&desc, sizeof(PROPERTY_DATA_DESCRIPTOR));
    desc.PropertyName = (ULONGLONG)propertyName;
    desc.ArrayIndex = ULONG_MAX;

    DWORD propertySize = 0;
    // 1. Ask TDH how large this specific property is inside the binary chunk
    DWORD status = TdhGetPropertySize(pEvent, 0, NULL, 1, &desc, &propertySize);
    if (status != ERROR_SUCCESS || propertySize == 0) {
        return L""; // Property not found or empty
    }

    // 2. Allocate a temporary buffer and pull the data
    BYTE* buffer = (BYTE*)malloc(propertySize);
    if (!buffer) return L"";

    status = TdhGetProperty(pEvent, 0, NULL, 1, &desc, propertySize, buffer);
    
    std::wstring result = L"";
    if (status == ERROR_SUCCESS) {
        // We cast the raw bytes back into a wide-string
        result = std::wstring((wchar_t*)buffer);
    }

    free(buffer);
    return result;
}


DWORD EtwMonitor::GetEventUInt32Property(PEVENT_RECORD pEvent, LPCWSTR propertyName) {
    PROPERTY_DATA_DESCRIPTOR desc;
    ZeroMemory(&desc, sizeof(PROPERTY_DATA_DESCRIPTOR));
    desc.PropertyName = (ULONGLONG)propertyName;
    desc.ArrayIndex = ULONG_MAX;

    DWORD propertySize = 0;
    DWORD status = TdhGetPropertySize(pEvent, 0, NULL, 1, &desc, &propertySize);
    if (status != ERROR_SUCCESS || propertySize != sizeof(DWORD)) return 0;

    DWORD value = 0;
    status = TdhGetProperty(pEvent, 0, NULL, 1, &desc, propertySize, (PBYTE)&value);
    if (status == ERROR_SUCCESS) return value;
    
    return 0;
}