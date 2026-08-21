#ifndef ETW_MONITOR_H
#define ETW_MONITOR_H

#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <string>
#include <atomic>

class ProcessEnumerator; // Forward declaration

class EtwMonitor {
public:
    EtwMonitor();
    ~EtwMonitor();

    bool Start(ProcessEnumerator* pEnum); // <-- UPDATE THIS
    void Stop();

private:
    TRACEHANDLE m_SessionHandle;
    TRACEHANDLE m_TraceHandle;
    std::wstring m_SessionName;

    HANDLE m_hEtwThread;
    std::atomic<bool> m_IsRunning;

    EVENT_TRACE_LOGFILEW m_TraceLog;

    // The Controller: Stops any orphaned sessions that crashed previously
    void CleanOrphanedSessions();

    // The Consumer Thread: Blocks and listens to the Kernel
    static DWORD WINAPI EtwThreadProc(LPVOID lpParam);

    // The Callback: The Kernel fires this function every time an event occurs
    static void WINAPI EventRecordCallback(PEVENT_RECORD EventRecord);
    // TDH Helper to extract string properties from the raw event payload
    static std::wstring GetEventStringProperty(PEVENT_RECORD pEvent, LPCWSTR propertyName);

    // FIX 2: New TDH Helper to extract exact Integers (like the True PID)
    static DWORD GetEventUInt32Property(PEVENT_RECORD pEvent, LPCWSTR propertyName);
};

#endif