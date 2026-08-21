# Threat Detection Engine POC

![C++](https://img.shields.io/badge/C%2B%2B-17-blue?logo=c%2B%2B&logoColor=white)
![Win32 API](https://img.shields.io/badge/Win32-API-0078D6?logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## Executive Summary
The **Threat Detection Engine POC** is a highly privileged, Session 0 autonomous Windows Service written in C++17. It acts as an endpoint detection and response (EDR) sensor, combining point-in-time process memory snapshotting with real-time Kernel event streaming. This project implements the foundational architecture required by the master blueprint, the Windows Telemetry and Threat Detection Engine.

By leveraging undocumented NTAPI structures, Event Tracing for Windows (ETW), and direct memory querying, this engine detects sophisticated evasion techniques like Process Hollowing, unbacked memory execution, and system DLL masquerading without relying on easily bypassed user-mode API hooks.

---

## Architectural Backbone

The engine is built on four core technical pillars:

### 1. Session 0 Isolation & IPC
To prevent tampering from standard user processes or malware, the engine runs exclusively as a Windows Service (Session 0). Communication with user-facing clients is facilitated through a secure, asynchronous **Named Pipe** (`\\.\pipe\ThreatDetectionPipe`) using Overlapped I/O. 

### 2. Event-Driven Kernel Telemetry (ETW)
Rather than aggressively polling the system for changes, the engine establishes a real-time bridge to the Windows Kernel via **Event Tracing for Windows (ETW)**. 
* Subscribes to the `Microsoft-Windows-Kernel-Process` provider.
* Uses the **Trace Data Helper (TDH)** API to parse raw binary payloads, extracting true Process IDs and NT Device Paths (`\Device\HarddiskVolume...`) the exact microsecond a process spawns or terminates.

### 3. Thread-Safe State Management & The Tombstone Pattern
Bridging a heavy 15-second baseline memory scan with a microsecond-level real-time ETW stream introduces extreme concurrency risks. The engine utilizes strict `std::mutex` locks and the **Tombstone Pattern**. When ETW logs a process termination, the memory manager safely marks the process as `Terminated` rather than physically deleting it, preventing vector reallocation crashes and dangling pointer access violations.

### 4. Memory Forensics & Cryptographic Verification
The engine actively scans the memory space of tracked processes:
* **Memory Anomalies:** Locates memory pages with `PAGE_EXECUTE_READWRITE` (RWX) protections that are `MEM_PRIVATE` (not backed by a legitimate file on disk)—a primary indicator of Process Hollowing or Reflective DLL Injection.
* **Cryptographic Hashing:** Calculates SHA-256 hashes for loaded modules using the Windows Cryptography API (`wincrypt.h`).
* **Signature Verification:** Uses `WinVerifyTrust` to validate Authenticode digital signatures.
* **RAM Cache:** Caches signature validation results in an O(1) `std::unordered_map` to prevent catastrophic CPU overhead during subsequent scans.

---

## Critical API & NTAPI Distinctions

This engine relies on several low-level Windows APIs to bypass standard abstractions:

| Function / Structure | Purpose in Engine |
| :--- | :--- |
| `NtQueryInformationProcess` | Dynamically resolved from `ntdll.dll` to locate the Process Environment Block (PEB). |
| `PEB` & `RTL_USER_PROCESS_PARAMETERS` | Read via `ReadProcessMemory` to extract the true command-line arguments of remote processes, bypassing standard toolhelp limitations. |
| `VirtualQueryEx` | Walks the virtual memory pages of remote processes to evaluate memory protections and states for injection detection. |
| `StartTraceW` / `OpenTraceW` | Initializes the high-resolution, real-time ETW kernel listener. |
| `TdhGetProperty` | Cracks the opaque binary ETW payload to extract strongly-typed properties (e.g., `ProcessId`, `ImageName`). |
| `WinVerifyTrust` | Executes heavy cryptographic checks to ensure loaded `.dll` files are legitimately signed by trusted authorities. |

---

## Deployment & Usage

### 1. Compilation
The engine is built using the MinGW-w64 compiler suite. It must be statically linked against several Windows libraries.

```bash
x86_64-w64-mingw32-g++ -std=c++17 -Wall -Wextra -static main.cpp ProcessEnumerator.cpp EtwMonitor.cpp -o ThreatDetectionEngine.exe -lwintrust -ladvapi32 -ltdh -lole32 -municode
```

### 2. Service Installation (Run as Administrator)
Because it is a service, you cannot double-click the `.exe`. You must register it with the Windows Service Control Manager (SCM).

```cmd
# Create the service
sc create ThreatDetectionEngine binPath= "C:\Path\To\Your\ThreatDetectionEngine.exe" start= demand

# Start the engine
sc start ThreatDetectionEngine
```

*(Note: The engine will take approximately 10-15 seconds to hash and baseline the system upon booting before it accepts IPC connections.)*

### 3. Querying the Engine
You can query the live telemetry stream using any client that connects to `\\.\pipe\ThreatDetectionPipe`. Sending the command `SCAN_MEMORY` returns the live, ETW-synchronized baseline:

```text
[+] LIVE TELEMETRY REPORT (ETW & MEMORY ENGINE)
    Total Processes in Scope:  105
    Active (Running):          105
    Terminated (Tombstoned):   1
    Suspicious Memory Regions: 18
    Suspicious DLLs/Modules:   1080
    SHA-256 Signature Cache:   Warm (Active)
    Kernel Telemetry Stream:   Synchronized (ETW)
```

### 4. Cleanup
```cmd
sc stop ThreatDetectionEngine
sc delete ThreatDetectionEngine
```
