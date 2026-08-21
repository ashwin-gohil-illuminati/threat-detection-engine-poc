#ifndef PROCESS_NODE_H
#define PROCESS_NODE_H

#include <string>
#include <vector>
#include <windows.h>

enum class ProcessState {
    Running,
    Terminated,
    // We can add more later (e.g., Suspended)
};

// --- NEW: Struct to hold Virtual Memory Regions ---
struct MemoryRegionNode {
    PVOID baseAddress;
    SIZE_T regionSize;
    DWORD state;             // MEM_COMMIT, MEM_FREE, etc.
    DWORD protection;        // PAGE_READWRITE, PAGE_EXECUTE_READWRITE, etc.
    DWORD type;              // MEM_IMAGE, MEM_PRIVATE, etc.
    bool isSuspicious;       // Flag for RWX or unbacked executable memory
};


// Struct to hold loaded DLL/Module data ---
struct ModuleNode {
    std::wstring moduleName;
    std::wstring modulePath;
    PVOID baseAddress;      // The memory address where the DLL is loaded
    DWORD moduleSize;       // The size of the loaded DLL in memory
    bool isSuspicious;      // Flag set if loaded from abnormal/writable paths
    std::wstring anomalyReason; // Description of detected anomaly (if any)
};


struct ProcessNode {
    DWORD pid;
    DWORD ppid;
    std::wstring imageName;
    std::wstring imagePath;
    std::wstring commandLine;
    FILETIME creationTime;
    FILETIME exitTime;
    ProcessState state;
    
    // Raw, non-owning pointers to child processes
    std::vector<ProcessNode*> children;
    std::vector<ModuleNode> modules;
    // --- NEW: List of memory regions allocated in this process ---
    std::vector<MemoryRegionNode> memoryRegions;
};


#endif