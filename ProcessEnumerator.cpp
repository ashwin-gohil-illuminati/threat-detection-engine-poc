#include "ProcessEnumerator.h"
#include "NtStructs.h"
#include <iostream>
#include <string>

std::vector<ProcessNode> ProcessEnumerator::captureSnapshot() {
    // The list we will return
    std::vector<ProcessNode> processList;

    HANDLE procSnapshotHnd;

    procSnapshotHnd = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,
        0 // required as not optional but kernel will ignore it
    );

    if(procSnapshotHnd != INVALID_HANDLE_VALUE){
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32W);

        if(Process32FirstW(procSnapshotHnd, &processEntry)){
            do{

                ProcessNode currentProcessNode;
                currentProcessNode.pid = processEntry.th32ProcessID;
                currentProcessNode.ppid = processEntry.th32ParentProcessID;
                currentProcessNode.imageName = processEntry.szExeFile; //Only the executable name
                currentProcessNode.state = ProcessState::Running;
                enrichProcessNode(currentProcessNode);
                processList.push_back(currentProcessNode);

            }while(Process32NextW(procSnapshotHnd, &processEntry));
        }
        CloseHandle(procSnapshotHnd);
    }

    return processList;
}



std::wstring ProcessEnumerator::getCommandLine(HANDLE hProcess) {
    // 1. Get the handle to ntdll.dll
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    
    // 2. Dynamically resolve the NtQueryInformationProcess function
    pNtQueryInformationProcess NtQueryInfoProcess = (pNtQueryInformationProcess)(void*)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (NtQueryInfoProcess == nullptr) return L"";

    // 3. Call NtQueryInfoProcess to get the PROCESS_BASIC_INFORMATION (PBI)
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength = 0;
    NTSTATUS status = NtQueryInfoProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (!NT_SUCCESS(status)) return L"";

    
    // 4. Read the PEB from the remote process memory
    // Hint: ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)
    PEB_PARTIAL peb;
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
        return L""; // If we fail to read the PEB, abort and return empty string
    }
    
    // 5. Read the RTL_USER_PROCESS_PARAMETERS from the remote memory
    // Hint: ReadProcessMemory(hProcess, peb.ProcessParameters, &processParams, sizeof(processParams), &bytesRead)
    RTL_USER_PROCESS_PARAMETERS_PARTIAL processParams;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &processParams, sizeof(processParams), &bytesRead)) {
        return L""; // If we fail to read the parameters, abort
    }

    // 6. Finally, read the actual wide-string command line buffer!
    // processParams.CommandLine.Length tells you how many bytes to read.
    // processParams.CommandLine.Buffer is the remote pointer to read from.
    // Hint: Create a std::wstring initialized with nulls, or a wchar_t buffer, and read into it.
    // 6. Finally, read the actual wide-string command line buffer!

    USHORT lengthInBytes = processParams.CommandLine.Length;
    PVOID remoteBuffer = processParams.CommandLine.Buffer;

    // Safety check: some processes might not have a command line, or access is denied
    if (lengthInBytes == 0 || remoteBuffer == nullptr) {
        return L"";
    }

    // UNICODE_STRING length is in bytes. A wchar_t is 2 bytes on Windows.
    // We calculate the number of characters to size our string correctly.
    size_t charCount = lengthInBytes / sizeof(wchar_t);
    
    // Pre-allocate a wide string of the exact size we need, filled with nulls
    std::wstring commandLineStr(charCount, L'\0');

    bytesRead = 0;
    // Read directly from the target process into our std::wstring's internal memory
    if (ReadProcessMemory(hProcess, remoteBuffer, &commandLineStr[0], lengthInBytes, &bytesRead)) {
        return commandLineStr;
    }

    return L""; // Return the extracted string here

}



void ProcessEnumerator::enrichProcessNode(ProcessNode& node) {
    // 1. Open a handle to the process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, node.pid);
    
    // 2. Check if we successfully got a handle
    if (hProcess != NULL) {

        wchar_t filePath[MAX_PATH];
        DWORD fileBufferSize = MAX_PATH;

        if(QueryFullProcessImageNameW(hProcess, 0, filePath, &fileBufferSize)){
            // 3. Query the full image path
            node.imagePath = filePath;
        }else{
            //std::cout << "Failed to query the Image Path Name." << std::endl;
        }

        FILETIME ftCreation, ftExit, ftKernel, ftUser;
        
        if(GetProcessTimes(hProcess, &ftCreation, &ftExit, &ftKernel, &ftUser)){
            node.creationTime = ftCreation;
            node.exitTime = ftExit;
        }else{
            //std::cout << "Failed to get create and exit times of the process." << std::endl;
        }
        CloseHandle(hProcess);

        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, node.pid);
        if(hProcess != NULL){

            node.commandLine = getCommandLine(hProcess);
            // --- NEW: Capture the Memory Regions ---
            node.memoryRegions = captureMemoryRegions(hProcess);
            CloseHandle(hProcess);
            
        }else{
            //std::cout << "Failed to obtain handle of OpenProcess the second time." << std::endl;
        }

        node.modules = captureModules(node.pid);
    }
}


#include <iomanip> // If you want formatted column widths

void ProcessEnumerator::printProcessDetails(const std::vector<ProcessNode>& processes) {
    for (size_t i = 0; i < processes.size(); ++i) {
        const ProcessNode& proc = processes[i];

        std::wcout << L"--------------------------------------------------" << std::endl;
        std::wcout << L"PID:          " << proc.pid << std::endl;
        std::wcout << L"PPID:         " << proc.ppid << std::endl;
        std::wcout << L"State:        " << (proc.state == ProcessState::Running ? L"Running" : L"Terminated") << std::endl;
        std::wcout << L"ImageName:    " << proc.imageName << std::endl;
        std::wcout << L"Image Path:   " << (proc.imagePath.empty() ? L"[Access Denied / Empty]" : proc.imagePath) << std::endl;
        std::wcout << L"Command Line: " << (proc.commandLine.empty() ? L"[Access Denied / Empty]" : proc.commandLine) << std::endl;
        std::wcout << L"Modules Loaded: " << proc.modules.size() << std::endl;

        // Convert Creation FILETIME to readable format
        if (proc.creationTime.dwLowDateTime != 0 || proc.creationTime.dwHighDateTime != 0) {
            FILETIME localFt;
            SYSTEMTIME st;
            if (FileTimeToLocalFileTime(&proc.creationTime, &localFt) &&
                FileTimeToSystemTime(&localFt, &st)) {
                
                std::wcout << L"Created:      " 
                           << st.wYear << L"-" 
                           << (st.wMonth < 10 ? L"0" : L"") << st.wMonth << L"-"
                           << (st.wDay < 10 ? L"0" : L"") << st.wDay << L" "
                           << (st.wHour < 10 ? L"0" : L"") << st.wHour << L":"
                           << (st.wMinute < 10 ? L"0" : L"") << st.wMinute << L":"
                           << (st.wSecond < 10 ? L"0" : L"") << st.wSecond << std::endl;
            }
        } else {
            std::wcout << L"Created:      [N/A]" << std::endl;
        }
    }
    std::wcout << L"==================================================" << std::endl;
    std::wcout << L"Total Processes Captured: " << processes.size() << std::endl;
}

void ProcessEnumerator::buildProcessTree(std::vector<ProcessNode>& processes) {
    // 1. Loop through every process to find its parent
    for (size_t i = 0; i < processes.size(); ++i) {
        ProcessNode& child = processes[i];

        // 2. We don't need to find a parent for the System Idle Process (PID 0)
        if (child.pid == 0) continue;

        // 3. Loop through the list AGAIN to find the matching parent
        for (size_t j = 0; j < processes.size(); ++j) {
            ProcessNode& potentialParent = processes[j];

            // 4. If we find the parent...
            if (potentialParent.pid == child.ppid) {
                // Add the memory address of the child to the parent's children vector
                potentialParent.children.push_back(&child);
                
                // A process only has one parent, so we can stop searching for this child
                break; 
            }
        }
    }
}

void ProcessEnumerator::displayTree(const std::vector<ProcessNode>& processes) {
    std::wcout << L"\n==================================================" << std::endl;
    std::wcout << L"                SYSTEM PROCESS TREE               " << std::endl;
    std::wcout << L"==================================================" << std::endl;

    // 1. Find the "roots" (Processes whose parents have already exited, or PID 0)
    std::vector<const ProcessNode*> roots;
    for (size_t i = 0; i < processes.size(); ++i) {
        bool hasParentInSnapshot = false;
        
        if (processes[i].pid != 0) { 
            for (size_t j = 0; j < processes.size(); ++j) {
                if (processes[i].ppid == processes[j].pid) {
                    hasParentInSnapshot = true;
                    break;
                }
            }
        }
        
        if (!hasParentInSnapshot) {
            roots.push_back(&processes[i]);
        }
    }

    // 2. Start the recursive printing from each root
    for (size_t i = 0; i < roots.size(); ++i) {
        printNodeRecursive(roots[i], L"", i == (roots.size() - 1));
    }
}


void ProcessEnumerator::printNodeRecursive(const ProcessNode* node, std::wstring indent, bool isLast) {
    // Print the current node's formatting
    std::wcout << indent;
    if (isLast) {
        std::wcout << L"\\-- ";
        indent += L"    ";
    } else {
        std::wcout << L"|-- ";
        indent += L"|   ";
    }

    // Print the process name and PID
    std::wcout << node->imageName << L" (" << node->pid << L")\n";

    // Recursively call this function for every child in the vector
    for (size_t i = 0; i < node->children.size(); ++i) {
        bool isLastChild = (i == (node->children.size() - 1));
        printNodeRecursive(node->children[i], indent, isLastChild);
    }
}



std::vector<ModuleNode> ProcessEnumerator::captureModules(DWORD pid){

    std::vector<ModuleNode> moduleList;
    HANDLE modSnapshotHnd;

    modSnapshotHnd = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        pid
    );

    if(modSnapshotHnd != INVALID_HANDLE_VALUE){
        MODULEENTRY32W moduleEntry;
        moduleEntry.dwSize = sizeof(MODULEENTRY32W);

        if(Module32FirstW(modSnapshotHnd, &moduleEntry)){
            do{

                ModuleNode currentModuleNode;
                currentModuleNode.moduleName = moduleEntry.szModule;
                currentModuleNode.modulePath = moduleEntry.szExePath;
                currentModuleNode.baseAddress = moduleEntry.modBaseAddr;
                currentModuleNode.moduleSize = moduleEntry.modBaseSize;
                currentModuleNode.isSuspicious = false;
                currentModuleNode.anomalyReason = L"-";

                analyzeModule(currentModuleNode);

                moduleList.push_back(currentModuleNode);

            }while(Module32NextW(modSnapshotHnd, &moduleEntry));
        }
        CloseHandle(modSnapshotHnd);
    }else{
        //std::cout << "Modules handle not obtained." << std::endl;
    }

    return moduleList;
}


void ProcessEnumerator::printModulesForProcess(const std::vector<ProcessNode>& processes, const std::wstring& targetProcessName){

    bool found = false;
    
    for (size_t i = 0; i < processes.size(); ++i) {
        if (processes[i].imageName == targetProcessName) {
            found = true;
            std::wcout << L"\n==================================================" << std::endl;
            std::wcout << L" MODULES LOADED IN: " << processes[i].imageName << L" (PID: " << processes[i].pid << L")" << std::endl;
            std::wcout << L"==================================================" << std::endl;
            
            for (size_t j = 0; j < processes[i].modules.size(); ++j) {
                const ModuleNode& mod = processes[i].modules[j];
                
                std::wcout << L"[" << (j + 1) << L"] " << mod.moduleName << std::endl;
                std::wcout << L"    Path: " << mod.modulePath << std::endl;
                std::wcout << L"    Base: " << mod.baseAddress << L" | Size: " << mod.moduleSize << L" bytes\n";
                std::wcout << L"    ----------------------------------------------\n";
                if (mod.isSuspicious) {
                    std::wcout << L"[!] SUSPICIOUS MODULE DETECTED: " << mod.anomalyReason << std::endl;
                }
                
            }
            std::wcout << L"Total Modules: " << processes[i].modules.size() << std::endl;
        }
    }
    
    if (!found) {
        std::wcout << L"\n[!] Process '" << targetProcessName << L"' was not found in the current snapshot." << std::endl;
    }
}

// Helper function to convert a wstring to lowercase for easy searching
std::wstring toLower(const std::wstring& str) {
    std::wstring lowerStr = str;
    for (size_t i = 0; i < lowerStr.length(); ++i) {
        lowerStr[i] = std::towlower(lowerStr[i]);
    }
    return lowerStr;
}

void ProcessEnumerator::analyzeModule(ModuleNode& mod) {
    std::wstring lowerPath = toLower(mod.modulePath);
    std::wstring lowerName = toLower(mod.moduleName);

    // Rule 1: Suspicious User-Writable Paths
    // Check if lowerPath contains L"\\users\\" or L"\\temp\\" or L"\\programdata\\"
    // If true -> set mod.isSuspicious = true, and append to mod.anomalyReason
    LPCWSTR suspiciousKey1 = L"\\users\\";
    LPCWSTR suspiciousKey2 = L"\\temp\\";
    LPCWSTR suspiciousKey3 = L"\\programdata\\";
    LPCWSTR rule1 = L" 1: Suspicious User-Writable Paths. ";

    size_t foundPosition;
    if(((foundPosition = lowerPath.find(suspiciousKey1)) != std::wstring::npos)
        || ((foundPosition = lowerPath.find(suspiciousKey2)) != std::wstring::npos)
        || ((foundPosition = lowerPath.find(suspiciousKey3)) != std::wstring::npos)){

        mod.isSuspicious = true;
        mod.anomalyReason.append(rule1);    
    }
    

    // Rule 2: System DLL Masquerading
    // Check if lowerName is L"ntdll.dll" or L"kernel32.dll"
    // AND the lowerPath does NOT contain L"\\windows\\system32\\" and does NOT contain L"\\windows\\syswow64\\"
    // If true -> set mod.isSuspicious = true, and append to mod.anomalyReason
    LPCWSTR dll1 = L"ntdll.dll";
    LPCWSTR dll2 = L"kernel32.dll";
    LPCWSTR suspicousPath1 = L"\\windows\\system32\\";
    LPCWSTR suspicousPath2 = L"\\windows\\syswow64\\";
    LPCWSTR rule2 = L" 2: System DLL Masquerading ";

    if(lowerName == dll1 || lowerName == dll2){
        if(((foundPosition = lowerPath.find(suspicousPath1)) == std::wstring::npos)
            && ((foundPosition = lowerPath.find(suspicousPath2)) == std::wstring::npos)){
                mod.isSuspicious = true;
                mod.anomalyReason.append(rule2);
            }
    }

    LPCWSTR rule3 = L" 3: Unsigned or Invalid Signature ";
    // Rule 3: Unsigned or Invalid Signature
    // Note: We only check modules that actually have a path (some system modules might be hidden)
    if (!mod.modulePath.empty()) {
        bool isValid = false;

        // 1. TRUE FAST LOOKUP (O(1) Map Lookup by File Path)
        // We check the cache BEFORE we ever touch the hard drive or calculate a hash.
        if (signatureCache.count(mod.modulePath)) {
            isValid = signatureCache[mod.modulePath]; // Cache Hit! Instantaneous.
        } 
        // 2. CACHE MISS (The Bucket is Empty for this file)
        else {
            // We calculate the SHA-256 here (since you noted we are collecting them for telemetry)
            std::wstring fileHash = calculateFileSHA256(mod.modulePath); 
            
            // We do the heavy Cryptographic Signature Verification
            isValid = verifyDigitalSignature(mod.modulePath); 
            
            // Save the result in the cache, mapped to the PATH so we never have to do this again
            signatureCache[mod.modulePath] = isValid; 
        }

        // 4. Flag it if it failed
        if (!isValid) {
            mod.isSuspicious = true;
            mod.anomalyReason.append(rule3);
        }
    }
}


bool ProcessEnumerator::verifyDigitalSignature(const std::wstring& filePath) {
    // 1. Initialize a WINTRUST_FILE_INFO structure.
    // Zero out the memory, set cbStruct to its size, and set pcwszFilePath to your filePath.c_str().

    WINTRUST_FILE_INFO winTrustStruct;
    ZeroMemory(&winTrustStruct, sizeof(WINTRUST_FILE_INFO));
    winTrustStruct.cbStruct = sizeof(WINTRUST_FILE_INFO);
    winTrustStruct.pcwszFilePath = filePath.c_str();


    // 2. Initialize a WINTRUST_DATA structure.
    // Zero out the memory, set cbStruct to its size.
    // Set dwUIChoice to WTD_UI_NONE (we don't want popups!).
    // Set fdwRevocationChecks to WTD_REVOKE_NONE (keep it fast for now).
    // Set dwUnionChoice to WTD_CHOICE_FILE.
    // Set dwStateAction to WTD_STATEACTION_VERIFY.
    // Point pFile to the WINTRUST_FILE_INFO structure you made in Step 1.
    WINTRUST_DATA winTrustDataStruct;
    ZeroMemory(&winTrustDataStruct, sizeof(WINTRUST_DATA));
    winTrustDataStruct.cbStruct = sizeof(WINTRUST_DATA);
    winTrustDataStruct.dwUIChoice = WTD_UI_NONE;
    winTrustDataStruct.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustDataStruct.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustDataStruct.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustDataStruct.pFile = &winTrustStruct;


    // 3. Define the Action GUID.
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    

    // 4. Call WinVerifyTrust.
    LONG status = WinVerifyTrust(NULL, &policyGUID, &winTrustDataStruct);

    // 5. Clean up the state (Crucial to prevent memory leaks in WinVerifyTrust!)
    // Change trustData.dwStateAction to WTD_STATEACTION_CLOSE.
    // Call WinVerifyTrust(NULL, &policyGUID, &trustData) one more time.
    winTrustDataStruct.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &winTrustDataStruct);

    // 6. Evaluate the status.
    // If status == ERROR_SUCCESS (which is 0), the signature is valid.
    // return true if valid, false if not.
    if(status == ERROR_SUCCESS){
        return true;
    }
    return false; 
}


std::wstring ProcessEnumerator::calculateFileSHA256(const std::wstring& filePath) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    
    // Open the file for reading
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return L"";

    // Initialize the Cryptography Provider for SHA-256
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        return L"";
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return L"";
    }

    // Read the file in 8KB chunks and hash it
    BYTE buffer[8192];
    DWORD bytesRead = 0;
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        CryptHashData(hHash, buffer, bytesRead, 0);
    }

    // Extract the final hash value
    BYTE hashBytes[32];
    DWORD hashLen = 32;
    CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashLen, 0);

    // Clean up handles
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    // Convert the raw bytes to a readable Hex String
    wchar_t hexString[65];
    for (int i = 0; i < 32; i++) {
        swprintf(&hexString[i * 2], 3, L"%02x", hashBytes[i]); // the difficult part
    }
    
    return std::wstring(hexString);
}


std::vector<MemoryRegionNode> ProcessEnumerator::captureMemoryRegions(HANDLE hProcess) {
    std::vector<MemoryRegionNode> regions;
    
    // Start scanning from the lowest possible memory address (typically 0)
    PBYTE currentAddress = nullptr;
    MEMORY_BASIC_INFORMATION mbi;
    
    // VirtualQueryEx fills the 'mbi' struct and returns the number of bytes written.
    // If it returns 0, we have reached the end of the process's accessible memory.
    while (VirtualQueryEx(hProcess, currentAddress, &mbi, sizeof(mbi)) != 0) {
        
        // We only care about memory that is actually allocated and in use (MEM_COMMIT)
        if (mbi.State == MEM_COMMIT) {
            MemoryRegionNode regionNode;
            regionNode.baseAddress = mbi.BaseAddress;
            regionNode.regionSize = mbi.RegionSize;
            regionNode.state = mbi.State;
            regionNode.protection = mbi.Protect;
            regionNode.type = mbi.Type;
            
            // --- Simple Process Hollowing / Injection Heuristic ---
            // If memory is Executable and Writable (PAGE_EXECUTE_READWRITE) 
            // AND it is not backed by a legitimate file on disk (MEM_PRIVATE)
            if (mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.Type == MEM_PRIVATE) {
                regionNode.isSuspicious = true;
            } else {
                regionNode.isSuspicious = false;
            }
            
            regions.push_back(regionNode);
        }
        
        // Advance the pointer to the next memory region
        currentAddress = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
    
    return regions;
}


void ProcessEnumerator::printMemoryForProcess(const std::vector<ProcessNode>& processes, const std::wstring& targetProcessName) {
    bool found = false;

    for (size_t i = 0; i < processes.size(); ++i) {
        if (processes[i].imageName == targetProcessName) {
            found = true;
            std::wcout << L"\n==================================================" << std::endl;
            std::wcout << L" MEMORY REGIONS IN: " << processes[i].imageName << L" (PID: " << processes[i].pid << L")" << std::endl;
            std::wcout << L"==================================================" << std::endl;

            size_t suspiciousCount = 0;

            for (size_t j = 0; j < processes[i].memoryRegions.size(); ++j) {
                const MemoryRegionNode& region = processes[i].memoryRegions[j];

                // Translate the Protection constant to a string
                std::wstring protectStr = L"UNKNOWN";
                switch (region.protection & 0xFF) {
                    case PAGE_EXECUTE_READWRITE: protectStr = L"PAGE_EXECUTE_READWRITE (RWX)"; break;
                    case PAGE_EXECUTE_READ:      protectStr = L"PAGE_EXECUTE_READ (RX)"; break;
                    case PAGE_READWRITE:         protectStr = L"PAGE_READWRITE (RW)"; break;
                    case PAGE_READONLY:          protectStr = L"PAGE_READONLY (R)"; break;
                    case PAGE_EXECUTE:           protectStr = L"PAGE_EXECUTE (X)"; break;
                    case PAGE_NOACCESS:          protectStr = L"PAGE_NOACCESS"; break;
                }

                // Translate the Type constant to a string
                std::wstring typeStr = L"UNKNOWN";
                if (region.type == MEM_IMAGE) typeStr = L"MEM_IMAGE (File Backed)";
                else if (region.type == MEM_PRIVATE) typeStr = L"MEM_PRIVATE (Heap/Stack/Alloc)";
                else if (region.type == MEM_MAPPED) typeStr = L"MEM_MAPPED (Memory Mapped File)";

                // Only print highly relevant regions (Executable memory) to avoid terminal flooding
                // A normal process has hundreds of PAGE_READWRITE blocks, we care about code!
                if (region.protection == PAGE_EXECUTE_READWRITE || region.protection == PAGE_EXECUTE_READ) {
                    std::wcout << L"Base: " << region.baseAddress << L" | Size: " << region.regionSize << L" bytes" << std::endl;
                    std::wcout << L"    Protect: " << protectStr << std::endl;
                    std::wcout << L"    Type:    " << typeStr << std::endl;

                    if (region.isSuspicious) {
                        suspiciousCount++;
                        std::wcout << L"    [!] SUSPICIOUS: Executable memory not backed by a verified file!" << std::endl;
                    }
                    std::wcout << L"    ----------------------------------------------\n";
                }
            }
            std::wcout << L"Total Executable Regions Scanned: " << processes[i].memoryRegions.size() << std::endl;
            std::wcout << L"Total Suspicious Regions: " << suspiciousCount << std::endl;
        }
    }

    if (!found) {
        std::wcout << L"\n[!] Process '" << targetProcessName << L"' was not found in the current snapshot." << std::endl;
    }
}



void ProcessEnumerator::ApplyEtwEvent(DWORD pid, const std::wstring& imagePath, bool isStart) {
    std::lock_guard<std::mutex> lock(m_Lock);

    if (isStart) {
        ProcessNode newNode;
        newNode.pid = pid;
        newNode.imageName = imagePath; 
        newNode.state = ProcessState::Running;
        
        GetSystemTimeAsFileTime(&newNode.creationTime);
        enrichProcessNode(newNode); 
        
        m_ActiveSnapshot.push_back(newNode);
        
        // Prevent Pointer Invalidations by clearing and rebuilding the tree
        for (auto& p : m_ActiveSnapshot) p.children.clear();
        buildProcessTree(m_ActiveSnapshot);
    } else {
        // The Tombstone Pattern: Mark as dead, do not delete memory
        for (auto& proc : m_ActiveSnapshot) {
            if (proc.pid == pid && proc.state == ProcessState::Running) {
                proc.state = ProcessState::Terminated;
                GetSystemTimeAsFileTime(&proc.exitTime);
                break;
            }
        }
    }
}

void ProcessEnumerator::InitializeBaseline() {
    // 1. Capture the baseline WITHOUT locking the mutex. 
    // This allows ETW to continue receiving real-time events while we do the heavy 15-second hashing.
    std::vector<ProcessNode> snap;
    int retries = 0;
    
    // Retry loop to overcome ERROR_BAD_LENGTH from CreateToolhelp32Snapshot
    // which occurs frequently when called from a LOWEST priority thread.
    while (snap.empty() && retries < 10) {
        snap = captureSnapshot();
        if (snap.empty()) {
            Sleep(100); 
            retries++;
        }
    }

    // 2. Heavy lifting is done. Now we lock the memory state manager.
    std::lock_guard<std::mutex> lock(m_Lock);
    
    if (!snap.empty()) {
        
        // Mark all baseline processes as Running
        for (auto& p : snap) {
            p.state = ProcessState::Running;
            p.children.clear();
        }

        // 3. The Merge Phase: ETW might have caught new processes (like Client.exe) 
        // while we were hashing. We append those real-time events to our baseline snapshot.
        for (const auto& liveProc : m_ActiveSnapshot) {
            snap.push_back(liveProc);
        }
        
        // 4. Safely overwrite the internal state and rebuild the pointer tree
        m_ActiveSnapshot = snap;
        m_ActiveSnapshot.reserve(5000); 
        
        for (auto& p : m_ActiveSnapshot) {
            p.children.clear(); // Ensure clean slate for pointers
        }
        buildProcessTree(m_ActiveSnapshot);
    }
}

std::vector<ProcessNode> ProcessEnumerator::GetSafeSnapshotCopy() {
    std::lock_guard<std::mutex> lock(m_Lock);
    return m_ActiveSnapshot; 
}