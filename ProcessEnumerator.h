#include <vector>
#include <windows.h>
#include <tlhelp32.h>
#include "ProcessNode.h"
#include <wintrust.h> // NEW: For WinVerifyTrust
#include <softpub.h>  // NEW: For WINTRUST_ACTION_GENERIC_VERIFY_V2
#include <unordered_map> // NEW: For our RAM Cache
#include <wincrypt.h>    // NEW: For SHA-256 Hashing
#include <mutex> // Add to top of file


class ProcessEnumerator{

    public:

    
        std::vector<ProcessNode> captureSnapshot();
        void enrichProcessNode(ProcessNode& node);
        void printProcessDetails(const std::vector<ProcessNode>& processes);
        void displayTree(const std::vector<ProcessNode>& processes);
        void buildProcessTree(std::vector<ProcessNode>& processes);
        std::vector<ModuleNode> captureModules(DWORD pid);
        void printModulesForProcess(const std::vector<ProcessNode>& processes, const std::wstring& targetProcessName);
        std::vector<MemoryRegionNode> captureMemoryRegions(HANDLE hProcess);
        void printMemoryForProcess(const std::vector<ProcessNode>& processes, const std::wstring& targetProcessName);
        // The ETW Bridge (Setter)
        void ApplyEtwEvent(DWORD pid, const std::wstring& imagePath, bool isStart);
        
        // The Bootstrapper Helper
        void InitializeBaseline();

        // The Pipe Helper (Getter)
        std::vector<ProcessNode> GetSafeSnapshotCopy();
        
    private:

        std::mutex m_Lock;
        std::vector<ProcessNode> m_ActiveSnapshot;

        // --- NEW: The RAM Cache ---
        // Maps a SHA-256 hash string to a boolean (true = signed, false = unsigned)
        std::unordered_map<std::wstring, bool> signatureCache;
        std::wstring getCommandLine(HANDLE hProcess);        
        void printNodeRecursive(const ProcessNode* node, std::wstring indent, bool isLast);
        // Add this new helper
        void analyzeModule(ModuleNode& mod);
        // NEW: Digital signature verifier
        bool verifyDigitalSignature(const std::wstring& filePath);
        // --- NEW: The Hashing Engine ---
        std::wstring calculateFileSHA256(const std::wstring& filePath);


};