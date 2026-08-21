#include <windows.h>
#include <iostream>
#include <string>

/*
compile instruction for this separate client only - 
x86_64-w64-mingw32-g++ -std=c++17 -Wall -Wextra -static Client.cpp -o Client.exe -municode


*/

int wmain(int argc, wchar_t *argv[]) {
    // The exact same pipe name the Service is listening on
    LPCWSTR pipeName = L"\\\\.\\pipe\\ThreatDetectionPipe";
    
    std::wcout << L"[*] Attempting to connect to Threat Engine in Session 0..." << std::endl;

    // 1. Open a connection to the Named Pipe
    // We treat the pipe exactly like opening a file on a hard drive (CreateFileW)
    HANDLE hPipe = CreateFileW(
        pipeName,
        GENERIC_READ | GENERIC_WRITE, // We need to send commands AND read responses
        0,                            // No sharing
        NULL,                         // Default security attributes
        OPEN_EXISTING,                // The pipe MUST already be created by the Service
        0,                            // Default attributes
        NULL                          // No template file
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] Failed to connect. Error: " << GetLastError() << std::endl;
        std::wcout << L"[-] Is the ThreatDetectionEngine Service actually running?" << std::endl;
        return 1;
    }

    std::wcout << L"[+] Connected to Engine!\n" << std::endl;

    // 2. Prepare the command to send
    std::wstring command = L"SCAN_MEMORY";
    
    // If the user passed an argument (e.g., Client.exe SUSPEND_PROCESS), use that instead
    if (argc > 1) {
        command = argv[1];
    }

    std::wcout << L"[*] Sending command: " << command << std::endl;

    // 3. Write the command to the pipe
    DWORD bytesWritten = 0;
    BOOL writeSuccess = WriteFile(
        hPipe, 
        command.c_str(), 
        command.length() * sizeof(wchar_t), // Number of BYTES, not characters
        &bytesWritten, 
        NULL
    );

    if (writeSuccess) {
        // 4. Wait for and read the response from the Service
        wchar_t buffer[512] = {0}; // Initialize with zeros
        DWORD bytesRead = 0;
        
        // ReadFile will block (wait) here until the Service writes something back
        BOOL readSuccess = ReadFile(
            hPipe, 
            buffer, 
            sizeof(buffer) - sizeof(wchar_t), // Leave room for the null terminator
            &bytesRead, 
            NULL
        );

        if (readSuccess) {
            std::wcout << L"[+] Response from Engine: " << buffer << std::endl;
        } else {
            std::wcout << L"[-] Failed to read response. Error: " << GetLastError() << std::endl;
        }
    } else {
        std::wcout << L"[-] Failed to send command. Error: " << GetLastError() << std::endl;
    }

    // 5. Close the connection
    CloseHandle(hPipe);
    return 0;
}