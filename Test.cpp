







#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <vector>

static DWORD FindChildProcessWithDll(const wchar_t* processName, const wchar_t* dllName) {
    DWORD targetPid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, processName) == 0) {
                    HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe.th32ProcessID);
                    if (hModSnap != INVALID_HANDLE_VALUE) {
                        MODULEENTRY32W me;
                        me.dwSize = sizeof(me);
                        if (Module32FirstW(hModSnap, &me)) {
                            do {
                                if (_wcsicmp(me.szModule, dllName) == 0) {
                                    targetPid = pe.th32ProcessID;
                                    break;
                                }
                            } while (Module32NextW(hModSnap, &me));
                        }
                        CloseHandle(hModSnap);
                    }
                    if (targetPid != 0) {
                        break;
                    }
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return targetPid;
}

static DWORD FindProcessId(const wchar_t* processName) {
    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, processName) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return pid;
}

static uintptr_t FindExecutableModuleBase(DWORD pid) {
    uintptr_t base = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me;
        me.dwSize = sizeof(me);
        if (Module32FirstW(hSnap, &me)) {
            base = (uintptr_t)me.modBaseAddr;
        }
        CloseHandle(hSnap);
    }
    return base;
}

static bool FindModuleTextSectionRemote(HANDLE hProcess, uintptr_t modBase, uintptr_t* outTextAddr, size_t* outTextSize) {
    IMAGE_DOS_HEADER dos;
    SIZE_T readBytes = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)modBase, &dos, sizeof(dos), &readBytes) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    IMAGE_NT_HEADERS nt;
    if (!ReadProcessMemory(hProcess, (LPCVOID)(modBase + dos.e_lfanew), &nt, sizeof(nt), &readBytes) || nt.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    uintptr_t firstSec = modBase + dos.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt.FileHeader.SizeOfOptionalHeader;
    for (WORD i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sec;
        if (ReadProcessMemory(hProcess, (LPCVOID)(firstSec + i * sizeof(IMAGE_SECTION_HEADER)), &sec, sizeof(sec), &readBytes)) {
            if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sec.Characteristics & IMAGE_SCN_CNT_CODE)) {
                *outTextAddr = modBase + sec.VirtualAddress;
                *outTextSize = sec.Misc.VirtualSize;
                return true;
            }
        }
    }
    return false;
}

static DWORD GetProtectedPid() {
    DWORD pid = FindChildProcessWithDll(L"fuftianticheat.exe", L"fuftianticheat.dll");
    if (pid == 0) {
        pid = FindProcessId(L"fuftianticheat.exe");
    }
    return pid;
}

static void ActionModifyRam() {
    std::cout << "\n==============================================" << std::endl;
    std::cout << "[1] Modifying Protected RAM..." << std::endl;
    std::cout << "==============================================" << std::endl;

    DWORD pid = GetProtectedPid();
    if (pid == 0) {
        std::cout << "[ERROR] fuftianticheat.exe is NOT running!" << std::endl;
        std::cout << "Please start fuftianticheat.exe first." << std::endl;
        return;
    }

    std::cout << "[+] Found Target Process PID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "[-] Failed to open process. Access Denied (Protected)!" << std::endl;
        return;
    }

    uintptr_t baseAddr = FindExecutableModuleBase(pid);
    uintptr_t textAddr = 0;
    size_t textSize = 0;
    if (!FindModuleTextSectionRemote(hProcess, baseAddr, &textAddr, &textSize)) {
        textAddr = baseAddr + 0x1000;
        textSize = 4096;
    }

    std::cout << "[+] Code section (.text) located at: 0x" << std::hex << textAddr
              << " (Size: 0x" << textSize << " bytes)" << std::dec << std::endl;

    LPVOID targetMemoryAddr = (LPVOID)textAddr;

    DWORD oldProtect = 0;
    std::cout << "[+] Step 1: Modifying memory page protection to PAGE_EXECUTE_READWRITE..." << std::endl;
    BOOL protectChanged = VirtualProtectEx(hProcess, targetMemoryAddr, 64, PAGE_EXECUTE_READWRITE, &oldProtect);

    if (protectChanged) {
        std::cout << "[+] Protection changed! Old: 0x" << std::hex << oldProtect << " -> New: 0x40 (RWX)" << std::dec << std::endl;
    } else {
        std::cout << "[-] VirtualProtectEx failed. Error: " << GetLastError() << std::endl;
    }

    unsigned char nopPatch[8] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    SIZE_T bytesWritten = 0;
    std::cout << "[+] Step 2: Writing 8 NOP bytes (0x90) into memory..." << std::endl;
    BOOL wrote = WriteProcessMemory(hProcess, targetMemoryAddr, nopPatch, sizeof(nopPatch), &bytesWritten);

    if (wrote) {
        std::cout << "[+] Successfully wrote " << bytesWritten << " bytes to RAM address: 0x"
                  << std::hex << (uintptr_t)targetMemoryAddr << std::dec << std::endl;
    } else {
        std::cout << "[-] WriteProcessMemory failed. Error: " << GetLastError() << std::endl;
    }

    std::cout << "[+] Step 3: Observing Anti-Cheat reaction..." << std::endl;
    Sleep(600);

    DWORD exitCode = 0;
    GetExitCodeProcess(hProcess, &exitCode);
    if (exitCode == STILL_ACTIVE) {
        Sleep(600);
        GetExitCodeProcess(hProcess, &exitCode);
    }

    if (exitCode != STILL_ACTIVE) {
        std::cout << "\n[SUCCESS] Anti-Cheat DETECTED RAM tampering and CRASHED the process!" << std::endl;
        std::cout << "[SUCCESS] Target process Exit Code: 0x" << std::hex << exitCode << std::dec << std::endl;
    } else {
        std::cout << "[-] Process is still running." << std::endl;
    }

    CloseHandle(hProcess);
}

static void ActionReadRam() {
    std::cout << "\n==============================================" << std::endl;
    std::cout << "[2] Reading Protected RAM..." << std::endl;
    std::cout << "==============================================" << std::endl;

    DWORD pid = GetProtectedPid();
    if (pid == 0) {
        std::cout << "[ERROR] fuftianticheat.exe is NOT running!" << std::endl;
        std::cout << "Please start fuftianticheat.exe first." << std::endl;
        return;
    }

    std::cout << "[+] Found Target Process PID: " << pid << std::endl;

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cout << "[-] Failed to open process for reading. Access Denied!" << std::endl;
        return;
    }

    uintptr_t baseAddr = FindExecutableModuleBase(pid);
    uintptr_t textAddr = 0;
    size_t textSize = 0;
    if (!FindModuleTextSectionRemote(hProcess, baseAddr, &textAddr, &textSize)) {
        textAddr = baseAddr + 0x1000;
        textSize = 4096;
    }

    std::cout << "[+] Base Address: 0x" << std::hex << baseAddr << std::dec << std::endl;
    std::cout << "[+] Code section (.text) address: 0x" << std::hex << textAddr << std::dec << std::endl;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, (LPCVOID)textAddr, &mbi, sizeof(mbi))) {
        std::cout << "[+] Page State: 0x" << std::hex << mbi.State
                  << " | Protect: 0x" << mbi.Protect
                  << " | Type: 0x" << mbi.Type << std::dec << std::endl;
    }

    const size_t bytesToRead = 64;
    std::vector<unsigned char> memBuffer(bytesToRead, 0);
    SIZE_T bytesRead = 0;

    std::cout << "[+] Reading first " << bytesToRead << " bytes from RAM at 0x"
              << std::hex << textAddr << std::dec << "...\n" << std::endl;

    if (ReadProcessMemory(hProcess, (LPCVOID)textAddr, memBuffer.data(), bytesToRead, &bytesRead)) {
        std::cout << "--- Memory Hex Dump (" << bytesRead << " bytes) ---" << std::endl;
        for (size_t i = 0; i < bytesRead; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)memBuffer[i] << " ";
            if ((i + 1) % 16 == 0) {
                std::cout << " | ";
                for (size_t j = i - 15; j <= i; ++j) {
                    char c = (memBuffer[j] >= 32 && memBuffer[j] <= 126) ? (char)memBuffer[j] : '.';
                    std::cout << c;
                }
                std::cout << std::endl;
            }
        }
        std::cout << std::dec << std::endl;
        std::cout << "[+] Memory read successfully." << std::endl;
    } else {
        std::cout << "[-] ReadProcessMemory failed. Error: " << GetLastError() << std::endl;
    }

    CloseHandle(hProcess);
}

static void ActionGenerateFakeDll() {
    std::cout << "\n==============================================" << std::endl;
    std::cout << "[3] Generating Fake DLL & Testing Integrity..." << std::endl;
    std::cout << "==============================================" << std::endl;

    std::wstring origDll = L"fuftianticheat.dll";
    std::wstring backupDll = L"fuftianticheat_backup.dll";

    std::cout << "[+] Backing up original fuftianticheat.dll to fuftianticheat_backup.dll..." << std::endl;
    if (!CopyFileW(origDll.c_str(), backupDll.c_str(), FALSE)) {
        std::cout << "[-] Warning: Failed to backup original DLL or it was not found!" << std::endl;
    }

    std::ifstream srcFile("fuftianticheat_backup.dll", std::ios::binary);
    std::vector<char> buffer((std::istreambuf_iterator<char>(srcFile)), std::istreambuf_iterator<char>());
    srcFile.close();

    if (buffer.size() > 1024) {
        buffer[buffer.size() - 256] ^= 0x55;
        buffer[buffer.size() - 255] ^= 0xAA;
    }

    std::cout << "[+] Writing valid PE file with modified SHA-256 to fuftianticheat.dll..." << std::endl;
    std::ofstream fakeFile("fuftianticheat.dll", std::ios::binary | std::ios::trunc);
    fakeFile.write(buffer.data(), buffer.size());
    fakeFile.close();

    std::cout << "[+] Fake DLL generated successfully!" << std::endl;
    std::cout << "[+] Running fuftianticheat.exe to verify integrity check...\n" << std::endl;

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    BOOL launched = CreateProcessA(
        "fuftianticheat.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (launched) {
        WaitForSingleObject(pi.hProcess, 3000);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        std::cout << "\n[+] fuftianticheat.exe exited with code: " << exitCode << std::endl;
        if (exitCode != 0) {
            std::cout << "[SUCCESS] FuftiAntiCheat detected fake DLL and blocked launch!" << std::endl;
        } else {
            std::cout << "[-] Fake DLL was not blocked." << std::endl;
        }
    } else {
        std::cout << "[-] Failed to launch fuftianticheat.exe. Error: " << GetLastError() << std::endl;
    }

    std::cout << "\n[+] Restoring original fuftianticheat.dll from backup..." << std::endl;
    CopyFileW(backupDll.c_str(), origDll.c_str(), FALSE);
    DeleteFileW(backupDll.c_str());
    std::cout << "[+] Original DLL restored." << std::endl;
}

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "1" || arg == "--ram-tamper") {
            ActionModifyRam();
            return 0;
        } else if (arg == "2" || arg == "--read-ram") {
            ActionReadRam();
            return 0;
        } else if (arg == "3" || arg == "--fake-dll") {
            ActionGenerateFakeDll();
            return 0;
        }
    }

    while (true) {
        std::cout << "\n==============================================" << std::endl;
        std::cout << "       FuftiAntiCheat Test Menu               " << std::endl;
        std::cout << "==============================================" << std::endl;
        std::cout << "1. Изменить оперативку (Modify RAM)" << std::endl;
        std::cout << "2. Вывести что там происходит (читать RAM)" << std::endl;
        std::cout << "3. Сгенерировать фейк дллку (Fake DLL)" << std::endl;
        std::cout << "0. Выход (Exit)" << std::endl;
        std::cout << "----------------------------------------------" << std::endl;
        std::cout << "Выберите действие [0-3]: ";

        int choice = -1;
        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::string ignore;
            std::cin >> ignore;
            continue;
        }

        if (choice == 1) {
            ActionModifyRam();
        } else if (choice == 2) {
            ActionReadRam();
        } else if (choice == 3) {
            ActionGenerateFakeDll();
        } else if (choice == 0) {
            std::cout << "Exiting." << std::endl;
            break;
        } else {
            std::cout << "Invalid choice. Try again." << std::endl;
        }
    }

    return 0;
}
