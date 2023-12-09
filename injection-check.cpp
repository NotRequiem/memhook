#include <iostream>
#include <Windows.h>
#include "D:\MinHook.h"  // Change header path here
#include <TlHelp32.h>
#include <Psapi.h>
#include <thread>
#include <string>
#include <Tchar.h>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "D:\\libMinHook.x64.lib") // Change library path here

// typedef DWORD(WINAPI* OriginalGetProcessImageFileName_t)(HANDLE, LPWSTR, DWORD);  hooking this is useless, was just for testing
typedef LPVOID(WINAPI* OriginalVirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
typedef LPVOID(WINAPI* OriginalVirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* OriginalWriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* OriginalCreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HHOOK(WINAPI* OriginalSetWindowsHookExA_t)(int, HOOKPROC, HINSTANCE, DWORD);
typedef HHOOK(WINAPI* OriginalSetWindowsHookExW_t)(int, HOOKPROC, HINSTANCE, DWORD);
typedef HANDLE(WINAPI* OriginalCreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE(WINAPI* OriginalOpenThread_t)(DWORD, BOOL, DWORD);
typedef HMODULE(WINAPI* OriginalLoadLibraryA_t)(const char*);
typedef HMODULE(WINAPI* OriginalLoadLibraryW_t)(const wchar_t*);
typedef HANDLE(WINAPI* OriginalOpenProcess_t)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

// OriginalGetProcessImageFileName_t originalGetProcessImageFileName = nullptr;
OriginalVirtualAlloc_t originalVirtualAlloc = nullptr;
OriginalVirtualAllocEx_t originalVirtualAllocEx = nullptr;
OriginalWriteProcessMemory_t originalWriteProcessMemory = nullptr;
OriginalCreateRemoteThread_t originalCreateRemoteThread = nullptr;
OriginalSetWindowsHookExA_t originalSetWindowsHookExA = nullptr;
OriginalSetWindowsHookExW_t originalSetWindowsHookExW = nullptr;
OriginalCreateThread_t originalCreateThread = nullptr;
OriginalOpenThread_t originalOpenThread = nullptr;
OriginalLoadLibraryA_t originalLoadLibraryA = nullptr;
OriginalLoadLibraryW_t originalLoadLibraryW = nullptr;
OriginalOpenProcess_t originalOpenProcess = nullptr;

DWORD targetPID = 0;

static void CheckMHResult(MH_STATUS status, const std::string& functionName) {
    if (status != MH_OK) {
        std::cerr << "MinHook error in " << functionName << ": " << MH_StatusToString(status) << std::endl;
        exit(1);
    }
}

static void PrintSourceProcess() {
    DWORD processId = GetCurrentProcessId();
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId); // here u just need QUERY_INFORMATION or QUERY_LIMITED_INFORMATION
    if (hProcess) {
        TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR)); // u can use GetProcessImageFileName or GetModuleFileNameEx, or Toolhelp32Snapshot API
        }

        _tprintf(TEXT("Hooking to: ProcessID=%u from: ImageFileName=%s\n"), processId, szProcessName);

        CloseHandle(hProcess);
    }
}

/* useless
static DWORD WINAPI HookedGetProcessImageFileName(HANDLE hProcess, LPWSTR lpImageFileName, DWORD nSize) {
    DWORD result = originalGetProcessImageFileName(hProcess, lpImageFileName, nSize);

    return result;
}
*/

// we can just do return address checking after hooking a bunch of libraries, or retrieve more information

static LPVOID WINAPI HookedVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    LPVOID result = originalVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);

    std::cout << "HookedVirtualAlloc: Address=" << result
        << " Size=" << std::dec << dwSize
        << " AllocationType=" << std::hex << flAllocationType
        << " Protection=" << std::hex << flProtect
        << std::endl;

    return result;
}

static LPVOID WINAPI HookedVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    LPVOID result = originalVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);

    std::cout << "HookedVirtualAllocEx: Address=" << result
        << " Size=" << std::dec << dwSize
        << " AllocationType=" << std::hex << flAllocationType
        << " Protection=" << std::hex << flProtect
        << std::endl;

    return result;
}

static BOOL WINAPI HookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    BOOL result;

    try {
        if (lpNumberOfBytesWritten == nullptr) {
            std::cerr << "HookedWriteProcessMemory: lpNumberOfBytesWritten is nullptr." << std::endl; // If you dont acheck for lpNumberOfBytesWritten being null ur program will crash
            return FALSE;  
        }

        result = originalWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

        std::cout << "HookedWriteProcessMemory: Address=" << lpBaseAddress
            << " Size=" << std::dec << nSize
            << " BytesWritten=" << std::dec << *lpNumberOfBytesWritten
            << std::endl;

        // Optionally, log the actual data being written
        if (nSize > 0) {
            std::stringstream hexData;
            hexData << std::hex << std::setfill('0');
            for (size_t i = 0; i < nSize; ++i) {
                hexData << std::setw(2) << static_cast<int>(reinterpret_cast<const unsigned char*>(lpBuffer)[i]) << " ";
            }
            std::cout << "  Data: " << hexData.str() << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Exception in HookedWriteProcessMemory: " << e.what() << std::endl;
        result = FALSE;
    }

    return result;
}

static HANDLE WINAPI HookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    HANDLE result = originalCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

    std::cout << "HookedCreateRemoteThread: Address=" << lpStartAddress
        << " ProcessHandle=" << hProcess
        << " ThreadId=" << (lpThreadId ? *lpThreadId : 0)
        << std::endl;

    return result;
}

static HHOOK WINAPI HookedSetWindowsHookExA(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId) {
    HHOOK result = originalSetWindowsHookExA(idHook, lpfn, hmod, dwThreadId);

    std::cout << "HookedSetWindowsHookExA: Address=" << lpfn
        << " IdHook=" << idHook
        << " ModuleHandle=" << hmod
        << " ThreadId=" << dwThreadId
        << std::endl;

    return result;
}

static HHOOK WINAPI HookedSetWindowsHookExW(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId) {
    HHOOK result = originalSetWindowsHookExW(idHook, lpfn, hmod, dwThreadId);

    std::cout << "HookedSetWindowsHookExW: Address=" << lpfn
        << " IdHook=" << idHook
        << " ModuleHandle=" << hmod
        << " ThreadId=" << dwThreadId
        << std::endl;

    return result;
}

static HANDLE WINAPI HookedCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
    HANDLE result = originalCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);

    std::cout << "HookedCreateThread: Address=" << lpStartAddress
        << " ThreadId=" << (lpThreadId ? *lpThreadId : 0)
        << std::endl;

    return result;
}

static HANDLE WINAPI HookedOpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId) {
    HANDLE result = originalOpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);

    std::cout << "HookedOpenThread: Address=" << result
        << " DesiredAccess=" << std::hex << dwDesiredAccess
        << " InheritHandle=" << bInheritHandle
        << " ThreadId=" << dwThreadId
        << std::endl;

    return result;
}

static HMODULE WINAPI HookedLoadLibraryA(const char* lpLibFileName) {
    HMODULE result = originalLoadLibraryA(lpLibFileName);

    std::cout << "HookedLoadLibraryA: Address=" << result
        << " LibraryName=" << lpLibFileName
        << std::endl;

    return result;
}

static HMODULE WINAPI HookedLoadLibraryW(const wchar_t* lpLibFileName) {
    HMODULE result = originalLoadLibraryW(lpLibFileName);

    std::wcout << L"HookedLoadLibraryW: Address=" << result
        << " LibraryName=" << lpLibFileName
        << std::endl;

    return result;
}

static HANDLE WINAPI HookedOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
    HANDLE result = originalOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);

    std::cout << "HookedOpenProcess: ProcessID=" << dwProcessId
        << " DesiredAccess=" << std::hex << dwDesiredAccess
        << " InheritHandle=" << bInheritHandle
        << std::endl;

    return result;
}

static DWORD FindProcessId(const wchar_t* processName) {
    DWORD processId = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                if (_wcsicmp(processEntry.szExeFile, processName) == 0) {
                    processId = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &processEntry));
        }

        CloseHandle(snapshot);
    }

    return processId;
}

static DWORD FindProcessIdRetry(const wchar_t* processName, int retryIntervalSeconds) {
    DWORD processId = 0;

    while (true) {
        processId = FindProcessId(processName);
        if (processId != 0) {
            return processId;
        }

        std::wcerr << L"Unable to find the '" << processName << L"' process. Retrying in " << retryIntervalSeconds << L" second(s)..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(retryIntervalSeconds));
    }
}

static void InjectCode(HANDLE hProcess) {
    LPVOID addressToHookVirtualAlloc = reinterpret_cast<LPVOID>(originalVirtualAlloc);
    LPVOID addressToHookVirtualAllocEx = reinterpret_cast<LPVOID>(originalVirtualAllocEx);
    LPVOID addressToHookWriteProcessMemory = reinterpret_cast<LPVOID>(originalWriteProcessMemory);
    LPVOID addressToHookCreateRemoteThread = reinterpret_cast<LPVOID>(originalCreateRemoteThread);
    LPVOID addressToHookSetWindowsHookExA = reinterpret_cast<LPVOID>(originalSetWindowsHookExA);
    LPVOID addressToHookSetWindowsHookExW = reinterpret_cast<LPVOID>(originalSetWindowsHookExW);
    LPVOID addressToHookLoadLibraryW = reinterpret_cast<LPVOID>(originalLoadLibraryW);
    LPVOID addressToHookLoadLibraryA = reinterpret_cast<LPVOID>(originalLoadLibraryA);
    LPVOID addressToHookCreateThread = reinterpret_cast<LPVOID>(originalCreateThread);
    LPVOID addressToHookOpenThread = reinterpret_cast<LPVOID>(originalOpenThread);
    // LPVOID addressToHookGetProcessImageFileName = reinterpret_cast<LPVOID>(originalGetProcessImageFileName);

    LPVOID hookedFunctionAddresses[] = {
        addressToHookVirtualAlloc,
        addressToHookVirtualAllocEx,
        addressToHookWriteProcessMemory,
        addressToHookCreateRemoteThread,
        addressToHookSetWindowsHookExA,
        addressToHookSetWindowsHookExW,
        addressToHookLoadLibraryW,
        addressToHookLoadLibraryA,
        addressToHookCreateThread,
        addressToHookOpenThread
    };

    for (int i = 0; i < sizeof(hookedFunctionAddresses) / sizeof(hookedFunctionAddresses[0]); i++) {
        LPVOID addressToHook = hookedFunctionAddresses[i];

        BYTE hookCode[] = {
            0x48, 0x83, 0xEC, 0x28,                         // Sub rsp, 0x28
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Mov rax, &HookedFunction
            0xFF, 0xE0,                                   // Jmp rax
            0x48, 0x83, 0xC4, 0x28,                         // Add rsp, 0x28
            0xC3                                          // Ret
        };

        // memcpy(hookCode + 7, &addressToHookGetProcessImageFileName, sizeof(LPVOID));
        memcpy(hookCode + 7, &addressToHook, sizeof(LPVOID));

        LPVOID remoteBuffer = VirtualAllocEx(hProcess, nullptr, sizeof(hookCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (remoteBuffer == nullptr) {
            std::cerr << "Failed to allocate memory in the target process" << std::endl;
            CloseHandle(hProcess);
            MH_Uninitialize();
            exit(1);
        }

        if (!WriteProcessMemory(hProcess, remoteBuffer, hookCode, sizeof(hookCode), nullptr)) {
            std::cerr << "Failed to write code to the target process" << std::endl;
            VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            MH_Uninitialize();
            exit(1);
        }

        HANDLE hRemoteThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteBuffer), nullptr, 0, nullptr);

        if (hRemoteThread == nullptr) {
            std::cerr << "Failed to create a remote thread in the target process" << std::endl;
            VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            MH_Uninitialize();
            exit(1);
        }

        if (WaitForSingleObject(hRemoteThread, INFINITE) != WAIT_OBJECT_0) {
            std::cerr << "Failed to wait for the remote thread" << std::endl;
            CloseHandle(hRemoteThread);
            VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            MH_Uninitialize();
            exit(1);
        }

        CloseHandle(hRemoteThread);
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    }

    CloseHandle(hProcess);
}

int main() {
    if (MH_Initialize() != MH_OK) {
        std::cerr << "MinHook initialization failed." << std::endl;
        return 1;
    }

    PrintSourceProcess();

    HANDLE hProcess = nullptr;

    while (true) {
        targetPID = FindProcessIdRetry(L"javaw.exe", 1);
        std::wcout << L"Hooking 'javaw.exe' (PID: " << targetPID << L")..." << std::endl;

        if (targetPID == 0) {
            std::wcerr << L"Failed to find the 'javaw.exe' process. Retrying in 1 second..." << std::endl;
        }
        else {
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID); // should not require debug privileges or any other token modification in our process to open it
            if (hProcess == nullptr) {
                std::wcerr << L"Failed to open 'javaw.exe' process. Exiting." << std::endl;
                break;
            }

            // Load the 64-bit versions of the functions from kernel32.dll
            HMODULE kernel32Module = GetModuleHandle(L"kernel32.dll");
            if (kernel32Module == nullptr) {
                DWORD error = GetLastError();
                std::cerr << "Failed to get handle for kernel32.dll. Error code: " << error << std::endl;
                CloseHandle(hProcess);
                MH_Uninitialize();
                return 1;
            }

            HMODULE user32Module = LoadLibrary(L"C:\\Windows\\System32\\user32.dll");
            if (user32Module == nullptr) {
                DWORD error = GetLastError();
                std::cerr << "Failed to get handle for user32.dll. Error code: " << error << std::endl;
                CloseHandle(hProcess);
                MH_Uninitialize();
                return 1;
            }

            // Load the 64-bit version of the OpenProcess function from kernel32.dll 

            if (kernel32Module != nullptr) { // just to avoid warnings
                originalVirtualAlloc = reinterpret_cast<OriginalVirtualAlloc_t>(GetProcAddress(kernel32Module, "VirtualAlloc"));
                originalVirtualAllocEx = reinterpret_cast<OriginalVirtualAllocEx_t>(GetProcAddress(kernel32Module, "VirtualAllocEx"));
                originalWriteProcessMemory = reinterpret_cast<OriginalWriteProcessMemory_t>(GetProcAddress(kernel32Module, "WriteProcessMemory"));
                originalCreateRemoteThread = reinterpret_cast<OriginalCreateRemoteThread_t>(GetProcAddress(kernel32Module, "CreateRemoteThread"));
                originalCreateThread = reinterpret_cast<OriginalCreateThread_t>(GetProcAddress(kernel32Module, "CreateThread"));
                originalOpenThread = reinterpret_cast<OriginalOpenThread_t>(GetProcAddress(kernel32Module, "OpenThread"));
                originalLoadLibraryA = reinterpret_cast<OriginalLoadLibraryA_t>(GetProcAddress(kernel32Module, "LoadLibraryA"));
                originalLoadLibraryW = reinterpret_cast<OriginalLoadLibraryW_t>(GetProcAddress(kernel32Module, "LoadLibraryW"));
            }

            if (user32Module != nullptr) { // just to avoid warnings
                originalSetWindowsHookExA = reinterpret_cast<OriginalSetWindowsHookExA_t>(GetProcAddress(user32Module, "SetWindowsHookExA"));
                originalSetWindowsHookExW = reinterpret_cast<OriginalSetWindowsHookExW_t>(GetProcAddress(user32Module, "SetWindowsHookExW"));
            }

            /* OpenProcess is the most important function to be hooked for external cheats
             originalOpenProcess = reinterpret_cast<OriginalOpenProcess_t>(GetProcAddress(kernel32Module, "OpenProcess"));

             if (originalOpenProcess == nullptr) {
                DWORD error = GetLastError();
                std::cerr << "Failed to get function address for OpenProcess. Error code: " << error << std::endl;
                CloseHandle(hProcess);
                MH_Uninitialize();
                return 1;
            }

            // Create a hook for OpenProcess
            MH_STATUS openProcessHookStatus = MH_CreateHookApi(L"kernel32.dll", "OpenProcess", &HookedOpenProcess, reinterpret_cast<LPVOID*>(&originalOpenProcess));
            CheckMHResult(openProcessHookStatus, "OpenProcess");

            // Enable the hook for OpenProcess
            MH_STATUS enableOpenProcessHookStatus = MH_EnableHook(MH_ALL_HOOKS);
            CheckMHResult(enableOpenProcessHookStatus, "Enable OpenProcess Hook");
            */

            if (originalVirtualAlloc == nullptr || originalVirtualAllocEx == nullptr || originalWriteProcessMemory == nullptr ||
                originalCreateRemoteThread == nullptr || originalSetWindowsHookExA == nullptr || originalSetWindowsHookExW == nullptr ||
                originalCreateThread == nullptr || originalOpenThread == nullptr || originalLoadLibraryA == nullptr || originalLoadLibraryW == nullptr) {
                DWORD error = GetLastError();
                std::cerr << "Failed to get function address from kernel32.dll or user32.dll. Error code: " << error << std::endl;
                CloseHandle(hProcess);
                MH_Uninitialize();
                return 1;
            }

            /*
            HMODULE psapiModule = LoadLibrary(L"psapi.dll");
            if (psapiModule == nullptr) {
                DWORD error = GetLastError();
                std::cerr << "Failed to get handle for psapi.dll. Error code: " << error << std::endl;
                CloseHandle(hProcess);
                MH_Uninitialize();
                return 1;
            }

            if (psapiModule != nullptr) {
                originalGetProcessImageFileName = reinterpret_cast<OriginalGetProcessImageFileName_t>(GetProcAddress(psapiModule, "GetProcessImageFileNameW"));
            }
            */

            MH_STATUS status;

            status = MH_CreateHookApi(L"kernel32.dll", "VirtualAlloc", &HookedVirtualAlloc, reinterpret_cast<LPVOID*>(&originalVirtualAlloc));
            CheckMHResult(status, "VirtualAlloc");

            status = MH_CreateHookApi(L"kernel32.dll", "VirtualAllocEx", &HookedVirtualAllocEx, reinterpret_cast<LPVOID*>(&originalVirtualAllocEx));
            CheckMHResult(status, "VirtualAllocEx");

            status = MH_CreateHookApi(L"kernel32.dll", "WriteProcessMemory", &HookedWriteProcessMemory, reinterpret_cast<LPVOID*>(&originalWriteProcessMemory));
            CheckMHResult(status, "WriteProcessMemory");

            status = MH_CreateHookApi(L"kernel32.dll", "CreateRemoteThread", &HookedCreateRemoteThread, reinterpret_cast<LPVOID*>(&originalCreateRemoteThread));
            CheckMHResult(status, "CreateRemoteThread");

            status = MH_CreateHookApi(L"user32.dll", "SetWindowsHookExA", &HookedSetWindowsHookExA, reinterpret_cast<LPVOID*>(&originalSetWindowsHookExA));
            CheckMHResult(status, "SetWindowsHookExA");

            status = MH_CreateHookApi(L"user32.dll", "SetWindowsHookExW", &HookedSetWindowsHookExW, reinterpret_cast<LPVOID*>(&originalSetWindowsHookExW));
            CheckMHResult(status, "SetWindowsHookExW");

            status = MH_CreateHookApi(L"kernel32.dll", "CreateThread", &HookedCreateThread, reinterpret_cast<LPVOID*>(&originalCreateThread));
            CheckMHResult(status, "CreateThread");

            status = MH_CreateHookApi(L"kernel32.dll", "OpenThread", &HookedOpenThread, reinterpret_cast<LPVOID*>(&originalOpenThread));
            CheckMHResult(status, "OpenThread");

            status = MH_CreateHookApi(L"kernel32.dll", "LoadLibraryA", &HookedLoadLibraryA, reinterpret_cast<LPVOID*>(&originalLoadLibraryA));
            CheckMHResult(status, "LoadLibraryA");

            status = MH_CreateHookApi(L"kernel32.dll", "LoadLibraryW", &HookedLoadLibraryW, reinterpret_cast<LPVOID*>(&originalLoadLibraryW));
            CheckMHResult(status, "LoadLibraryW");

            // status = MH_CreateHookApi(L"psapi.dll", "GetProcessImageFileNameW", &HookedGetProcessImageFileName, reinterpret_cast<LPVOID*>(&originalGetProcessImageFileName));
            // CheckMHResult(status, "GetProcessImageFileNameW");

            if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
                std::cerr << "Failed to enable hooks" << std::endl;
                CloseHandle(hProcess);
                MH_Uninitialize();
                return 1;
            }

            InjectCode(hProcess);

            if (hProcess != nullptr) {
                CloseHandle(hProcess);
            }

            MH_Uninitialize();

            return 0;
        }
    }

    return 0;
}
