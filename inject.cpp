// language: C++17, target: Windows 11 x64, MSVC
// Injector — LoadLibrary injection into a target process by name
// Usage: inject.exe <process_name.exe> <path_to_dll.dll>

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <string>

static DWORD find_pid(const wchar_t* proc_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe))
    {
        do {
            if (_wcsicmp(pe.szExeFile, proc_name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3) {
        wprintf(L"usage: inject.exe <process.exe> <dll_full_path.dll>\n");
        return 1;
    }

    DWORD pid = find_pid(argv[1]);
    if (!pid) {
        wprintf(L"[-] process not found: %s\n", argv[1]);
        return 2;
    }
    wprintf(L"[+] pid: %lu\n", pid);

    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!proc) {
        wprintf(L"[-] OpenProcess failed: %lu\n", GetLastError());
        return 3;
    }

    std::wstring dll_path(argv[2]);
    size_t byte_len = (dll_path.size() + 1) * sizeof(wchar_t);

    LPVOID remote_buf = VirtualAllocEx(proc, nullptr, byte_len,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_buf) {
        wprintf(L"[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(proc);
        return 4;
    }

    WriteProcessMemory(proc, remote_buf, dll_path.c_str(), byte_len, nullptr);

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC ll   = GetProcAddress(k32, "LoadLibraryW");

    HANDLE thread = CreateRemoteThread(proc, nullptr, 0,
                                       reinterpret_cast<LPTHREAD_START_ROUTINE>(ll),
                                       remote_buf, 0, nullptr);
    if (!thread) {
        wprintf(L"[-] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(proc, remote_buf, 0, MEM_RELEASE);
        CloseHandle(proc);
        return 5;
    }

    WaitForSingleObject(thread, 5000);
    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);
    wprintf(exit_code ? L"[+] injected OK (module base: 0x%lX)\n"
                      : L"[-] LoadLibrary returned NULL — wrong path or bitness mismatch\n",
            exit_code);

    CloseHandle(thread);
    VirtualFreeEx(proc, remote_buf, 0, MEM_RELEASE);
    CloseHandle(proc);
    return exit_code ? 0 : 6;
}
