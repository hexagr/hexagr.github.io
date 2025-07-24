---
title: Detecting WoW64 Processes
date: 2025-05-11
categories: [windows, cpp, programming]
tags: [windows, cpp, programming]
excerpt: 
ShowToc: false
---

WoW64 (Windows 32-bit on Windows 64-bit) is a subsystem within Microsoft Windows that lets Windows run 32-bit programs on 64-bit hardware. 

One way to glean what processes are currently running in WoW64 mode is by querying `NtQuerySystemInformation` and checking whether `IsWow64Process` returns true or not.

This returns a pointer to a value that is set to TRUE if the process is running under WOW64 on an Intel64, x64, or ARM64 processor.

```C
typedef NTSTATUS(NTAPI* PNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

BOOL IsProcessWow64(HANDLE hProcess) {
    BOOL bIsWow64 = FALSE;
    FARPROC pIsWow64Process = GetProcAddress(
        GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

    if (pIsWow64Process) {
        ((BOOL(WINAPI*)(HANDLE, PBOOL))pIsWow64Process)(hProcess, &bIsWow64);
    }
    return bIsWow64;
}
```

With our type definition and the IsProcessWow64 function defined, we can implement the following logic in our main function like so: before doing anything, we pass GetCurrentProcess to our WoW64 check, thus checking whether the current process or environment we're in is WoW64. 

We then get a handle to `ntdll`, set up a do-while loop and a buffer to store queried process information, and then iterate over them via `NextEntryOffset`.

If the process is a normal 64-bit process, we simply print “x64,” the process name, and the related PID, like so: `[x64] process.exe (PID: 1336)`.

Similarly, if the process returns true for the WOW64 check, we instead print WOW64, like so: `[WOW64] process.exe (PID: 1337)`.

We iterate over the Windows process list after setting up a pointer to the process information buffer: 

```C
  // Iterate processes
    PSYSTEM_PROCESS_INFORMATION procInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (procInfo->NextEntryOffset) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
            (DWORD)(ULONG_PTR)procInfo->UniqueProcessId);  // Iterate processes
    PSYSTEM_PROCESS_INFORMATION procInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (procInfo->NextEntryOffset) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
            (DWORD)(ULONG_PTR)procInfo->UniqueProcessId);
```

For each unique process ID we see, we call `OpenProcess` [which takes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess) a "Desired Access" key represented by a DWORD, a BOOLEAN indicating whether or not to inherit the handle -- we set this to false -- and last, our process ID, represented by a DWORD.

```Cpp
HANDLE OpenProcess(
  [in] DWORD dwDesiredAccess,
  [in] BOOL  bInheritHandle,
  [in] DWORD dwProcessId
);
```

The access level we want to use is `PROCESS_QUERY_LIMITED_INFORMATION`. This allows us to query processes from a standard user account without encountering errors, even when dealing with elevated system processes.

Using this method, in order to enumerate elevated processes, the binary must be run with elevated privileges.

Putting it all together, we traverse the system process list via `NextEntryOffset`, [part](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FSystem%20Information%2FStructures%2FSYSTEM_PROCESS_INFORMATION.html) of the SYSTEM_PROCESS_INFORMATION structure -- checking each process ID against the WoW64 function, and then finally freeing our buffer and ntdll handle after completion.
```C
int main() {
    // Check if *this* program is running under WOW64
    if (IsProcessWow64(GetCurrentProcess())) {
        printf("[!] We appear to be running under WOW64 (32-bit on 64-bit Windows)\n\n");
    }
    else {
        printf("[*] We appear to be running as native 64-bit\n\n");
    }

    // Load NtQuerySystemInformation
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    PNtQuerySystemInformation NtQuerySystemInformation =
        (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");

    ULONG bufferSize = 0;
    NTSTATUS status;
    PVOID buffer = NULL;

    // Query process info
    do {
        if (buffer) free(buffer);
        buffer = malloc(bufferSize);
        status = NtQuerySystemInformation(5, buffer, bufferSize, &bufferSize);
    } while (status == 0xC0000004);  // STATUS_INFO_LENGTH_MISMATCH

    // Iterate processes
    PSYSTEM_PROCESS_INFORMATION procInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (procInfo->NextEntryOffset) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
            (DWORD)(ULONG_PTR)procInfo->UniqueProcessId);

        if (hProcess) {
            BOOL isWow64 = IsProcessWow64(hProcess);
            CloseHandle(hProcess);

            printf("[%s] %.*S (PID: %d)\n",
                isWow64 ? "WOW64" : "x64",
                procInfo->ImageName.Length / 2,
                procInfo->ImageName.Buffer,
                (DWORD)(ULONG_PTR)procInfo->UniqueProcessId);
        }

        procInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)procInfo + procInfo->NextEntryOffset);
    }

    free(buffer);
    FreeLibrary(ntdll);
    return 0;
}
```
![wow64](/wow64.png)

As seen below, one process is running in WoW64 mode on my vanilla Windows installation: 

```text
//snipped
[x64] vshost.exe (PID: 3300)
[WOW64] vcpkgsrv.exe (PID: 7144)
[x64] ServiceHub.Host.dotnet.x64.exe (PID: 7248)
```
[WoW64Search](https://github.com/hexagr/Wow64Search) on Github
