---
title: Using C Sharp to Enumerate Windows Processes
date: 2023-09-03
categories: [windows,csharp,process enumeration]
tags: [windows,csharp,process enumeration]
excerpt: 
---

In previous posts, I covered how to observe process information [in Windbg by starting a debugging session and dumping the Process Environment Block](https://hexagr.blogspot.com/2023/08/windows-process-initialization.html).

And how we can view the EPROCESS structure, including a doubly linked-list of [active processes via ActiveProcessLinks](https://hexagram.foo/posts/finding-active-processes-with-windbg/).

But in this post, we'll discuss yet another way of gleaning information about processes in Windows, this time from another structure within the Windows ecosystem: the `SYSTEM_PROCESS_INFORMATION` structure.


## SYSTEM_PROCESS_INFORMATION Structure

Microsoft tells us in their documentation that this structure holds various entries which hold system and process information.

> When the `SystemInformationClass` parameter is `SystemProcessInformation`, the buffer pointed to by the `SystemInformation` parameter contains a `SYSTEM_PROCESS_INFORMATION` structure for each process. Each of these structures is immediately followed in memory by one or more `SYSTEM_THREAD_INFORMATION` structures that provide info for each thread in the preceding process. For more information about `SYSTEM_THREAD_INFORMATION`, see the section about this structure in this article.

> The buffer pointed to by the `SystemInformation` parameter should be large enough to hold an array that contains as many `SYSTEM_PROCESS_INFORMATION` and `SYSTEM_THREAD_INFORMATION` structures as there are processes and threads running in the system. This size is specified by the `ReturnLength` parameter.

Microsoft goes on to give us the following type definition for the **`SYSTEM_PROCESS_INFORMATION`** structure, which gives us access to process variables like **`ImageNames`**, **`UniqueProcessId`**, and more:

```c
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION;
```

## NTDLL, Home of .. Many Functions

In previous posts, I talked about how `NTDLL.dll` is where Windows user space frequently calls into in order to talk to relevant low-level parts of Windows and to do stuff in general. And this case is no exception.

In retrieving information from the `SYSTEM_PROCESS_INFORMATION`, we'll need to communicate with `NTDLL` through a couple of system calls. To reach the `SYSTEM_PROCESS_INFORMATION` structure, we'll need to do so through the Windows API via the `QuerySystemInformation` function, which Microsoft provides us with the following type definition for:

```c
__kernel_entry NTSTATUS NtQuerySystemInformation(
  [in]            SYSTEM_INFORMATION_CLASS SystemInformationClass,
  [in, out]       PVOID                    SystemInformation,
  [in]            ULONG                    SystemInformationLength,
  [out, optional] PULONG                   ReturnLength
);
```

## Using Csharp to Talk to NTDLL

We'll translate this type definition to C# and create the following declaration to call the `NtQuerySystemInformation` function and access the `SYSTEM_PROCESS_INFORMATION` structure. Since this function resides in `NTDLL`, we'll use the `extern` keyword to tell the compiler this. 

`PVOID`, a pointer to void, is an `IntPtr` in C#, an integer whose size is that of a pointer. This is for referencing unmanaged memory. Per Microsoft's documentation:

> The `IntPtr` type can be used by languages that support pointers and as a common means of referring to data between languages that do and do not support pointers. `IntPtr` objects can also be used to hold handles. For example, instances of `IntPtr` are used extensively in the `System.IO`.

And `SystemInformationLength` is a `ulong`, or unsigned integer, which is a `uint` in C#. And `ReturnLength` is also a `uint`. So, our initial declaration looks like this:

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class Program
{
    [DllImport("ntdll.dll")]
    public static extern uint NtQuerySystemInformation(uint SystemInformationClass, IntPtr SystemInformation, uint SystemInformationLength, out uint ReturnLength);
}
```

To correctly read the outputs from the Windows API, as well as this structure, we'll need to utilize Unicode. This signature is straightforward. We have a `Length`, `Max Length`, and `Buffer`. Microsoft clarifies this in their documentation:

> When the `ProcessInformationClass` parameter is `ProcessImageFileName`, the buffer pointed to by the `ProcessInformation` parameter should be large enough to hold a `UNICODE_STRING` structure as well as the string itself. The string stored in the `Buffer` member is the name of the image file.
> 
> If the buffer is too small, the function fails with the `STATUS_INFO_LENGTH_MISMATCH` error code and the `ReturnLength` parameter is set to the required buffer size.

The `UNICODE_STRING` signature in C# is as follows:

```csharp
[StructLayout(LayoutKind.Sequential)]
public struct UNICODE_STRING
{
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
}
```

Next, we'll need to Marshal the unmanaged `SYSTEM_PROCESS_INFORMATION` structure. Microsoft provides us this type definition:

```c
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION;
```

But if we dig a bit deeper, we find this type definition provided by Microsoft is seemingly incomplete. Software analyst Geoff Chappell has provided a much more thorough overview of this structure.

If we reference [Geoff Chappell's documentation](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/process.htm), we see the `SYSTEM_PROCESS_INFORMATION` structure actually includes many attributes that Microsoft doesn't officially list.

So, here we'll use Geoff Chappell's analysis for reference since it provides a much more comprehensive layout of the structure.

We'll once again use a C# `StructLayout` to Marshal this information so our program can handle it. After converting the types, our layout for the `SYSTEM_PROCESS_INFORMATION` structure looks like this:

```csharp
[StructLayout(LayoutKind.Sequential)]
public struct SYSTEM_PROCESS_INFORMATION
{
    public uint NextEntryOffset;
    public uint NumberOfThreads;
    public LARGE_INTEGER WorkingSetPrivateSize;
    public uint HardFaultCount;
    public uint NumberOfThreadsHighWatermark;
    public ulong CycleTime;
    public LARGE_INTEGER CreateTime;
    public LARGE_INTEGER UserTime;
    public LARGE_INTEGER KernelTime;
    public UNICODE_STRING ImageName;
    public int BasePriority;
    public IntPtr UniqueProcessId;
    public IntPtr InheritedFromUniqueProcessId;
    public uint HandleCount;
    public uint SessionId;
    public IntPtr UniqueProcessKey;
    public IntPtr PeakVirtualSize;
    public IntPtr VirtualSize;
    public uint PageFaultCount;
    public IntPtr PeakWorkingSetSize;
    public IntPtr WorkingSetSize;
    public IntPtr QuotaPeakPagedPoolUsage;
    public IntPtr QuotaPagedPoolUsage;
    public IntPtr QuotaPeakNonPagedPoolUsage;
    public IntPtr QuotaNonPagedPoolUsage;
    public IntPtr PagefileUsage;
    public IntPtr PeakPagefileUsage;
    public IntPtr PrivatePageCount;
    public LARGE_INTEGER ReadOperationCount;
    public LARGE_INTEGER WriteOperationCount;
    public LARGE_INTEGER OtherOperationCount;
    public LARGE_INTEGER ReadTransferCount;
    public LARGE_INTEGER WriteTransferCount;
    public LARGE_INTEGER OtherTransferCount;
}
```

The `large_integer` will need to be correctly defined too. This was used in the aforementioned documentation. And it represents a 64-bit signed integer, e.g. `long QuadPart`:

```csharp
[StructLayout(LayoutKind.Sequential)]
public struct LARGE_INTEGER
{
    public long QuadPart;
}
```

Next we'll declare and initialize the variables for our function. These will all be unsigned integers with the exception of the `IntPtr`. `dwRet` will hold our return value from `NtQuerySystemInformation`. `dwSize` represents the size of the memory buffers we'll be operating on. We'll initialize this to zero. And `dwStatus` represents a default error code indicating that a length mismatch has occurred. We'll set this as the default error status for now. And last, we'll initialize our pointer to zero.

```csharp
public static void Main()
{
    uint dwRet;
    uint dwSize = 0x0;
    uint dwStatus = 0xC0000004;
    IntPtr p = IntPtr.Zero;
}
```

We initialize a loop where we first check if the pointer p is not zero. If it is not, we free the previously allocated memory using `Marshal.FreeHGlobal(p)`.

Next, we allocate memory for the buffer by using `Marshal.AllocHGlobal((int)dwSize)`, where `dwSize` specifies the amount of memory needed for our result. 

Afterward, we call `NtQuerySystemInformation`, passing the allocated buffer `p`, the size of the buffer `dwSize`, and a variable `dwRet` to hold the number of bytes returned.

If `NtQuerySystemInformation` returns a status code of 0, our query was successful, and we can break the loop and process the data. If the status code is `0xC0000004`, there's a length mismatch, e.g. our buffer size wasn't large enough to hold all the data. 

In this case, we don't bail out of the loop immediately but instead adjust the buffer size with `dwSize = dwRet + (2 << 12)`, increasing dwSize to accommodate the full result.

If we encounter any other error code, however, we print an error message, free the memory, and exit the loop.

```csharp
while (true)
{
    if (p != IntPtr.Zero) Marshal.FreeHGlobal(p);

    p = Marshal.AllocHGlobal((int)dwSize);
    dwStatus = NtQuerySystemInformation(5, p, dwSize, out dwRet);

    if (dwStatus == 0) { break; }
    else if (dwStatus != 0xC0000004)
    {
        Marshal.FreeHGlobal(p);
        p = IntPtr.Zero;
        Console.WriteLine("Data retrieval failed");
        return;
    }

    dwSize = dwRet + (2 << 12);
}
```

Finally, we can loop through the entries and print the attributes from the `SYSTEM_PROCESS_INFORMATION` structure.

We use `Marshal.PtrToStructure` to reference the unmanaged memory we've marshaled into the `currentPtr`. This allows us to map raw memory to the specific C# SYSTEM_PROCESS_INFORMATION typedef we defined earlier. C sharp's use of static typing ensures the data is retrieved safely and with the correct types.


```csharp
var processInfo = (SYSTEM_PROCESS_INFORMATION)Marshal.PtrToStructure(currentPtr, typeof(SYSTEM_PROCESS_INFORMATION));
```

And then we write out output with `Console.WriteLine`, checking the values of the attributes we're referencing. If the `ImageName.Buffer` is non-zero, we likely have a valid `ImageName`. So we call `Marshal.PtrToStringUni(processInfo.ImageName.Buffer)` on it to get the Unicode **ImageName**. And to extract the **UniqueProcessId**, we convert the value to a `Int64`, a signed integer.

After each record, we move to the next entry using the `NextEntryOffset` value. We convert this to a 32-bit integer, though. Per Microsoft's documentation:

> `NextEntryOffset` (4 bytes): A 32-bit unsigned integer that MUST specify the offset, in bytes, from the current `FILE_LINK_ENTRY_INFORMATION` structure to the next `FILE_LINK_ENTRY_INFORMATION` structure. A value of 0 indicates this is the last entry structure.

Altogether, our last bit of code will look like this:

```csharp
IntPtr currentPtr = p;
do
{
    var processInfo = (SYSTEM_PROCESS_INFORMATION)Marshal.PtrToStructure(currentPtr, typeof(SYSTEM_PROCESS_INFORMATION));

    Console.WriteLine($"[*] Image name: {(processInfo.ImageName.Buffer != IntPtr.Zero ? Marshal.PtrToStringUni(processInfo.ImageName.Buffer) : "")}");
    Console.WriteLine($"    > PID: {processInfo.UniqueProcessId.ToInt64()}");
    Console.WriteLine();

    // Calculate the offset to the next process entry
    int offset = (int)processInfo.NextEntryOffset;
    if (offset == 0)
        break;

    // Move to the next process entry
    currentPtr = IntPtr.Add(currentPtr, offset);
} while (true);

Marshal.FreeHGlobal(p);
}
```

On Github I've uploaded the C# code for this demonstration to a [small repository dubbed "Cardinal."](https://github.com/hexagr/Cardinal)

After compiling, we can do:
```powershell
>.\Cardinal\bin\Debug\Cardinal.exe
[*] Image name:
    > PID: 0

[*] Image name: System
    > PID: 4

[*] Image name: Registry
    > PID: 116

[*] Image name: smss.exe
    > PID: 444

[*] Image name: csrss.exe
    > PID: 636

[*] Image name: wininit.exe
    > PID: 708
```    