---
title: Finding Active Processes with Windbg
date: 2023-09-02
categories: [windows,windbg]
tags: [windows,windbg]
excerpt: 
---

In the Windows kernel, each process is assigned an EPROCESS structure, which is a kernel object that represents a program or process. And a Process Environment Block (PEB) is just one of many structures pointed to by the EPROCESS structure.  A snippet from `_EPROCESS` as documented on Vergilius Project:

```C
volatile ULONGLONG OwnerProcessId;
struct _PEB* Peb;
struct _MM_SESSION_SPACE* Session;
VOID* Sparel;
```

In user space however, we cannot directly reference all of the EPROCESS structures and their data. At most, we can do something like `dt nt!_EPROCESS` in windbg and get a peek at the layout. We'll have to enable kernel debugging to more closely examine things. But here's what we can see in user mode. The EPROCESS structure is large. The entire output from windbg is as follows:

```text
> dt nt!_EPROCESS
ntdll!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x438 ProcessLock      : _EX_PUSH_LOCK
   +0x440 UniqueProcessId  : Ptr64 Void
   +0x448 ActiveProcessLinks : _LIST_ENTRY
   +0x458 RundownProtect   : _EX_RUNDOWN_REF
   +0x460 Flags2           : Uint4B
   +0x460 JobNotReallyActive : Pos 0, 1 Bit
   +0x460 AccountingFolded : Pos 1, 1 Bit
   +0x460 NewProcessReported : Pos 2, 1 Bit
   +0x460 ExitProcessReported : Pos 3, 1 Bit
   +0x460 ReportCommitChanges : Pos 4, 1 Bit
   +0x460 LastReportMemory : Pos 5, 1 Bit
   +0x460 ForceWakeCharge  : Pos 6, 1 Bit
   +0x460 CrossSessionCreate : Pos 7, 1 Bit
   +0x460 NeedsHandleRundown : Pos 8, 1 Bit
   +0x460 RefTraceEnabled  : Pos 9, 1 Bit
   +0x460 PicoCreated      : Pos 10, 1 Bit
   +0x460 EmptyJobEvaluated : Pos 11, 1 Bit
   +0x460 DefaultPagePriority : Pos 12, 3 Bits
   +0x460 PrimaryTokenFrozen : Pos 15, 1 Bit
   +0x460 ProcessVerifierTarget : Pos 16, 1 Bit
   +0x460 RestrictSetThreadContext : Pos 17, 1 Bit
   +0x460 AffinityPermanent : Pos 18, 1 Bit
   +0x460 AffinityUpdateEnable : Pos 19, 1 Bit
   +0x460 PropagateNode    : Pos 20, 1 Bit
   +0x460 ExplicitAffinity : Pos 21, 1 Bit
   +0x460 ProcessExecutionState : Pos 22, 2 Bits
   +0x460 EnableReadVmLogging : Pos 24, 1 Bit
   +0x460 EnableWriteVmLogging : Pos 25, 1 Bit
   +0x460 FatalAccessTerminationRequested : Pos 26, 1 Bit
   +0x460 DisableSystemAllowedCpuSet : Pos 27, 1 Bit
   +0x460 ProcessStateChangeRequest : Pos 28, 2 Bits
   +0x460 ProcessStateChangeInProgress : Pos 30, 1 Bit
   +0x460 InPrivate        : Pos 31, 1 Bit
   +0x464 Flags            : Uint4B
   +0x464 CreateReported   : Pos 0, 1 Bit
   +0x464 NoDebugInherit   : Pos 1, 1 Bit
   +0x464 ProcessExiting   : Pos 2, 1 Bit
   +0x464 ProcessDelete    : Pos 3, 1 Bit
   +0x464 ManageExecutableMemoryWrites : Pos 4, 1 Bit
   +0x464 VmDeleted        : Pos 5, 1 Bit
   +0x464 OutswapEnabled   : Pos 6, 1 Bit
   +0x464 Outswapped       : Pos 7, 1 Bit
   +0x464 FailFastOnCommitFail : Pos 8, 1 Bit
   +0x464 Wow64VaSpace4Gb  : Pos 9, 1 Bit
   +0x464 AddressSpaceInitialized : Pos 10, 2 Bits
   +0x464 SetTimerResolution : Pos 12, 1 Bit
   +0x464 BreakOnTermination : Pos 13, 1 Bit
   +0x464 DeprioritizeViews : Pos 14, 1 Bit
   +0x464 WriteWatch       : Pos 15, 1 Bit
   +0x464 ProcessInSession : Pos 16, 1 Bit
   +0x464 OverrideAddressSpace : Pos 17, 1 Bit
   +0x464 HasAddressSpace  : Pos 18, 1 Bit
   +0x464 LaunchPrefetched : Pos 19, 1 Bit
   +0x464 Reserved         : Pos 20, 1 Bit
   +0x464 VmTopDown        : Pos 21, 1 Bit
   +0x464 ImageNotifyDone  : Pos 22, 1 Bit
   +0x464 PdeUpdateNeeded  : Pos 23, 1 Bit
   +0x464 VdmAllowed       : Pos 24, 1 Bit
   +0x464 ProcessRundown   : Pos 25, 1 Bit
   +0x464 ProcessInserted  : Pos 26, 1 Bit
   +0x464 DefaultIoPriority : Pos 27, 3 Bits
   +0x464 ProcessSelfDelete : Pos 30, 1 Bit
   +0x464 SetTimerResolutionLink : Pos 31, 1 Bit
   +0x468 CreateTime       : _LARGE_INTEGER
   +0x470 ProcessQuotaUsage : [2] Uint8B
   +0x480 ProcessQuotaPeak : [2] Uint8B
   +0x490 PeakVirtualSize  : Uint8B
   +0x498 VirtualSize      : Uint8B
   +0x4a0 SessionProcessLinks : _LIST_ENTRY
   +0x4b0 ExceptionPortData : Ptr64 Void
   +0x4b0 ExceptionPortValue : Uint8B
   +0x4b0 ExceptionPortState : Pos 0, 3 Bits
   +0x4b8 Token            : _EX_FAST_REF
   +0x4c0 MmReserved       : Uint8B
   +0x4c8 AddressCreationLock : _EX_PUSH_LOCK
   +0x4d0 PageTableCommitmentLock : _EX_PUSH_LOCK
   +0x4d8 RotateInProgress : Ptr64 _ETHREAD
   +0x4e0 ForkInProgress   : Ptr64 _ETHREAD
   +0x4e8 CommitChargeJob  : Ptr64 _EJOB
   +0x4f0 CloneRoot        : _RTL_AVL_TREE
   +0x4f8 NumberOfPrivatePages : Uint8B
   +0x500 NumberOfLockedPages : Uint8B
   +0x508 Win32Process     : Ptr64 Void
   +0x510 Job              : Ptr64 _EJOB
   +0x518 SectionObject    : Ptr64 Void
   +0x520 SectionBaseAddress : Ptr64 Void
   +0x528 Cookie           : Uint4B
   +0x530 WorkingSetWatch  : Ptr64 _PAGEFAULT_HISTORY
   +0x538 Win32WindowStation : Ptr64 Void
   +0x540 InheritedFromUniqueProcessId : Ptr64 Void
   +0x548 OwnerProcessId   : Uint8B
   +0x550 Peb              : Ptr64 _PEB
   +0x558 Session          : Ptr64 _MM_SESSION_SPACE
   +0x560 Spare1           : Ptr64 Void
   +0x568 QuotaBlock       : Ptr64 _EPROCESS_QUOTA_BLOCK
   +0x570 ObjectTable      : Ptr64 _HANDLE_TABLE
   +0x578 DebugPort        : Ptr64 Void
   +0x580 WoW64Process     : Ptr64 _EWOW64PROCESS
   +0x588 DeviceMap        : _EX_FAST_REF
   +0x590 EtwDataSource    : Ptr64 Void
   +0x598 PageDirectoryPte : Uint8B
   +0x5a0 ImageFilePointer : Ptr64 _FILE_OBJECT
   +0x5a8 ImageFileName    : [15] UChar
   +0x5b7 PriorityClass    : UChar
   +0x5b8 SecurityPort     : Ptr64 Void
   +0x5c0 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
   +0x5c8 JobLinks         : _LIST_ENTRY
   +0x5d8 HighestUserAddress : Ptr64 Void
   +0x5e0 ThreadListHead   : _LIST_ENTRY
   +0x5f0 ActiveThreads    : Uint4B
   +0x5f4 ImagePathHash    : Uint4B
   +0x5f8 DefaultHardErrorProcessing : Uint4B
   +0x5fc LastThreadExitStatus : Int4B
   +0x600 PrefetchTrace    : _EX_FAST_REF
   +0x608 LockedPagesList  : Ptr64 Void
   +0x610 ReadOperationCount : _LARGE_INTEGER
   +0x618 WriteOperationCount : _LARGE_INTEGER
   +0x620 OtherOperationCount : _LARGE_INTEGER
   +0x628 ReadTransferCount : _LARGE_INTEGER
   +0x630 WriteTransferCount : _LARGE_INTEGER
   +0x638 OtherTransferCount : _LARGE_INTEGER
   +0x640 CommitChargeLimit : Uint8B
   +0x648 CommitCharge     : Uint8B
   +0x650 CommitChargePeak : Uint8B
   +0x680 Vm               : _MMSUPPORT_FULL
   +0x7c0 MmProcessLinks   : _LIST_ENTRY
   +0x7d0 ModifiedPageCount : Uint4B
   +0x7d4 ExitStatus       : Int4B
   +0x7d8 VadRoot          : _RTL_AVL_TREE
   +0x7e0 VadHint          : Ptr64 Void
   +0x7e8 VadCount         : Uint8B
   +0x7f0 VadPhysicalPages : Uint8B
   +0x7f8 VadPhysicalPagesLimit : Uint8B
   +0x800 AlpcContext      : _ALPC_PROCESS_CONTEXT
   +0x820 TimerResolutionLink : _LIST_ENTRY
   +0x830 TimerResolutionStackRecord : Ptr64 _PO_DIAG_STACK_RECORD
   +0x838 RequestedTimerResolution : Uint4B
   +0x83c SmallestTimerResolution : Uint4B
   +0x840 ExitTime         : _LARGE_INTEGER
   +0x848 InvertedFunctionTable : Ptr64 _INVERTED_FUNCTION_TABLE_USER_MODE
   +0x850 InvertedFunctionTableLock : _EX_PUSH_LOCK
   +0x858 ActiveThreadsHighWatermark : Uint4B
   +0x85c LargePrivateVadCount : Uint4B
   +0x860 ThreadListLock   : _EX_PUSH_LOCK
   +0x868 WnfContext       : Ptr64 Void
   +0x870 ServerSilo       : Ptr64 _EJOB
   +0x878 SignatureLevel   : UChar
   +0x879 SectionSignatureLevel : UChar
   +0x87a Protection       : _PS_PROTECTION
   +0x87b HangCount        : Pos 0, 3 Bits
   +0x87b GhostCount       : Pos 3, 3 Bits
   +0x87b PrefilterException : Pos 6, 1 Bit
   +0x87c Flags3           : Uint4B
   +0x87c Minimal          : Pos 0, 1 Bit
   +0x87c ReplacingPageRoot : Pos 1, 1 Bit
   +0x87c Crashed          : Pos 2, 1 Bit
   +0x87c JobVadsAreTracked : Pos 3, 1 Bit
   +0x87c VadTrackingDisabled : Pos 4, 1 Bit
   +0x87c AuxiliaryProcess : Pos 5, 1 Bit
   +0x87c SubsystemProcess : Pos 6, 1 Bit
   +0x87c IndirectCpuSets  : Pos 7, 1 Bit
   +0x87c RelinquishedCommit : Pos 8, 1 Bit
   +0x87c HighGraphicsPriority : Pos 9, 1 Bit
   +0x87c CommitFailLogged : Pos 10, 1 Bit
   +0x87c ReserveFailLogged : Pos 11, 1 Bit
   +0x87c SystemProcess    : Pos 12, 1 Bit
   +0x87c HideImageBaseAddresses : Pos 13, 1 Bit
   +0x87c AddressPolicyFrozen : Pos 14, 1 Bit
   +0x87c ProcessFirstResume : Pos 15, 1 Bit
   +0x87c ForegroundExternal : Pos 16, 1 Bit
   +0x87c ForegroundSystem : Pos 17, 1 Bit
   +0x87c HighMemoryPriority : Pos 18, 1 Bit
   +0x87c EnableProcessSuspendResumeLogging : Pos 19, 1 Bit
   +0x87c EnableThreadSuspendResumeLogging : Pos 20, 1 Bit
   +0x87c SecurityDomainChanged : Pos 21, 1 Bit
   +0x87c SecurityFreezeComplete : Pos 22, 1 Bit
   +0x87c VmProcessorHost  : Pos 23, 1 Bit
   +0x87c VmProcessorHostTransition : Pos 24, 1 Bit
   +0x87c AltSyscall       : Pos 25, 1 Bit
   +0x87c TimerResolutionIgnore : Pos 26, 1 Bit
   +0x87c DisallowUserTerminate : Pos 27, 1 Bit
   +0x87c EnableProcessRemoteExecProtectVmLogging : Pos 28, 1 Bit
   +0x87c EnableProcessLocalExecProtectVmLogging : Pos 29, 1 Bit
   +0x87c MemoryCompressionProcess : Pos 30, 1 Bit
   +0x880 DeviceAsid       : Int4B
   +0x888 SvmData          : Ptr64 Void
   +0x890 SvmProcessLock   : _EX_PUSH_LOCK
   +0x898 SvmLock          : Uint8B
   +0x8a0 SvmProcessDeviceListHead : _LIST_ENTRY
   +0x8b0 LastFreezeInterruptTime : Uint8B
   +0x8b8 DiskCounters     : Ptr64 _PROCESS_DISK_COUNTERS
   +0x8c0 PicoContext      : Ptr64 Void
   +0x8c8 EnclaveTable     : Ptr64 Void
   +0x8d0 EnclaveNumber    : Uint8B
   +0x8d8 EnclaveLock      : _EX_PUSH_LOCK
   +0x8e0 HighPriorityFaultsAllowed : Uint4B
   +0x8e8 EnergyContext    : Ptr64 _PO_PROCESS_ENERGY_CONTEXT
   +0x8f0 VmContext        : Ptr64 Void
   +0x8f8 SequenceNumber   : Uint8B
   +0x900 CreateInterruptTime : Uint8B
   +0x908 CreateUnbiasedInterruptTime : Uint8B
   +0x910 TotalUnbiasedFrozenTime : Uint8B
   +0x918 LastAppStateUpdateTime : Uint8B
   +0x920 LastAppStateUptime : Pos 0, 61 Bits
   +0x920 LastAppState     : Pos 61, 3 Bits
   +0x928 SharedCommitCharge : Uint8B
   +0x930 SharedCommitLock : _EX_PUSH_LOCK
   +0x938 SharedCommitLinks : _LIST_ENTRY
   +0x948 AllowedCpuSets   : Uint8B
   +0x950 DefaultCpuSets   : Uint8B
   +0x948 AllowedCpuSetsIndirect : Ptr64 Uint8B
   +0x950 DefaultCpuSetsIndirect : Ptr64 Uint8B
   +0x958 DiskIoAttribution : Ptr64 Void
   +0x960 DxgProcess       : Ptr64 Void
   +0x968 Win32KFilterSet  : Uint4B
   +0x96c Machine          : Uint2B
   +0x96e Spare0           : Uint2B
   +0x970 ProcessTimerDelay : _PS_INTERLOCKED_TIMER_DELAY_VALUES
   +0x978 KTimerSets       : Uint4B
   +0x97c KTimer2Sets      : Uint4B
   +0x980 ThreadTimerSets  : Uint4B
   +0x988 VirtualTimerListLock : Uint8B
   +0x990 VirtualTimerListHead : _LIST_ENTRY
   +0x9a0 WakeChannel      : _WNF_STATE_NAME
   +0x9a0 WakeInfo         : _PS_PROCESS_WAKE_INFORMATION
   +0x9d0 MitigationFlags  : Uint4B
   +0x9d0 MitigationFlagsValues : <unnamed-tag>
   +0x9d4 MitigationFlags2 : Uint4B
   +0x9d4 MitigationFlags2Values : <unnamed-tag>
   +0x9d8 PartitionObject  : Ptr64 Void
   +0x9e0 SecurityDomain   : Uint8B
   +0x9e8 ParentSecurityDomain : Uint8B
   +0x9f0 CoverageSamplerContext : Ptr64 Void
   +0x9f8 MmHotPatchContext : Ptr64 Void
   +0xa00 IdealProcessorAssignmentBlock : _KE_IDEAL_PROCESSOR_ASSIGNMENT_BLOCK
   +0xb18 DynamicEHContinuationTargetsTree : _RTL_AVL_TREE
   +0xb20 DynamicEHContinuationTargetsLock : _EX_PUSH_LOCK
   +0xb28 DynamicEnforcedCetCompatibleRanges : _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
   +0xb38 DisabledComponentFlags : Uint4B
   +0xb3c PageCombineSequence : Int4B
   +0xb40 EnableOptionalXStateFeaturesLock : _EX_PUSH_LOCK
   +0xb48 PathRedirectionHashes : Ptr64 Uint4B
   +0xb50 SyscallProviderReserved : [4] Ptr64 Void
   +0xb70 MitigationFlags3 : Uint4B
   +0xb70 MitigationFlags3Values : <unnamed-tag>

   ```
I won't cover all of these entries here. But observe that near the top of the structure, we see an entry called `ActiveProcessLinks`, which is part of a doubly linked-list, containing forward and backwards pointers linking entries together. This EPROCESS list structure contains all the active programs. And if we enable kernel debugging, we can iterate through this list.

In an elevated Command Prompt, we run `bcdedit -debug on` and reboot the machine. And then open windbg with administrative privileges.

In a local kernel debug session, we can now check the PsActiveProcessHead structure and get it's address. This is the structure that the Microsoft utility PsList walks to produce a list of active processes.

```text
lkd> x nt!PsActiveProcessHead
fffff807`25e37f90 nt!PsActiveProcessHead = <no type information>
```

Next let's get the `_LIST_ENTRY` forward link (Flink) using the address from the `PsActiveProcessHead` structure:

```text
lkd> dt nt!_LIST_ENTRY fffff807`25e37f90
 [ 0xffffc509`c5488488 - 0xffffc509`cc9d6508 ]
   +0x000 Flink            : 0xffffc509`c5488488 _LIST_ENTRY [ 0xffffc509`c54f64c8 - 0xfffff807`25e37f90 ]
   +0x008 Blink            : 0xffffc509`cc9d6508 _LIST_ENTRY [ 0xfffff807`25e37f90 - 0xffffc509`cbf98508 ]   
```

The second thing we need is the offset of the EPROCESS structure's ActiveProcessLinks `_LIST_ENTRY`, which we can see here at `0x448`:

```text
lkd> dt nt!_eprocess
   +0x000 Pcb              : _KPROCESS
   +0x438 ProcessLock      : _EX_PUSH_LOCK
   +0x440 UniqueProcessId  : Ptr64 Void
   +0x448 ActiveProcessLinks : _LIST_ENTRY
```

And now that we have the Flink `_LIST_ENTRY` address ```0xffffc509`c5488488``` — bringing it all together, we can get the first entry (first foward link, or flink) to the ActiveProcessLinks list, and thus the ImageFileName of the first record in the EPROCESS list. We'll use the LIST_ENTRY address and subtract the offset of the ActiveProcessLinks value (0x448).

What we're doing here essentially is using the offset to locate the beginning of each EPROCESS record. Knowing this, we then tell the debugger we want get both the ActiveProcessLinks.flink, the forward link to the next entry in the linked list, and the ImageFileName of the current entry:

```text
lkd> dt nt!_eprocess 0xffffc509`c5488488-0x448 -y ActiveProcessLinks.flink -y ImageFileName
   +0x448 ActiveProcessLinks       :  [ 0xffffc509`c54f64c8 - 0xfffff807`25e37f90 ]
      +0x000 Flink                    : 0xffffc509`c54f64c8 _LIST_ENTRY [ 0xffffc509`c8373488 - 0xffffc509`c5488488 ]
   +0x5a8 ImageFileName            : [15]  "System"
 ```  

Ah, the System image file name. And we see the next flink that is referenced is ```0xffffc509`c54f64c8```. Let's get the ImageFileName for that entry, too:

```text
lkd> dt nt!_eprocess 0xffffc509`c54f64c8-0x448 -y ActiveProcessLinks.flink -y ImageFileName
   +0x448 ActiveProcessLinks       :  [ 0xffffc509`c8373488 - 0xffffc509`c5488488 ]
      +0x000 Flink                    : 0xffffc509`c8373488 _LIST_ENTRY [ 0xffffc509`c8194508 - 0xffffc509`c54f64c8 ]
   +0x5a8 ImageFileName            : [15]  "Registry"

```

The Registry service! Alright. And once more we see the next address is at ```0xffffc509`c8373488```. We'll get the ImageFileName for that entry as well: 

```text
lkd> dt nt!_eprocess 0xffffc509`c8373488-0x448 -y ActiveProcessLinks.flink -y ImageFileName
   +0x448 ActiveProcessLinks       :  [ 0xffffc509`c8194508 - 0xffffc509`c54f64c8 ]
      +0x000 Flink                    : 0xffffc509`c8194508 _LIST_ENTRY [ 0xffffc509`ca6794c8 - 0xffffc509`c8373488 ]
   +0x5a8 ImageFileName            : [15]  "smss.exe"
```
And that's the `smss.exe` executable, which provides functionality for Microsoft Window's Session Manager Subsystem.

We could continue walking the EPROCESS list and enumerate every processes forward and backwards pointers. But I won't iterate through all of them manually here.

The kernel debugger in Windows also provides some nice built-in functionality to make looping through process structures pretty fast. We can use the `!process` module in the kernel debugger to get information about active processes, like so:

```text
lkd> !process 0 0
**** NT ACTIVE PROCESS DUMP ****
PROCESS ffffc509c5488040
    SessionId: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 001ae002  ObjectTable: ffffda878c2aae80  HandleCount: 2748.
    Image: System

PROCESS ffffc509c54f6080
    SessionId: none  Cid: 006c    Peb: 00000000  ParentCid: 0004
    DirBase: 1031d5002  ObjectTable: ffffda878c259cc0  HandleCount:   0.
    Image: Registry

PROCESS ffffc509c8373040
    SessionId: none  Cid: 01c0    Peb: 5d58682000  ParentCid: 0004
    DirBase: 10dcb5002  ObjectTable: ffffda878d5909c0  HandleCount:  58.
    Image: smss.exe

 ...
 ``` 

 We can verify our work here. The expression ```0xffffc509`c5488488 - `0x448``` evaluates to ```0xffffc509c5488040```. So, we know our System value is correct.

But what about our Registry value? Well, ```0xffffc509`c54f64c8 - 0x448``` gives us ```0xffffc509c54f6080```. So our Registry value is also correct.

And our entry for `smss.exe` appears to be on accurate as well. Verifying it against the kernel debugger's `!process` module output, it correctly evaluates to `0xffffc509c8373040`, which is the result of the offset subtraction we did prior: ```0xffffc509`c8373488 - 0x448```.

We can use a simple Python script to double check that the offsets we calculated beforehand align with those printed out by the !process module:
```python
offset = 0x448

memory_addresses = [
    0xffffc509c5488488,
    0xffffc509c54f64c8,
    0xffffc509c8373488
]

for address in memory_addresses:
    result = address - offset
    print(hex(result))

```

```plaintext
0xffffc509c5488040
0xffffc509c54f6080
0xffffc509c8373040
```



