#ifndef __PROCESS_DEF__
#define __PROCESS_DEF__

#include <windows.h> 
#include <Psapi.h>
#include <vector>
#include <algorithm>
#include <string>
#include <iterator>
#include <list>

#include "process_mem_man.h"

#include "md5.h"
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)



typedef struct _CLIENT_ID {
  DWORD UniqueProcess;
  DWORD UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

  typedef struct _THREAD_BASIC_INFORMATION {
  typedef PVOID KPRIORITY;
  NTSTATUS ExitStatus; 
  PVOID TebBaseAddress; 
  CLIENT_ID ClientId; 
  KAFFINITY AffinityMask; 
  KPRIORITY Priority; 
  KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef struct _UNICODE_STRING {     
	USHORT Length;     
	USHORT MaximumLength;     
	PWSTR Buffer; } 
UNICODE_STRING, *PUNICODE_STRING;

typedef long NTSTATUS;
typedef NTSTATUS *PNTSTATUS;

typedef ULONG KAFFINITY;
typedef KAFFINITY *PKAFFINITY;

typedef LONG KPRIORITY;

typedef struct _PROCESS_PARAMETERS
{
  ULONG   AllocationSize;
  ULONG   ActualSize;
  ULONG   Flags;
  ULONG   Unknown1;
  HANDLE  InputHandle;
  HANDLE  OutputHandle;
  HANDLE  ErrorHandle;
  UNICODE_STRING Unknown3;         
  UNICODE_STRING CurrentDirectory;
  HANDLE  CurrentDir;
  UNICODE_STRING SearchPath;       
  UNICODE_STRING ApplicationName;   
  UNICODE_STRING CommandLine;
  PVOID   EnvironmentBlock;
  ULONG   Unknown[9];
  UNICODE_STRING Unknown4;
  UNICODE_STRING Unknown5;
  UNICODE_STRING Unknown6;
  UNICODE_STRING Unknown7;
} PROCESS_PARAMETERS, *PPROCESS_PARAMETERS;

typedef struct _LDR_MODULE

{
   LIST_ENTRY     InLoadOrderModuleList;
   LIST_ENTRY     InMemoryOrderModuleList;// not used
   LIST_ENTRY     InInitializationOrderModuleList;// not used
   PVOID          BaseAddress;
   ULONG          EntryPoint;
   ULONG          SizeOfImage;
   UNICODE_STRING FullDllName;
   UNICODE_STRING BaseDllName;
   ULONG          Flags;
   SHORT          LoadCount;
   SHORT          TlsIndex;
   HANDLE         SectionHandle;
   ULONG          CheckSum;
   ULONG          TimeDateStamp;
#ifdef KDBG
  IMAGE_SYMBOL_INFO SymbolInfo;
#endif /* KDBG */
} LDR_MODULE, *PLDR_MODULE;

/*
typedef struct _PBI_WOW64
{
	NTSTATUS ExitStatus;
	ULONG64  PebBaseAddress;
	ULONG64  AffinityMask;
	KPRIORITY BasePriority;
	ULONG64  UniqueProcessId;
	ULONG64  InheritedFromUniqueProcessId;

} PBI_WOW64, *PPBI_WOW64;
*/
typedef struct _PBI_WOW64 {
	PVOID Reserved1[2];
	PVOID64 PebBaseAddress;
	PVOID Reserved2[4];
	ULONG_PTR UniqueProcessId[2];
	PVOID Reserved3[2];
} PBI_WOW64, *PPBI_WOW64;




typedef struct _PEB_LDR_DATA

{
   ULONG Length;
   BOOLEAN Initialized;
   PVOID SsHandle;
   LIST_ENTRY InLoadOrderModuleList;
   LIST_ENTRY InMemoryOrderModuleList;
   LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

/*
typedef struct _PROCESS_BASIC_INFORMATION_WOW64 {
	PVOID Reserved1[2];
	PVOID64 PebBaseAddress;
	PVOID Reserved2[4];
	ULONG_PTR UniqueProcessId[2];
	PVOID Reserved3[2];
} PROCESS_BASIC_INFORMATION_WOW64;
*/
/*
typedef struct _PEBx64 {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[21];
	PPEB_LDR_DATA LoaderData;
	PVOID64 ProcessParameters;
	BYTE Reserved3[520];
	void *PostProcessInitRoutine;
	BYTE Reserved4[136];
	ULONG SessionId;
} PEBx64 , *PEBx64;
*/


/*
typedef struct _PEBx64 {
  BYTE Reserved1[2];
  BYTE BeingDebugged;
  BYTE Reserved2[21];
  PPEB_LDR_DATA LoaderData;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  BYTE Reserved3[520];
  void *PostProcessInitRoutine;
  BYTE Reserved4[136];
  ULONG SessionId;
} PEBx64 , *PPEBx64;
*/


typedef struct _PROCESS_ENVIRONMENT_BLOCK
{

  BOOLEAN                 InheritedAddressSpace;
  BOOLEAN                 ReadImageFileExecOptions;
  BOOLEAN                 BeingDebugged;
  BOOLEAN                 Spare;
  HANDLE                  Mutant;
  PVOID                   ImageBaseAddress;
  PPEB_LDR_DATA Ldr;                             // 0Ch
  PPROCESS_PARAMETERS    pp;
  HANDLE  hHeap;     
  DWORD   lock;      
  void    *ack_lock; 
  void    *rel_lock; 
  DWORD   *lock_cnt; 
  void    *user_cb;  
  HANDLE  *heaps;    
  void    *cs;
  DWORD   ver;       
} PROCESS_ENVIRONMENT_BLOCK, *PPROCESS_ENVIRONMENT_BLOCK;



typedef struct _PEB
{
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBaseAddress;
	PPEB_LDR_DATA           LoaderData;
	PROCESS_PARAMETERS      *ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	//  PPEBLOCKROUTINE         FastPebLockRoutine;
	PVOID         FastPebLockRoutine;
	//  PPEBLOCKROUTINE         FastPebUnlockRoutine;
	PVOID         FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID                  *KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	//  PPEB_FREE_BLOCK         FreeList;
	PVOID         FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID                   *ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID                  **ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
} PEB, *PPEB;


//typedef PROCESS_ENVIRONMENT_BLOCK PEB, *PPEB;

typedef struct _TEB {
  PVOID Reserved1[12];
  PPEB  ProcessEnvironmentBlock;
  PVOID Reserved2[399];
  BYTE  Reserved3[1952];
  PVOID TlsSlots[64];
  BYTE  Reserved4[8];
  PVOID Reserved5[26];
  PVOID ReservedForOle;
  PVOID Reserved6[4];
  PVOID TlsExpansionSlots;
} TEB, *PTEB;


typedef struct PEBx {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[21];
	PPEB_LDR_DATA LoaderData;
	PVOID64 ProcessParameters;
	BYTE Reserved3[520];
	void *PostProcessInitRoutine;
	BYTE Reserved4[136];
	ULONG SessionId;
};

typedef PEBx *PPEBx;


typedef enum _PROCESSINFOCLASS 
{
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,          
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef   enum   _THREADINFOCLASS
{
  ThreadBasicInformation,
  ThreadTimes,
  ThreadPriority,
  ThreadBasePriority,
  ThreadAffinityMask,
  ThreadImpersonationToken,
  ThreadDescriptorTableEntry,
  ThreadEnableAlignmentFaultFixup,
  ThreadEventPair_Reusable,
  ThreadQuerySetWin32StartAddress,
  ThreadZeroTlsCell,
  ThreadPerformanceCount,
  ThreadAmILastThread,
  ThreadIdealProcessor,
  ThreadPriorityBoost,
  ThreadSetTlsArrayAddress,
  ThreadIsIoPending,
  ThreadHideFromDebugger,
  ThreadBreakOnTermination,
  MaxThreadInfoClass
}   THREADINFOCLASS;
typedef THREADINFOCLASS   ThreadInformationClass;

/*typedef struct _PROCESS_BASIC_INFORMATION 
{
  NTSTATUS ExitStatus;
  PPEB PebBaseAddress;
  KAFFINITY AffinityMask;
  KPRIORITY BasePriority;
  ULONG UniqueProcessId;
  ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION *PPROCESS_BASIC_INFORMATION;
*/
typedef struct _PROCESS_BASIC_INFORMATION
{
	PVOID Reserved1;
	PPEB PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;


 typedef struct _NT_FILETIME 
 { 
    DWORD dwLowDateTime; 
    DWORD dwHighDateTime; 
 }NT_FILETIME;

  typedef struct _PROCESS_INFO
  {
    DWORD         dwOffset; // an ofset to the next Process structure // 00h
    DWORD         dwThreadCount;                                      // 04h
    DWORD         dwUnknown1[6];                                       // 08h
    NT_FILETIME   ftCreationTime;                                     // 20h
    NT_FILETIME   ftUserTime;
    NT_FILETIME   ftKernelTime;
    UNICODE_STRING ProcessName;                                       // 38h
    DWORD         dwBasePriority;                                     // 40h
    DWORD         dwProcessID;                                        // 44h
    DWORD         dwParentProcessID;                                  // 48h
    DWORD         dwHandleCount;                                      // 4Ch
    DWORD         dwUnkown7;                                          // 50h
    DWORD         dwUnkown8;                                          // 54h
    DWORD         dwVirtualBytesPeak;
    DWORD         dwVirtualBytes;     //dwVirtualSize
    DWORD         dwPageFaultsCountPerSec;
    DWORD         dwWorkingSetPeak;   //PeakWorkingSetSize
    DWORD         dwWorkingSet;       //WorkingSetSize
    DWORD         dwPeekPagedPoolUsage;
    DWORD         dwPagedPool; // kbytes PagedPoolUsage
    DWORD         dwPeekNonPagedPoolUsage;
    DWORD         dwNonPagedPool; // kbytes NonPagedPoolUsage
    DWORD         dwPageFileBytesPeak;
    DWORD         dwPageFileBytes;
    DWORD         dwPrivateBytes;
    NT_FILETIME   ProcessorTime;
    DWORD         dwUnknown13;
    DWORD         dwUnknown14;
} PROCESS_INFO, *PPROCESS_INFO;              
typedef enum _SYSTEM_INFORMATION_CLASS
{
  SystemBasicInformation = 0,
  SystemProcessorInformation,
  SystemTimeZoneInformation,
  SystemTimeInformationInformation,
  SystemUnk4Information, 
  SystemProcessesInformation,
  SystemUnk6Information,
  SystemConfigurationInformation,
  SystemUnk8Information,
  SystemUnk9Information,
  SystemUnk10Information,
  SystemDriversInformation,
  SystemLoadImageInformation = 26,
  SystemUnloadImageInformation = 27,
  SystemLoadAndCallImageInformation = 38
} SYSTEM_INFORMATION_CLASS;
/*
typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;
*/

typedef struct _VM_COUNTERS {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} VM_COUNTERS;
typedef VM_COUNTERS *PVM_COUNTERS;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchCount;
	LONG State;
	LONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;


typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)



typedef struct _THREAD_INFO 
{ 
  NT_FILETIME   ftCreationTime; 
  DWORD         dwUnknown1; 
  DWORD         dwStartAddress; 
  DWORD         dwOwningPID; 
  DWORD         dwThreadID; 
  DWORD         dwCurrentPriority; 
  DWORD         dwBasePriority; 
  DWORD         dwContextSwitches; 
  DWORD         dwThreadState; 
  DWORD         dwThreadWaitReason; 
  DWORD         dwUnknown3; 
  DWORD         dwUnknown4; 
  DWORD         dwUnknown5; 
  DWORD         dwUnknown6; 
  DWORD         dwUnknown7; 
} THREAD_INFO, *PTHREAD_INFO; 

typedef long (__stdcall *PNTQUERYSYSTEMINFORMATION)
(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
 OUT PVOID SystemInformation, // pointer to buffer
 IN DWORD SystemInformationLength, // buffer size in bytes       
 OUT PDWORD LehgthReturned OPTIONAL // number of bytes written to the buffer
  	);
typedef LONG(__stdcall *PNTQUERYINFORMATIONPROCESS)(HANDLE , PROCESSINFOCLASS, PVOID, ULONG, PULONG);

typedef
NTSTATUS(WINAPI *PNTWOW64QUERY64INFORMATIONPROCESS)(HANDLE, PROCESSINFOCLASS,
	PVOID , UINT32 ProcessInformationLength,
	PULONG ReturnLength);


typedef LONG(__stdcall *PNTQUERYINFORMATIONTHREAD)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);

static PNTQUERYSYSTEMINFORMATION NtQuerySystemInformation = NULL;
static PNTQUERYINFORMATIONPROCESS NtQueryInformationProcess = NULL;
static PNTWOW64QUERY64INFORMATIONPROCESS NtWow64Query64InformationProcess = NULL;
static PNTQUERYINFORMATIONTHREAD NtQueryInformationThread = NULL;
//static PNTWOW64READVIRTUALMEMORY64 NtWow64ReadVirtualMemory64 = NULL;
PTHREAD_INFO 
GetThreadInfoPtr(
       PPROCESS_INFO pProcessInfo
       );

std::string GetProcessName(DWORD dwPid);



struct EmptyState
{
  
  EmptyState(DWORD dwThreadID)
  {
    this->dwThreadID = dwThreadID;
  }

  bool
  operator()()
  { 
    return ( dwThreadID != GetCurrentThreadId() );
  }
private:
  DWORD dwThreadID;
};

struct  SuspendPolicy
{
  SuspendPolicy(DWORD dwThreadID)
  {
    ThreadHandle = OpenThread(THREAD_ALL_ACCESS,false,dwThreadID); 
   // char tmp_[MAX_PATH];
  //  sprintf(tmp_,"ThreadHandle = %d\n",ThreadHandle);
  //  OutputDebugStringA(tmp_);     
 
  }
  bool operator ()()
  {
    if (!ThreadHandle)
      return (false); 
    return ( -1 != SuspendThread(
        ThreadHandle  
      ));
  }
  ~SuspendPolicy()
  {
    CloseHandle( ThreadHandle );
  }
private:
  HANDLE ThreadHandle;
};

struct  ResumePolicy
{
  ResumePolicy(DWORD dwThreadID)
  {
    ThreadHandle = OpenThread(THREAD_ALL_ACCESS,false,dwThreadID); 
  }
  bool operator ()()
  {
    if (!ThreadHandle)
      return (false); 
    return ( -1 != ResumeThread(
        ThreadHandle  
      ));
  }
  ~ResumePolicy()
  {
    CloseHandle( ThreadHandle );
  }
private:
  HANDLE ThreadHandle;
};


template
<
  typename SetStatePolicy,
  typename StateCmpPolicy
>
void 
manipulate_threads()
{
  char tmp_[MAX_PATH];
  enum{PROC_INFO_COUNT = 500};
  HINSTANCE hinst_ntdll;
  hinst_ntdll = GetModuleHandle("ntdll.dll");
  if (!hinst_ntdll) 
    hinst_ntdll=LoadLibrary("ntdll.dll"); 
  if (!hinst_ntdll)
    return ;  
  

  NtQuerySystemInformation= 
    reinterpret_cast<NTQUERYSYSTEMINFORMATION>( 
    GetProcAddress(hinst_ntdll,"NtQuerySystemInformation")
    );


  if (!NtQuerySystemInformation)
    return;
  
  DWORD SysInfoLen;
  unsigned long NtStatus = 0;
  std::vector<PROCESS_INFO> pid;
  pid.resize(PROC_INFO_COUNT);
	SysInfoLen = sizeof(PROCESS_INFO)*PROC_INFO_COUNT;


  NtStatus =
    NtQuerySystemInformation(SystemProcessesInformation,
       &pid[0],SysInfoLen,&SysInfoLen);

  sprintf(tmp_,"NtStatus == %d\n",NtStatus);
  OutputDebugStringA(tmp_);     
 
  PPROCESS_INFO mem_ptr_pid = &pid[0];
  while (true)
  {
//    sprintf(tmp_,"mem_ptr_pid->dwProcessID == %d\n",mem_ptr_pid->dwProcessID);
//    OutputDebugStringA(tmp_);     
    if (GetCurrentProcessId() == mem_ptr_pid->dwProcessID)
    {
 //     OutputDebugStringA("GetCurrentProcessId() == mem_ptr_pid->dwProcessID");     
      std::vector<THREAD_INFO> ThreadInfo;
      ThreadInfo.resize(mem_ptr_pid->dwThreadCount);
 			memcpy   (
          &ThreadInfo[0],
          GetThreadInfoPtr(mem_ptr_pid),
          sizeof(THREAD_INFO)*mem_ptr_pid->dwThreadCount
         );
      for (size_t i = 0; i < mem_ptr_pid->dwThreadCount; ++i)
      {
//        sprintf(tmp_,"i = %d : threadId = %X\n",i,ThreadInfo[i].dwThreadID);
//        OutputDebugStringA(tmp_);     
        SetStatePolicy SetPolicy( ThreadInfo[i].dwThreadID );
        StateCmpPolicy StateCmpPolicy ( ThreadInfo[i].dwThreadID );
        if (StateCmpPolicy())
        {
          if (SetPolicy())
          {
            OutputDebugStringA("Set Policy OK!\n");
          }
        }
			}
    }
    if (!mem_ptr_pid->dwOffset)
      break;
    mem_ptr_pid =
      (
        reinterpret_cast<PPROCESS_INFO>(
          (reinterpret_cast< char* > (mem_ptr_pid) + mem_ptr_pid->dwOffset)
         )
      );
  }
}


::std::string 
GetProcessName( void );

struct _Thread
{
  DWORD Tid;
  LONG State;
  LONG BasePriority;
  LONG Priority;
  LARGE_INTEGER KernelTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER CreateTime;
  ::std::string hash;
  _Thread(
     DWORD Tid_,   
	 LARGE_INTEGER _KernelTime,
     LARGE_INTEGER _UserTime,
     LARGE_INTEGER _CreateTime,  
	 LONG State_,LONG BasePriority_,
	 LONG Priority_,::std::string hash_)
	  :State(State_),BasePriority(BasePriority_),Priority(Priority_),
	  KernelTime(_KernelTime),UserTime(_UserTime),CreateTime(_CreateTime),
	  hash(hash_),Tid(Tid_)
  {};
};


struct _Process 
{	 
  ::std::string hash_;
  ::std::string ProcessName;
  ULONG Uid;
  ::std::vector<_Thread>  Thread_Seq;
};


template
<
	typename T
>
struct EmptyFunctor
{
  T& operator()(T& t)
  {
	return (t);
  }
};




#endif