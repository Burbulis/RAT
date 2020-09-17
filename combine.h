#pragma once
#include "proc_mini_lib.h"
#include "process_mem_man.h"

struct GetThreadBasicInfo
{
	GetThreadBasicInfo(HANDLE ThreadId, ULONG Pid) {
		if (!ThreadId)
			return;
		SIZE_T Readed = 0;
		THREAD_BASIC_INFORMATION tbi;
		PROCESS_PARAMETERS    pp;
		HINSTANCE hinst_ntdll = LoadLibraryA("ntdll.dll");
		NtQueryInformationThread = reinterpret_cast<PNTQUERYINFORMATIONTHREAD>(GetProcAddress(hinst_ntdll, "NtQueryInformationThread"));
		HANDLE proc_Handle = ::OpenProcess(PROCESS_ALL_ACCESS, true, Pid);
		mem::IS_WOW64 iw;
		//iw.
	
		//mem::protector<>
		DWORD NtStatus = NtQueryInformationThread(ThreadId, ThreadBasicInformation, &tbi, sizeof(tbi), 0);
		if (tbi.TebBaseAddress)
		{
			printf("NtStatus == %x\n,ThreadId = %x\n", NtStatus, ThreadId);
			printf("TebBaseAddress == %x\n", tbi.TebBaseAddress);
			TEB teb;
			PEB _peb;
			mem::_handle open(PROCESS_ALL_ACCESS, Pid);
			
		    //mem::read_a< PVOID64 >::lister_t *olx = new mem::read_a< PVOID64 >::lister_t;
		    
			
			mem::ObjectList< mem::Universal_Type<PVOID, ULONG> > *olx = new mem::ObjectList< mem::Universal_Type<PVOID, ULONG> >;
		//	mem::read_x86< PVOID >lister_t *olx = new mem::read_x86< PVOID >::lister_t;
		//	mem::read_x86< PVOID > r_a;
		//	r_a.rx( olx , tbi.TebBaseAddress , reinterpret_cast<PVOID>(teb.ProcessEnvironmentBlock) );
				//reinterpret_cast<PVOID64>(&_peb)
				

		
		}
		//  ::CloseHandle(proc_Handle);
	}

};

struct GetProcessBasicInfo:protected mem::_handle
{
	//HANDLE proc_Handle;
	GetProcessBasicInfo(DWORD Pid) {
		//proc_Handle = ::OpenProcess(PROCESS_ALL_ACCESS, true, Pid);
		HINSTANCE hinst_ntdll = LoadLibraryA("ntdll.dll");
		//	NtQueryInformationProcess = reinterpret_cast<PNTQUERYINFORMATIONPROCESS>(GetProcAddress(hinst_ntdll, "NtQueryInformationProcess"));
		NtWow64Query64InformationProcess = reinterpret_cast<PNTWOW64QUERY64INFORMATIONPROCESS>(GetProcAddress(hinst_ntdll, "NtWow64QueryInformationProcess64"));
		PBI_WOW64  ProcessInfo;
		//if (hinst_ntdll)
		//{
			//	PEBx64 _peb;
			PROCESS_PARAMETERS    pp;
			ULONG RLength;
			ULONG Readed = 0;

			//	std::vector<char>  ProcessInfo;
			//	ULONG size = 1000;
			//	ProcessInfo.resize(size);
			//	memset(&ProcessInfo[0], 0, size);
			mem::_handle open(PROCESS_VM_READ, Pid);
			//char *prcName = NULL;
			NTSTATUS NtStatus = NtWow64Query64InformationProcess(mem::_handle::get(),
				ProcessBasicInformation,
				reinterpret_cast<PVOID>(&ProcessInfo),
				sizeof(PBI_WOW64),
				&RLength);
			    if (STATUS_SUCCESS != NtStatus)
			      return ;
				PEBx _peb;
				//		PPBI_WOW64 pbi = reinterpret_cast<PPBI_WOW64>(&ProcessInfo[0]);
				/*PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | READ_CONTROL PROCESS_ALL_ACCESS*/
				
				//mem::ObjectList< mem::Universal_Type< PVOID, ULONG > > *ol = new mem::ObjectList< mem::Universal_Type< PPEBx, ULONG64> >;
				mem::IS_WOW64 iw;
				if (!iw.yes())
				{
				  mem::read_x86< VOID >::lister_t *ol = new mem::read_x86< VOID >::lister_t; 
				  mem::read_x86< VOID > x_;
				  x_.rx(ol,reinterpret_cast<PVOID>(ProcessInfo.PebBaseAddress),reinterpret_cast<PPEBx>(&_peb));
				}
				//PVOID64 _ppeb = reinterpret_cast<PVOID64>(&_peb);
				//mem::read(ol, reinterpret_cast<PPEB *>(ProcessInfo.PebBaseAddress), &teb);

				//mem::read(ol, reinterpret_cast<PPEBx>(ProcessInfo.PebBaseAddress), &_peb);
				
				//	mem::read(ol, reinterpret_cast<PROCESS_PARAMETERS *>(_peb.ProcessParameters), &pp);
				//ReadProcessMemory(proc_Handle, ProcessInfo.PebBaseAddress, &_peb, sizeof(PEB), &Readed);
				//ReadProcessMemory(proc_Handle, _peb.ProcessParameters, &pp, sizeof(PROCESS_PARAMETERS), &Readed);
				//	if (pp.CommandLine.Length > 1)
				//		prcName = new char[pp.CommandLine.Length];
				///	memset(prcName, 0, pp.CommandLine.Length);
				//	wchar_t CommandLine[MAX_PATH];
				//	ReadProcessMemory(proc_Handle, pp.CommandLine.Buffer, CommandLine, pp.CommandLine.Length, &Readed);
				//	size_t counter = 0;
				//	wcstombs_s(static_cast<size_t *>(&counter), prcName, pp.CommandLine.Length, reinterpret_cast<wchar_t *>(CommandLine),  MAX_PATH);
				//(prcName, CommandLine, pp.CommandLine.Length);
		//	}
		}
	};

struct GetProcessSeq
{
	typedef ::std::vector<_Process> PList;
	PList PrcLst;
	ULONG TotalOffset;
	::std::vector<char> Buffer_;
	DWORD Buffer_Size;
	DWORD NeedBufferSize;
	NTSTATUS status;

	GetProcessSeq()
	{
		reinit();
	}


	void
		get(PList &processes)
	{
		processes.clear();
		EmptyFunctor< _Process > fn;
		::std::transform(PrcLst.begin(), PrcLst.end(), std::back_inserter(processes), fn);
	}

	void
		reinit(void)
	{
		Buffer_Size = 224096;
		NeedBufferSize = 0;
		TotalOffset = 0;
		char *pBuffer = NULL;
		Buffer_.resize(Buffer_Size + 100);
		HMODULE hmod = LoadLibrary("ntdll.dll");
		NtQuerySystemInformation = reinterpret_cast<PNTQUERYSYSTEMINFORMATION>(GetProcAddress(hmod, "NtQuerySystemInformation"));
		pBuffer = &Buffer_[0];
		status = NtQuerySystemInformation(SystemProcessesInformation, pBuffer, Buffer_Size, &NeedBufferSize);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			Buffer_Size = (Buffer_Size * 2);
			Buffer_.resize(Buffer_Size);
			pBuffer = &Buffer_[0];
			NeedBufferSize = 0;
			status = NtQuerySystemInformation(SystemProcessesInformation, pBuffer, Buffer_Size, &NeedBufferSize);
			PSYSTEM_PROCESS_INFORMATION _p_info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(pBuffer);
			printf("Buffer length mismatch...\r\n");
			printf("need length = %d\n", NeedBufferSize);
		}

		if (STATUS_SUCCESS == status)
		{
			PSYSTEM_PROCESS_INFORMATION _p_info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(pBuffer);
			while (_p_info)
			{

				char tmp[MAX_PATH];
				memset(tmp, 0, MAX_PATH);
				WideCharToMultiByte(CP_ACP, 0, _p_info->ProcessName.Buffer,
					_p_info->ProcessName.Length, tmp, sizeof(tmp), NULL, NULL);
				_Process prc;

				prc.Uid = _p_info->ProcessId;
				prc.ProcessName = tmp;
				if (0 == prc.Uid)
				{
					prc.ProcessName = "idle";
				}
				memset(tmp, 0, MAX_PATH);
				sprintf_s(tmp, "%d", prc.Uid);
				std::string _tmp_str = std::string(tmp) + prc.ProcessName;
				prc.hash_ = "";//md5(_tmp_str);
				for (size_t i = 0; i < _p_info->ThreadCount; ++i)
					printf("kernel_time = %d\n", _p_info->Threads[i].KernelTime.u.LowPart);

				for (size_t i = 0; i < _p_info->ThreadCount; ++i)
				{

					prc.Thread_Seq.push_back(_Thread(_p_info->Threads[i].ClientId.UniqueThread,
						_p_info->Threads[i].KernelTime,
						_p_info->Threads[i].UserTime,
						_p_info->Threads[i].CreateTime,
						_p_info->Threads[i].State,
						_p_info->Threads[i].BasePriority,
						_p_info->Threads[i].Priority,
						prc.hash_));
				}
				PrcLst.push_back(prc);
				TotalOffset += _p_info->NextEntryDelta;
				pBuffer = &Buffer_[TotalOffset];
				_p_info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(pBuffer);
				if (!_p_info->NextEntryDelta)
					break;
			}
		}
	}



};