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
		    mem::ObjectList< mem::Universal_Type<PVOID64, ULONG64> > *olx = new mem::ObjectList< mem::Universal_Type<PVOID64, ULONG64> >;

			mem::read_a< PVOID64 > r_a;
			r_a.rx( olx ,reinterpret_cast< PVOID64 >(tbi.TebBaseAddress)); /*,reinterpret_cast<PVOID64>(teb.ProcessEnvironmentBlock));//,*/
				//reinterpret_cast<PVOID64>(&_peb)
				

		
				//mem::read(ol, reinterpret_cast<PPEB>(teb.ProcessEnvironmentBlock), &_peb);
				//mem::read(ol, reinterpret_cast<PROCESS_PARAMETERS *>(_peb.ProcessParameters), &pp);
			//	wchar_t *CommandLine = new wchar_t[pp.CommandLine.Length * 2];
			//	RtlZeroMemory(CommandLine, pp.CommandLine.Length * 2);
			//	if (mem::read(ol, reinterpret_cast<wchar_t *> (pp.CommandLine.Buffer), CommandLine, pp.CommandLine.Length * 2))
			//	{
			//		_asm {nop}
			//	}

		//		wchar_t *appName = new wchar_t[pp.ApplicationName.Length * 2];
		//		RtlZeroMemory(appName, pp.ApplicationName.Length * 2);
		//		size_t sz_ = pp.ApplicationName.Length * 2;
		//		mem::read(ol, reinterpret_cast<wchar_t *>(pp.ApplicationName.Buffer), appName, sz_);

			//}
			//delete ol;
			// ReadProcessMemory(proc_Handle, tbi.TebBaseAddress ,reinterpret_cast<PTEB>(&teb), sizeof(TEB), &Readed);
			// printf("PEB = %x\n", teb.ProcessEnvironmentBlock);
			// {
			// }
			// Readed = 0;
			/* ReadProcessMemory(proc_Handle, _peb.ProcessParameters, reinterpret_cast<PPROCESS_PARAMETERS>(&pp), sizeof(pp), &Readed);
			wchar_t *CommandLine = new wchar_t[pp.CommandLine.Length * 2];
			char *prcName = new char[pp.CommandLine.Length*2];
			RtlZeroMemory(prcName, pp.CommandLine.Length * 2);
			ReadProcessMemory(proc_Handle, pp.CommandLine.Buffer, CommandLine, pp.CommandLine.Length, &Readed);
			wcstombs(prcName, CommandLine, pp.CommandLine.Length);
			printf("prcName =%s\n", prcName);
			//pp.ApplicationName
			wchar_t *ApplicationName = new wchar_t[pp.ApplicationName.Length * 2];
			char *appName = new char[pp.ApplicationName.Length * 2];
			RtlZeroMemory(appName, pp.ApplicationName.Length * 2);
			ReadProcessMemory(proc_Handle, pp.ApplicationName.Buffer, ApplicationName, pp.ApplicationName.Length, &Readed);
			wcstombs(appName, ApplicationName, pp.ApplicationName.Length);
			printf("appName =%s\n", appName);
			printf("ImageBase = %x\n", _peb.ImageBaseAddress);
			std::vector< char > buffer;
			buffer.resize(100);
			VirtualProtectEx(proc_Handle, _peb.ImageBaseAddress, 100, PAGE_EXECUTE_READ, &_old_protect);
			ReadProcessMemory(proc_Handle, _peb.ImageBaseAddress, reinterpret_cast<LPVOID>(&buffer[0]), buffer.size(), &Readed);

			delete prcName;
			delete CommandLine;*/
		}
		//  ::CloseHandle(proc_Handle);
	}

};

struct GetProcessBasicInfo
{
	HANDLE proc_Handle;
	GetProcessBasicInfo(DWORD Pid) {
		proc_Handle = ::OpenProcess(PROCESS_ALL_ACCESS, true, Pid);
		HINSTANCE hinst_ntdll = LoadLibraryA("ntdll.dll");
		//	NtQueryInformationProcess = reinterpret_cast<PNTQUERYINFORMATIONPROCESS>(GetProcAddress(hinst_ntdll, "NtQueryInformationProcess"));
		NtWow64Query64InformationProcess = reinterpret_cast<PNTWOW64QUERY64INFORMATIONPROCESS>(GetProcAddress(hinst_ntdll, "NtWow64QueryInformationProcess64"));
		PBI_WOW64  ProcessInfo;
		if (hinst_ntdll)
		{
			//	PEBx64 _peb;
			PROCESS_PARAMETERS    pp;
			ULONG RLength;
			ULONG Readed = 0;

			//	std::vector<char>  ProcessInfo;
			//	ULONG size = 1000;
			//	ProcessInfo.resize(size);
			//	memset(&ProcessInfo[0], 0, size);

			char *prcName = NULL;
			NTSTATUS NtStatus = NtWow64Query64InformationProcess(proc_Handle,
				ProcessBasicInformation,
				reinterpret_cast<PVOID>(&ProcessInfo),
				sizeof(PBI_WOW64),
				&RLength);
			if (STATUS_SUCCESS == NtStatus)
			{
				PEBx _peb;
				//		PPBI_WOW64 pbi = reinterpret_cast<PPBI_WOW64>(&ProcessInfo[0]);
				mem::_handle open(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | READ_CONTROL, Pid);
				mem::ObjectList< mem::Universal_Type< PVOID64, ULONG64 > > *ol = new mem::ObjectList< mem::Universal_Type<PVOID64, ULONG64> >;
				//	mem::read(ol, reinterpret_cast<PPEB *>(ProcessInfo.PebBaseAddress), &teb);

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
			}
		}
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