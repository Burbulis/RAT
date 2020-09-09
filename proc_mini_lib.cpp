
#include "proc_mini_lib.h"

//ern PNTQUERYINFORMATIONPROCESS NtQuerySystemInformation;
//PNTQUERYINFORMATIONPROCESS NtQueryInformationProcess = NULL;

PTHREAD_INFO 
GetThreadInfoPtr(
       PPROCESS_INFO pProcessInfo
       )
{
	PTHREAD_INFO pThreadInfo = NULL; 
	OSVERSIONINFOEX osvi;
	BOOL bOsVersionInfoEx;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if( !(bOsVersionInfoEx = GetVersionEx ((OSVERSIONINFO *) &osvi)) )
	{
		osvi.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
		if (! GetVersionEx ( (OSVERSIONINFO *) &osvi) ) 
			return pThreadInfo;
	}
	if (osvi.dwPlatformId == VER_PLATFORM_WIN32_NT){
		if ( osvi.dwMajorVersion <= 4 )
			pThreadInfo = (PTHREAD_INFO) ((char*)pProcessInfo + sizeof(PROCESS_INFO)); 
		if ( osvi.dwMajorVersion == 5)
			pThreadInfo = (PTHREAD_INFO) ((char*)pProcessInfo + sizeof(PROCESS_INFO) + sizeof(DWORD)*12); 
	}
	return pThreadInfo; 
}
/*
PVOID
GetModuleBase(HANDLE prc_hndl_,std::string mod_name)
{
 /* HINSTANCE  hinst_ntdll = GetModuleHandle("ntdll.dll");
  if (!hinst_ntdll) 
    hinst_ntdll=LoadLibrary("ntdll.dll"); 
  if (!hinst_ntdll)
    return (NULL);  

  NtQueryInformationProcess = 
    reinterpret_cast<PNTQUERYINFORMATIONPROCESS> (GetProcAddress(hinst_ntdll,"NtQueryInformationProcess"));
  ULONG   RLength;
  PROCESS_BASIC_INFORMATION  ProcessInfo;
     NtQueryInformationProcess(prc_hndl_ , ProcessBasicInformation, 
                             reinterpret_cast<PVOID>(&ProcessInfo), 
                             sizeof(PROCESS_BASIC_INFORMATION), 
                             &RLength
                );	

  PEB _peb;
  PROCESS_PARAMETERS    pp;
  ULONG Readed;
  ReadProcessMemory(prc_hndl_,ProcessInfo.PebBaseAddress,&_peb,sizeof(PEB),&Readed);
	ReadProcessMemory(prc_hndl_,_peb.ProcessParameters,&pp,sizeof(PROCESS_PARAMETERS),&Readed);
	PEB_LDR_DATA LdrData;
 	LDR_MODULE head,crt;
  ReadProcessMemory( prc_hndl_,_peb.LoaderData,&LdrData,sizeof(PEB_LDR_DATA),&Readed);
	ReadProcessMemory( prc_hndl_,LdrData.InLoadOrderModuleList.Flink,&head,sizeof(LDR_MODULE),&Readed);
	crt.InLoadOrderModuleList.Flink = head.InLoadOrderModuleList.Flink;
	while ( crt.InLoadOrderModuleList.Flink!= LdrData.InLoadOrderModuleList.Blink)
  {
    char tmp_[MAX_PATH];
    sprintf(tmp_,"crt.InLoadOrderModuleList.Flink == %X",crt.InLoadOrderModuleList.Flink);
    OutputDebugStringA(tmp_);     	
    if (NULL == crt.InLoadOrderModuleList.Flink)
      break;
    ReadProcessMemory(prc_hndl_,
          crt.InLoadOrderModuleList.Flink,
          &crt,sizeof(LDR_MODULE),&Readed);
  	WCHAR wstrFullDllName[MAX_PATH];
  	ReadProcessMemory(prc_hndl_,
      crt.BaseDllName.Buffer,wstrFullDllName,
      crt.FullDllName.MaximumLength,
      &Readed);
  //  sprintf(tmp_,"%X::%ws",crt.BaseAddress,wstrFullDllName);
  //  std::string tmp_s(tmp_);
  //  OutputDebugStringA(tmp_);     	
	}*/
 //   return (crt.BaseAddress);
//}

std::string 
GetProcessName( void )
{
  return (GetProcessName(GetCurrentProcessId()));
}



std::string GetProcessName(DWORD dwPid)
{
 // HANDLE hProcs;
 // HANDLE hHeap = 0;
  std::string ReturnValue("");
  NTSTATUS NtStatus;
  std::vector<char>  ProcessInfo;
  ULONG                      RLength;
  DWORD Readed;
  PEB _peb;
  PROCESS_PARAMETERS    pp;
  char *prcName;

  ULONG size = 1000;
  ProcessInfo.resize(size);

  memset(&ProcessInfo[0], 0, size);
  size = 24;
  HMODULE hinst_ntdll = LoadLibraryW(L"ntdll.dll");
  if (!hinst_ntdll)
    return (ReturnValue);  

  NtQueryInformationProcess = 
    reinterpret_cast<PNTQUERYINFORMATIONPROCESS>( GetProcAddress(hinst_ntdll,"ZwQueryInformationProcess") );

    
  if (!NtQueryInformationProcess) 
	  return (ReturnValue);	

  // Tokenizer tokenizer_;
  // tokenizer_.enable();
   HANDLE hProcs = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | READ_CONTROL,FALSE , dwPid );
   if (!hProcs)
   {
	   
	   return ("ERROR");
   }
 

  RLength = 0;
  NtStatus = NtQueryInformationProcess(hProcs , ProcessBasicInformation,
		                                         reinterpret_cast<PVOID>(&ProcessInfo[0]),
					                             size, 
					                             &RLength  );	
	if (NtStatus != STATUS_SUCCESS)
      return ("ERROR_SZ_MISMACH");
 // PEBx64 *peb = reinterpret_cast<PEBx64 *>(&ProcessInfo[0]);
	//if (!IsBadReadPtr(ProcessInfo, reinterpret_cast<UINT_PTR>(&dwSize)))
	//{
	////	printf("processinfo read access failure");
	//}
	printf("NtStatus = %d\n", NtStatus);


	CloseHandle(hProcs);
  return (ReturnValue);

}


/*HMODULE
get_mod_handle(HANDLE prc_hndl_,std::string mod_name)
{
  DWORD needed_ = 0;
  EnumProcessModules(prc_hndl_,NULL,
      NULL,&needed_);
  DWORD sz_ = needed_;
  std::vector<HMODULE> hmd_seq;
  hmd_seq.resize(needed_ / sizeof(HMODULE));
  EnumProcessModules( prc_hndl_ , &hmd_seq[0] ,
      sz_ ,&needed_ );
  for (size_t i = 0 ;
       i < hmd_seq.size() ;
       ++i)
  { 
    char mod_name_[MAX_PATH];
    memset(mod_name_,0,MAX_PATH);
    GetModuleFileNameExA(prc_hndl_,
        hmd_seq[i],mod_name_,MAX_PATH);
    std::string mod_name_str(mod_name_);
    std::transform( 
      &mod_name_str[0],
      &mod_name_str
      [
         mod_name_str.length()
      ],
      &mod_name_str[0],
      toupper);
    std::transform( 
      &mod_name[0],
      &mod_name
      [
         mod_name.length()
      ],
      &mod_name[0],
      toupper);
    char tmp_[MAX_PATH];
    sprintf(tmp_,"ModName == %s : Handle = %X\n",mod_name_str.c_str(),hmd_seq[i]);
    OutputDebugStringA(tmp_); 
    if (std::string::npos != mod_name.find(mod_name_str))
    {
      return ( hmd_seq[i] );
    }
  }
  return (NULL);
}               */
