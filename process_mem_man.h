#pragma once
#include <windows.h> 
#include <Psapi.h>
#include <vector>
#include <algorithm>
#include <string>
#include <list>
#include <typeinfo.h>
#include <mutex>
#include "auto_sync.h"
#include "proc_mini_lib.h"
//NtWow64ReadVirtualMemory64

typedef LONG(__stdcall *PNTWOW64READVIRTUALMEMORY64)(
	IN HANDLE ProcessHandle,
	IN PVOID64 BaseAddress,
	OUT PVOID Buffer,
	IN ULONG64 Size,
	OUT PULONG64 NumberOfBytesRead);

/*
typedef LONG(__stdcall *NtWow64QueryInformationProcess64) (
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	)
*/


namespace mem
{



 // static PNTWOW64READVIRTUALMEMORY64 NtWow64ReadVirtualMemory64 = NULL;
  template
	  <
	    typename t_ptr,
		typename t_size
	  >
	
  struct  Universal_Type
  {
    Universal_Type() {};
    Universal_Type(t_ptr _Ptr, t_size sz, size_t hash_code_) :Ptr(_Ptr), size_(sz),
      hash_code_type(hash_code_) {};
     
    t_ptr get_ptr(void)
      const
    {
      return (Ptr);
    }

    t_size get_sz(void)
      const
    {
      return (size_);
    }

  private:
	t_ptr Ptr;
    size_t hash_code_type;
    t_size size_;
  };



  struct _handle
  {
    _handle(DWORD _Access, DWORD Pid):_pid(Pid),_access(_Access)
    {  
      init();
    };

    void init()
    {
		HINSTANCE load_dll = NULL;
		load_dll = GetModuleHandle("ntdll.dll");
		if (!load_dll)
			load_dll = LoadLibrary("ntdll.dll");
		//if (!hinst_ntdll)
		//	return;
		NtWow64ReadVirtualMemory64 = reinterpret_cast<PNTWOW64READVIRTUALMEMORY64>(GetProcAddress(load_dll,"NtWow64ReadVirtualMemory64"));
	
      if (NULL != handle)
      {
        return;
      }
      handle = ::OpenProcess(_access, true, _pid);
    }

    _handle()
    {};

    ~_handle()
    {
    }

  protected:
    void destroy()
    {
      if (handle)
      {
        ::CloseHandle(handle);
      }
      handle = NULL;
    }

    static
    HANDLE get()
    {
      return (handle);
    }

	PNTWOW64READVIRTUALMEMORY64 NtWow64ReadVirtualMemory64;

  private:
	 
    DWORD _pid;
    DWORD _access;
    static HANDLE handle;
  };
  
  class process_mem_man
  {
  public:
    process_mem_man();
  protected:
    virtual ULONG _rd() =0;
    virtual ~process_mem_man() {};
  };


   struct protector:
     public process_mem_man, protected _handle
  {
    protector(const Universal_Type<PVOID64,ULONG64>& Ut)
    {
      this->Ut = Ut;
      _process = get();
    //  _old_protect = 0;
    //  VirtualProtectEx(get() , Ut.get_ptr(), Ut.get_sz(), PAGE_EXECUTE_READ, &_old_protect);
    }


    template
      <
      typename T
      >
     ULONG
     read(T *_buffer)
    {
 
      AUTO_MUTEX(this);
      size_t readed = _rd_();
      //buffer.resize(readed);
      RtlCopyMemory(_buffer, &buffer[0], readed);
      return (readed);
    }
    ~protector()
    {
    }

  private:

  ULONG _rd()
    {
      AUTO_MUTEX(this);
      SIZE_T Readed = 0;
      buffer.resize(Ut.get_sz());
      ReadProcessMemory(get(), Ut.get_ptr(), &buffer[0], Ut.get_sz(), &Readed);
      reset();
      return (Readed);
    }
  
  ULONG _rd_()
  {
	  AUTO_MUTEX(this);
	 
	  SIZE_T Readed = 0;
	  HINSTANCE load_dll = NULL;
	  load_dll = GetModuleHandle("ntdll.dll");
	  if (!load_dll)
		  load_dll = LoadLibrary("ntdll.dll");
	  //if (!hinst_ntdll)
	  //	return;
	  NtWow64ReadVirtualMemory64 = reinterpret_cast<PNTWOW64READVIRTUALMEMORY64>(GetProcAddress(load_dll, "NtWow64ReadVirtualMemory64"));
	  //buffer.resize(Ut.get_sz());
	  //ReadProcessMemory(get(), Ut.get_ptr(), &buffer[0], Ut.get_sz(), &Readed);
	 
	//  HANDLE test = get();
	//  LONG result_ = NtWow64ReadVirtualMemory64(test, Ut.get_ptr(), &peb_, sizeof(peb_), &Readed);
	//  reset();
	  return ( static_cast<ULONG> (Readed));
  }

  protected:
    void reset()
    {
    
		// DWORD _protect = 0;
     // VirtualProtectEx(get(), Ut.get_ptr() /*_Address*/, Ut.get_sz(), _old_protect, &_protect);
    }

	HANDLE get()
	{
	  return (mem::_handle::get());
	}

    mem::Universal_Type<PVOID64 , ULONG64> Ut;
    //T *_Address;
    std::vector<char> buffer;
    HANDLE _process;
    DWORD _old_protect;
    size_t _sz;
  };

  template
    <
    typename T,
    typename storage = mem::protector//<T>
    >
  struct PreObjectList
  {
    //virtual storage* Create(T *Address) = 0;
    virtual storage* Create(const mem::Universal_Type< PVOID64, ULONG64 >& ut) = 0;
  };

 
  template
    <
    typename T,
    typename storage = mem::protector
    >
    struct ObjectList :public PreObjectList<T>
  {
    std::mutex obj_mutex;
    typedef storage* storage_ptr;
    typedef mem::protector storage;

    ObjectList()
    {

    }

    ~ObjectList()
    {
      // AUTO_MUTEX(this);

      clear();
    }


    storage* Create(const mem::Universal_Type< PVOID64, ULONG64 >& ut)
    {
      std::lock_guard<std::mutex> lock(obj_mutex);
      storage* object = new storage(ut);
      storage_seq.push_back(object);
      return (object);
    }

    void
      clear()
    {
      std::lock_guard<std::mutex> lock(obj_mutex);
      std::list<storage *>::iterator first = storage_seq.begin();
      std::list<storage *>::iterator last = storage_seq.end();
      while (first != last)
      {
        storage *obj = (*first);
        delete obj;
        ++first;
      }
      storage_seq.clear();
    }
  private:
    std::list<protector *> storage_seq;
  };

  template
    <
      typename T
    >
  mem::Universal_Type<PVOID64, ULONG64>
  CreatorUniversalType(T *Addr_src)
  {
    mem::Universal_Type<PVOID64, ULONG64> ut(reinterpret_cast<PVOID64>(Addr_src), sizeof(Addr_src), typeid(Addr_src).hash_code());
    return (ut);
  }

  template
    <
    typename T
    >
   mem::Universal_Type<PVOID64, ULONG64>
  CreatorUniversalType(T *Addr_src,size_t sz_)
  {
    mem::Universal_Type<PVOID64, ULONG64> ut(reinterpret_cast<PVOID64>(Addr_src), sz_, typeid(T).hash_code());
    return (ut);
  }


  template
	  <
      typename T,
	  typename lister  = mem::ObjectList<mem::Universal_Type<T,UINT64>>,
      typename binder_ = mem::_handle
	  >
	  struct read_a
	  {
		typedef T t_;
		typedef lister lister_t;
		typedef binder_ binder_t;
	
		ULONG64 rx(lister *list,PVOID64 Addr_src/*,T *Addr_dst*/)
		{
			
		  object = list->Create(CreatorUniversalType(Addr_src));
		  return (/*object->read(Addr_dst)*/0);

		
		}
	  private:
		typename  lister::storage *object;
	  };
/*

    Overload for Buffered functions

*/
  template
	  <
      typename T,
      typename lister  = mem::ObjectList<T>,
      typename binder_ = mem::_handle
	  >
	  struct read_b
	  {
		typedef T t_;
		typedef lister lister_t;
		typedef binder_ binder_t;
	
  	    read_b(lister *list, T *Addr_src, T *Addr_dst,size_t sz_)
		{
			/*lister::storage **/
			object = list->Create(CreatorUniversalType(Addr_src,sz_));
			readed = object->read(Addr_dst);
		}

		size_t size(void)
		{
			return(readed);
		}

	  private:
		typename lister::storage *object;
};
 }