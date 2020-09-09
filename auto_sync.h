#ifndef AUTO_SYNC
#define AUTO_SYNC

#include <stdio.h>
#include <windows.h>
#include <typeinfo>
#include <string>
namespace sync
{
#define SYNC_TIMEOUT 160000

#ifdef SYNC_TIMEOUT
  class sync_exceptions
  { 
  public:
    sync_exceptions
      (unsigned long timeout)
      :timeout_(timeout){};
    unsigned long 
    what()
    {
      return (timeout_);
    }
    private:
     unsigned long timeout_;   
  };
#endif

#ifndef SYNC_TIMEOUT

  class auto_sync
  { 
  private:
    auto_sync(auto_sync&);
    auto_sync &operator= (auto_sync&);
  	HANDLE mutex_;
  public:
    auto_sync(std::string name_)
    {
	    mutex_ = CreateMutex(NULL , FALSE , name_.c_str()  );
	    WaitForSingleObject( mutex_  , INFINITE  );
    }
  	~auto_sync()
    {
      ReleaseMutex( mutex_  );
      CloseHandle( mutex_ );
    }
  };
#define AUTO_MUTEX(CLASS_THIS_) \
    sync::auto_sync auto_mutex( typeid(CLASS_THIS_).name() );

#endif

#ifdef SYNC_TIMEOUT
  class auto_mutex_timeout
  {
  private:
    auto_mutex_timeout(auto_mutex_timeout&);
    auto_mutex_timeout &operator= (auto_mutex_timeout&);
  	HANDLE mutex_;
  public:
    auto_mutex_timeout(std::string name_)
    {
	    mutex_ = CreateMutex(NULL , FALSE , name_.c_str()  );
	    DWORD wait_result =WaitForSingleObject( mutex_  , SYNC_TIMEOUT  );
      if (WAIT_OBJECT_0 != wait_result)
      {
        sync_exceptions s_excpt( SYNC_TIMEOUT );
        throw (s_excpt);
      }
    }
  	~auto_mutex_timeout()
    {
      ReleaseMutex( mutex_  );
      CloseHandle( mutex_ );
    }
  };
};
#define AUTO_MUTEX(CLASS_THIS_) \
    sync::auto_mutex_timeout auto_mutex( typeid(CLASS_THIS_).name() );

#endif

#endif
