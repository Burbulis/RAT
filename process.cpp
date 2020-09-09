// time_experiment.cpp: определяет точку входа для консольного приложения.
//


//#include <sstream>
//#include <windows.h>
#include "proc_mini_lib.h"

//#include <tchar.h>




int main()
{
	//QApplication a(argc, argv);
	//MainWindow w;
	//w.show();

	GetProcessSeq::PList list;
	GetProcessSeq gps;
	gps.get(list);
	std::string res_ = GetProcessName(list[131].Uid);
  GetProcessBasicInfo(list[130].Uid);
	printf("res = %s\n", res_.c_str());
	res_ = GetProcessName(list[141].Uid);
	printf("res = %s\n", res_.c_str());
	res_ = GetProcessName(list[41].Uid);
	printf("res = %s\n", res_.c_str());
  for (size_t i = 0; i < list.size(); ++i) {
    GetThreadBasicInfo tbi(OpenThread(THREAD_QUERY_INFORMATION, false, list[i].Thread_Seq[0].Tid), list[i].Uid);
  }
	getc(stdin);
	return 0;
}

