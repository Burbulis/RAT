// processes.cpp: определяет точку входа для консольного приложения.
//

#include "stdafx.h"
#include "proc_mini_lib.h"
#include "combine.h"

int main()
{
	GetProcessSeq::PList list;
	GetProcessSeq gps;
	gps.get(list);
	for (size_t i = 0; i < list.size(); ++i) {
		GetProcessBasicInfo gpbi(list[i].Uid);
	}

    return 0;
}

