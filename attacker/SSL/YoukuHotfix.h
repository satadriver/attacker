#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"

using namespace std;




class YoukuHotfix {
public:
	static int isYoukuHotfix(const char * url, const char * host);

	static int makeRequestReply(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl);


};
