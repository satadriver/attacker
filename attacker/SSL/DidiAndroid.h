#pragma once



#include <windows.h>
#include <iostream>
#include "sslPublic.h"


using namespace std;




class DidiAndroid {
public:
	static int isDidi(const char * url, const char * host);

	static int replyDidi(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl);
};