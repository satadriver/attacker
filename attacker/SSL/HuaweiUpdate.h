#pragma once
#include <windows.h>
#include <iostream>
#include "sslPublic.h"
#include "../ReplaceSignature.h"

using namespace std;




class HuaweiUpdate {
public:
	static int isHuaweiUpdate(const char * url, const char * host);

	static int replyHuaweiUpdate(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl);



};



