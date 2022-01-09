#pragma once


#include <windows.h>
#include <iostream>
#include "sslPublic.h"
#include "../ReplaceSignature.h"

using namespace std;




class KuaiyaUpdate {
public:
	static int isKuaiya(const char * url, const char * host);

	static int replyKuaiyaUpdate(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl);
};

