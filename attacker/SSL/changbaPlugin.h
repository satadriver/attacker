#pragma once


#include <windows.h>
#include <iostream>
#include "sslPublic.h"
#include "../ReplaceSignature.h"

using namespace std;




class ChangBaPlugin {
public:
	static int isChangba(const char * url, const char * host);

	static int replyChangbaPlugin(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lpssl);
};
