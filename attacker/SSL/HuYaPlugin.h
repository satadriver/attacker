#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"
#include "../ReplaceSignature.h"

using namespace std;




class HuYaPlugin {
public:
	static int isHuya(const char * url, const char * host);

	static int makeHuyaPluginReply(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl);



};
