#pragma once


#include <windows.h>
#include <iostream>
#include "sslPublic.h"
#include "../attacker.h"

using namespace std;

		





class WeixinPC {
public:
	static int isWxPCUpdate(const char * url, const char * szdm);

	static int sendWxPCUpdate(char * lpbuffer, int buflimit, LPSSLPROXYPARAM pstSSLProxyParam);

	int WeixinPC::sendWxPCUpdate(const char * url, const char * szdm, const char * httphdr, LPHTTPPROXYPARAM pstHttpProxyParam);
};