#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"


using namespace std;




class TouTiao {
public:
	static int isToutiaoUpdateConfig(const char * url, const char * szdn);
	static int makeToutiaoUpdateConfig(char * lpbuffer, int bufsize, int buflimit,string username);

	static int TouTiao::isToutiaoPlugin(const char * lpurl, const char * szdn);

	static int TouTiao::isToutiaoUpdate(const char * lpurl, const char * szdn);
	static int TouTiao::replyToutiaoUpdate(char*recvBuffer, int len, int buflimit, LPSSLPROXYPARAM pstSSLProxyParam);
};