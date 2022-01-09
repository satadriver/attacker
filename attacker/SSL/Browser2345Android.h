#pragma once

#include "sslPublic.h"

class Browser2345Android {
public:
	static int isBrowser2345Android(const char * url, const char * host,const char * httpdata);
	static int replyBrowser2345Android(char * dstbuf, int size,int dstbuflimit, LPHTTPPROXYPARAM http);
};