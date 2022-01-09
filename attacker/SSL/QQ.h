#pragma once


#include <iostream>
#include "sslpublic.h"

using namespace std;

class QQBrowserPlugin {
public:
	static int isQQBrowserPlugin(const char * url, const char * host,const char * httphdr,const char * httpdata);
	static int sendQQBrowserPlugin(char * dstbuf, int dstbuflimit, string username);

	static int isQQClubApp(const char * url, const char * host);
	static int sendQQClubApp(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl);
};