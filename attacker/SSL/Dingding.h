#pragma once


#include <iostream>
#include "sslPublic.h"

using namespace std;

class DingDing {
public:
	static int DingDing::sendPlugin(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl);
	static int DingDing::isDingdingPluginUpdate(const char *url, const char * host);
	static int isDingdingUpdate(const char * url, const char * host);
	static int makeReponse( char * dstbuf, int len,int dstbuflimit, LPSSLPROXYPARAM pstSSLProxyParam);
};