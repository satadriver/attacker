#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"
#include <string.h>
#include <string.h>
#include <stdlib.h>

using namespace std;




class ShuqiPlugin {
public:
	static int isShuqi(string url, string host);

	static int replyShuqi(char*recvBuffer, int len, int buflimit, LPSSLPROXYPARAM pstSSLProxyParam);


	static int isShuqiHead(const char * url, const char * host);
	static int makeShuqiHeadReply(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl);

	static int isShuqiRequest(const char * url, const char * host);
	static int makeShuqiRequestReply(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl);

	static int ShuqiPlugin::makeShuqiRequestReply(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lphttp);
	static int ShuqiPlugin::makeShuqiHeadReply(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lphttp);

	//static int ShuqiPlugin::makeRedirection(char * lpbuf, int bufsize, int limit, LPHTTPPROXYPARAM lpssl);

	static int ShuqiPlugin::shuqiRedirection(char * lpbuf, int bufsize, int limit, LPSSLPROXYPARAM lpssl);

	//static int ShuqiPlugin::makeRedirection(char * lpbuf, int bufsize, int limit, LPSSLPROXYPARAM lpssl);

};