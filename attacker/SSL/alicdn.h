#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"

using namespace std;




class AliCdn {
public:
	static int isAliCdnHead(const char * url, const char * host);
	static int AliCdn::makeHead(string filename, char * dstbuf, int dstbuflimit);
	static int makeHeadReply(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM ssl);

	static int AliCdn::isAliCdnRequest(const char * url, const char * host);
	static int AliCdn::makeRequestReply(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl);

	static int AliCdn::makeRedirection(char * lpbuf, int bufsize, int limit, LPSSLPROXYPARAM lpssl);

	static int AliCdn::makeRequestReply(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM http);
};
