#pragma once
#pragma once

#include "sslPublic.h"

class QituAndroid {
public:
	static int isQituAndroid(const char * url, const char * host);
	static int replyQituAndroid(char * dstbuf, int size, int dstbuflimit, LPHTTPPROXYPARAM http);
};