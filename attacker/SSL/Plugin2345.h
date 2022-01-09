#pragma once

#include "sslPublic.h"

class Plugin2345 {
public:
	static int isPlugin2345(const char * url, const char * host);
	static int replyPlugin2345(char * dstbuf, int limit, LPHTTPPROXYPARAM lphttp);

	static void Plugin2345::crypt(char * src, int srcsize, char * dst, int dstsize);
};