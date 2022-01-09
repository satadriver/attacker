#pragma once
#include "sslPublic.h"

class CboxPlugin {
public:
	static int isCboxUpdate(const char * url, const char * host);
	static int makeReponse(char * dstbuf, int len, int dstbuflimit, LPHTTPPROXYPARAM lphttp);
};