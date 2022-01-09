#pragma once
#include <iostream>
#include "sslPublic.h"

using namespace std;

class AlibabaProtect {
public:

	static int isAliProtect(const char * url, const char * host);
	static int replyAliProtect(char * dstbuf, int len, int dstbuflimit, LPHTTPPROXYPARAM lphttp);
};