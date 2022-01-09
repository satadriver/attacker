#pragma once
#include <iostream>
#include "sslPublic.h"

using namespace std;

class BaofengPllugin {
public:

	static int isBaofengUpdate(const char * url, const char * host);
	static int replyBaofengPlugin(char * dstbuf, int len, int dstbuflimit, LPHTTPPROXYPARAM lphttp);
};