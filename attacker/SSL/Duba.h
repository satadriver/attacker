#pragma once



#include <iostream>
#include "sslPublic.h"

using namespace std;

class DuBa {
public:

	static int isDuba(const char * url, const char * host);
	static int replyDuba(char * dstbuf, int len, int dstbuflimit, LPHTTPPROXYPARAM lphttp);
};