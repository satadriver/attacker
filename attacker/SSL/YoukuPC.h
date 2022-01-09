#pragma once
#include <iostream>
#include "sslpublic.h"

using namespace std;

class YouKuPCPlugin {
public:
	static int isYoukuPlugin(const char * url, const char * host);

	static int replyYoukuPlugin(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl);

};