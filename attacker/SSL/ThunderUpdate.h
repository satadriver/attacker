#pragma once

#include <iostream>
#include "sslpublic.h"

using namespace std;

class ThunderUpdate {
public:
	static int isThunder(const char * url, const char * host,const char * httphdr);
	static int replyThunder(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lpssl);
};