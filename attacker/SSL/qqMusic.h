#pragma once


#pragma once

#include <iostream>
#include "sslpublic.h"

using namespace std;

class QQMusic {
public:
	static int isQQMusic(const char * url, const char * host);
	static int sendPlugin(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl);
};