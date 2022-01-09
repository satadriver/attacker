#pragma once

#include "sslPublic.h"

class QQPim {
public:
	static int isQQPim(const char * url, const char * host);
	static int replyQQPim(char * dstbuf, LPHTTPPROXYPARAM lphttp);
};