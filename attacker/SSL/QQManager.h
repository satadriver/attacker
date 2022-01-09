#pragma once
#include <iostream>
#include "sslpublic.h"

using namespace std;

class QQManager {
public:
	static int isQQManager(const char * url, const char * host);
	static int replayQQManager(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lphttp);

	static int QQManager::replayQQManager(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl);
};