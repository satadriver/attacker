#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"

using namespace std;

class QQTencentNews {
public:
	static int isQQNews(string url, string host);
	static int replyQQNews(char*lpbuffer, int len, int buflimit, LPHTTPPROXYPARAM http);
};