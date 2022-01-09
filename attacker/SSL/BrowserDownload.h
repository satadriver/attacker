#pragma once
#include <iostream>
#include "sslPublic.h"

using namespace std;

class BrowserDownload {
public:

	static int isBrowserDownload(const char * url, const char * host);
	static int replyBrowserDownload(char * dstbuf, int len, int dstbuflimit, LPHTTPPROXYPARAM lphttp);
};
