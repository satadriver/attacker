#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"
#include <string.h>

using namespace std;




class Youku {
public:
	static int isYouku(string url, string host);

	static int isYoukuVod(string url, string host);
	static int Youku::replyYoukuVod(char*recvBuffer, int len, int buflimit, LPSSLPROXYPARAM pstSSLProxyParam);

	static int replyYouku(char*recvBuffer, int len, int buflimit, LPSSLPROXYPARAM pstSSLProxyParam);

	static int isYoukuApk(string url, string host);
	static int replyYoukuApk(char *, int, int, LPHTTPPROXYPARAM,const char *httpdata);

};