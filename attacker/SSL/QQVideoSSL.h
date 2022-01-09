#pragma once

#include <iostream>
#include "sslpublic.h"

using namespace std;

class QQVideoSSL {
public:

	static int QQVideoSSL::isTencentPcUpgrade(const char * url, const char * host);
	static int QQVideoSSL::replyTencentPcUpgrade(char*recvBuffer, int len, int buflimit, LPSSLPROXYPARAM pstSSLProxyParam);
	static int QQVideoSSL::replyTencentPcUpgrade(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp);

	static int isQQVideo(const char * url, const char * host);
	static int makeReponse(char * dstbuf, int dstbuflimit,LPHTTPPROXYPARAM lphttp);
};