#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"

using namespace std;




class QQigtimg {
public:
	static int isQQigtimg(string url, string host);

	static int replyQQigtimg(char*recvBuffer,int len, int buflimit, LPSSLPROXYPARAM pstSSLProxyParam);

};