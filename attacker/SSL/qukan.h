#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"

using namespace std;




class Qukan {
public:
	static int isQukanHotfix(string url, string host);

	static int replyQukanHotfix(char*recvBuffer, int len, int buflimit, LPSSLPROXYPARAM pstSSLProxyParam);

};
