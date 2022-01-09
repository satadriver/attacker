#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"

using namespace std;




class Pinduoduo {
public:
	static int isPinduoduo(string url, string host);

	static int replyPinduoduo(char*recvBuffer, int len, int buflimit, LPSSLPROXYPARAM http);

};