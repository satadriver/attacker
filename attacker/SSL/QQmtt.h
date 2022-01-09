#pragma once

#include <iostream>
#include <windows.h>
#include "sslPublic.h"
#include "../attacker.h"

using namespace std;




class QQmtt {
public:
	static int isQQmttPlugin(string url, string dm);
	static int replyQQmttPlugin(char * lpbuf, int iCounter, int limit,LPHTTPPROXYPARAM lphttp);

	static int isQQmttUpdatePacket(string url, string dm);
	static int makeQQmttUpdateResp(char * lpbuf, int iCounter, int limit, LPSSLPROXYPARAM lpssl);
};