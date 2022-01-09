#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"

using namespace std;




class BaiduLocation {
public:
	static int isBaiduLoc(string url, string host);

	static int replyBaiduLoc(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp);

};