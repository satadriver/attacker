#pragma once


#include <windows.h>
#include <iostream>
#include "sslPublic.h"
#include <string.h>
#include "../Android/Jingdong.h"

using namespace std;




class JingDongPlugin {
public:
	static int isJingDong(string url, string host);

	static int replyJingDongPlugin(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp);

};