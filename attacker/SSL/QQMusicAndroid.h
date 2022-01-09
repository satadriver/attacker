#pragma once

#include <iostream>
#include <windows.h>
#include "sslPublic.h"
#include "../attacker.h"

using namespace std;




class QQMusicAndroid {
public:
	static int isQQMusicUpdatePacket(string url, string dm);
	static int makeQQMusicUpdateResp(char * lpbuf, int iCounter, int limit, LPHTTPPROXYPARAM lphttp);
};