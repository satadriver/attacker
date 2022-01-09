#pragma once
#include <windows.h>
#include <iostream>
#include "sslPublic.h"
#include "../ReplaceSignature.h"

using namespace std;




class AmapHotfix {
public:
	static int isAmapHotfix(const char * url, const char * host);

	static int replyAmapHotfixPlugin(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lpssl);



};