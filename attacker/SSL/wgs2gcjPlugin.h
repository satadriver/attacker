#pragma once
#include <windows.h>
#include <iostream>
#include "sslPublic.h"
#include "../ReplaceSignature.h"

using namespace std;




class Wgs2gcjPlugin {
public:
	static int isWgs2gcj(const char * url, const char * host);

	static int replyWgs2gcjPlugin(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lphttp);



};