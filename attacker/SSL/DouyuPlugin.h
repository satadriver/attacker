#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"
#include "../ReplaceSignature.h"

using namespace std;




class DouyuPlugin{
public:
	static int isDouyu(const char * url, const char * host);

	static int makeDouyuPluginReply(char * dstbuf, int dstbuflimit, string username);



};
