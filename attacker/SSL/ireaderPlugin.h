#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"
#include "../ReplaceSignature.h"

using namespace std;




class IReaderPlugin {
public:
	static int isIReaderPlgin(const char * url, const char * host);

	static int replyIReaderPlgin(char * dstbuf, int dstbuflimit, string username);



};