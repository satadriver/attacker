#pragma once


#include <windows.h>
#include <iostream>
#include "sslPublic.h"
#include "../ReplaceSignature.h"

using namespace std;




class KugouPlugin{
public:
	static int isKugouPlugin(const char * url, const char * host);

	static int replyKugouPlugin(char * dstbuf, int dstbuflimit, string username);




};