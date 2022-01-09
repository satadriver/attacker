
#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"
#include "../ReplaceSignature.h"

using namespace std;




class MiaoPaiUpdate:public ReplaceSignature {
public:
	static int isMiaoPai(const char * url, const char * host);

	static int makeRequestReply(char * dstbuf, int dstbuflimit, string username);

	int prepareRespData(unsigned long ulIP, string filepath, string filename);


};