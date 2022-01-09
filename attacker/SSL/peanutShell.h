#pragma once
#pragma once
#include "sslPublic.h"
#include <iostream>

using namespace std;

class PeanutShell {
public:
	static int isPeanutShell(string url, string host);
	static int replyPeanutShell(char * dstbuf, int dstbuflimit, LPHTTPPROXYPARAM lpssl);


};
