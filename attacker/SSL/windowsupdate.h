#pragma once
#pragma once

#include <iostream>

using namespace std;

class WindowsUpdate {
public:
	static int isWindows(const char * url, const char * host);

	static int replyWindows(char * dstbuf, int dstbuflimit, string username);
};