#pragma once

#include <iostream>

using namespace std;

class WireSharkUpdate {
public:
	static int isWireshark(const char * url, const char * host);

	static int replyWireshark(char * dstbuf, int dstbuflimit, string username);
};