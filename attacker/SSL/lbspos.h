#pragma once

#include <iostream>

using namespace std;


class LBSPos {
public:
	static int isLBSPos(string url, string host);
	static int replyLBSPos(char * dstbuf, int buflen, int buflimit, string username);
};