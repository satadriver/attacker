#pragma once

#include <iostream>

using namespace std;


class ZHWNL {
public:
	static int isZhwnl(string url, string host);
	static int replyZhwnl(char * dstbuf, int buflen, int buflimit, string username);
};