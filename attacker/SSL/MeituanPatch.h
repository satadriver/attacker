#pragma once


#include <iostream>

using namespace std;


class MeiTuanPatch {
public:
	static int isMeiTuan(string url, string host);
	static int replyMeiTuan(char * dstbuf, int buflen, int buflimit, string username);
};

