#pragma once
#include <iostream>
#include "sslpublic.h"

using namespace std;


class NetEaseNewsUpdate {
public:
	static int isNeteaseNews(string url, string host);
	static int NetEaseNewsUpdate::replyNetEaseNews(char * dstbuf, int buflen, int buflimit, LPHTTPPROXYPARAM lphttp);
};