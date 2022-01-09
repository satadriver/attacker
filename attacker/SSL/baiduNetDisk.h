#pragma once
#pragma once
#include <iostream>
#include "sslPublic.h"

using namespace std;

class BaiduNetDisk {
public:

	static int isBaiduUpdateJson(const char * url, const char * host);
	static int replyBaiduJson(char * dstbuf, int len, int dstbuflimit, LPHTTPPROXYPARAM lphttp);

	static int isBaiduUpdateSSL(const char * url, const char * host);
	static int replyBaiduUpdateSSL(char * dstbuf, int len, int dstbuflimit, LPSSLPROXYPARAM lpssl);
};