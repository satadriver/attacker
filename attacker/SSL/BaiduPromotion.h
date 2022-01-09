#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"

using namespace std;




class BaiduPromotion {
public:
	static int isBaiduAd(string url, string host);

	static int replyBaiduAd(char*recvBuffer, int len, int buflimit, string username);

};