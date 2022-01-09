#pragma once
#include <iostream>

using namespace std;

class WechatPlugin {
public:
	static int iswechatPlugin(string url, string host);
	static int replyWechatPlugin(string username, char * dstbuf, int bufdatasize,int dstbuflimit);
};