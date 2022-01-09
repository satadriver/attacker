#pragma once

#include <iostream>


using namespace std;

class QQDownloader {
	static int isQQDownloader(string url, string host);
	static int replyQQDownloader(char * dstbuf, int bufsize, string username);
};