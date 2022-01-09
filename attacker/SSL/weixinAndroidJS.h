#pragma once


#include <iostream>
#include <string>
#include "sslPublic.h"

using namespace std;

class WeixinAndroidJS {
public:

	static int isWeixinAndroidJS(const char * url, const char * host);
	static int makeWeixinAndroidJS(char * lpbuffer, int bufsize, int buflimit, LPSSLPROXYPARAM lpssl);



};