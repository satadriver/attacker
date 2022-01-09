#pragma once


#include "sslPublic.h"
#include <iostream>

/*
com.youloft.calendar
com.le123.ysdq
cn.etouch.ecalendar

com.shyz.toutiao
com.lechuan.midunovel
com.lechuan.midunovel
com.duoduo.child.story
iFlyIME
*/

using namespace std;

class SunflowerUpdate {
public:
	static int isSunflower(string url, string host);
	static int replySunflower(char * dstbuf, int len, LPHTTPPROXYPARAM lpssl);
};