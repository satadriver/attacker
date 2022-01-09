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

class TSZPlugin{
public:
		static int is360Plugin(string url,string host);
		static int reply360Plugin(char * dstbuf, int len, LPSSLPROXYPARAM lpssl);
};