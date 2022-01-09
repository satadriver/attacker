#pragma once

#include <windows.h>
#include <iostream>
#include "sslPublic.h"
#include <string.h>
#include "../Android/QiyiVideo.h"

using namespace std;




class IqiyiPlugin{
public:
	static int isIqiyi(string url, string host);
	static int replyIqiyiPlugin(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp);

	static int replyIqiyiFw(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp);
	static int replyIqiyiSo(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp);

	static int replyIqiyiPcDll(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp);
	static int replyIqiyiPcDllIni(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp);

	static int replyIqiyiPcUpdateInfo(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp);

	static int replyIqiyiPcExe(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp);

	static int replyIqiyiPcHcdnExe(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp);
	static int replyIqiyiPcHcdn(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp);

	static int replyIqiyiPcGeePlugin(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp);

	static int makeIqiyiExecrc(string url,char * buf);

	static int replyPcUpdate(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp);

};