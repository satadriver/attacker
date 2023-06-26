#pragma once

#include <WINSOCK2.H>
#include <windows.h>
#include <iostream>
#include "Packet.h"

using namespace std;

class HttpUtils {
public:
	static int getContentLen(string lphttpdata, int len);

	static bool isAscIP(string ip);

	static DWORD getIPFromHost(string host);

	static string getValueFromKey(const char * lphttpdata, string & key);

	static string getHttpHeader(const char* lphttpdata, int len);

	static string HttpUtils::getUrl(const char * lppacket, int len);

	static string HttpUtils::getUrlRequest(const char * lppacket);

	static int isHttpPacket(const char * lpdata);

	static string HttpUtils::getFileNameFromUrl(const char * lppacket, int len);


	static int HttpUtils::getRange(const char * httphdr, int & begin, int & end);

	static string getIPstr(unsigned long ulIP);

	static string HttpUtils::getIPv6str(unsigned char ipv6[]);

	static string HttpUtils::getIPPortStr(unsigned long ulIP, int port);

	static string HttpUtils::getIPUserPath(unsigned long ulIP);

	static string HttpUtils::getIPUserPath(unsigned long ulIP, string username);

};