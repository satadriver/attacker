#pragma once

#ifndef HTTPUTILS_H_H_H
#define HTTPUTILS_H_H_H


#include <WINSOCK2.H>
#include <windows.h>
#include <iostream>
#include "Packet.h"
#include <vector>

using namespace std;

class HttpUtils {
public:
	static int getContentLen(string lphttpdata, int len);

	static bool isAscIP(string ip);

	static DWORD getIPFromHost(string host);

	static string getValueFromKey(const char * lphttphdr, string  key);

	static string getValueFromHttp(string data, string k);

	static string HttpUtils::getValueFromKeyWithoutSpace(const char * lphttphdr, string  searchkey);

	static string getHttpHeader(const char* lphttpdata, int len,char ** data);

	static string HttpUtils::getLongUrl(const char * lppacket, int len);

	static string HttpUtils::getUrl(const char * lppacket, int len);

	static int parseHttpHdr(const char * packet, int datalen, int &type, string & httphdr,char **httpdata, string &url, string & host,int &port);

	static int isHttpPacket(const char * lpdata);

	static int isHttpConnect(const char * lpdata);

	static int HttpUtils::getRange(const char * httphdr, int & begin, int & end);

	static string getIPstr(unsigned long ulIP);

	vector<string> getParamFromUrl(string url);

	static string HttpUtils::getIPv6str(unsigned char ipv6[]);

	static string HttpUtils::getIPPortStr(unsigned long ulIP, int port);

	static string HttpUtils::getIPUserPath(unsigned long ulIP);

	static string HttpUtils::getIPUserPath(unsigned long ulIP, string username);

	static string HttpUtils::getIPPortUrlStr(unsigned long ulIP, int port);

	unsigned int HttpUtils::ipatoi(const char* cstrip);

	static string HttpUtils::getmac(unsigned char * mac);

	static void HttpUtils::ipv4toipv6(unsigned char* ipv4, unsigned char * ipv6);
};

#endif 