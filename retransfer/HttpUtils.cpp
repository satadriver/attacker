

#include "HttpUtils.h"

#include "Utils/Asc2Hex.h"
#include <iostream>
#include <vector>

#include "Packet.h"
#include "Public.h"

using namespace std;

#define G_USERNAME "test20181205"


int HttpUtils::isHttpPacket(const char * lpdata) {

	if (memcmp(lpdata, "POST /", 6) == 0 || 
		memcmp(lpdata, "GET /", 5) == 0 || 
		memcmp(lpdata, "HEAD /", 6) == 0 || 
		memcmp(lpdata, "PUT /", 5) == 0 ||
		memcmp(lpdata, "CONNECT ", 8) == 0) {

		return TRUE;
	}
	return FALSE;
}


vector<string> getParamFromUrl(string url) {
	vector<string> ret;
	int pos = url.find("?");
	if (pos != -1)
	{
		string substr = url.substr(pos + 1);

		int size = 0;

		while (TRUE)
		{
			pos = substr.find("&");
			if (pos != -1)
			{
				ret.push_back(substr.substr(0, pos));
				substr = substr.substr(pos + 1);
			}
			else {
				ret.push_back(substr.substr(0, pos));
				break;
			}
		}
	}
	return ret;
}


string HttpUtils::getValueFromKey(const char * lphttphdr, string & searchkey) {

	string key = "\r\n" + searchkey + ": ";
	char * phdr = strstr((char*)lphttphdr, key.c_str());
	if (phdr)
	{
		phdr += key.length();
		char * pend = strstr(phdr, "\r\n");
		int len = pend - phdr;
		if (pend && len > 0 && len < 256)
		{
			string value = string(phdr, len);
			return value;
		}
	}

	return "";
}




int HttpUtils::getContentLen(string httphdr, int len) {
	string contentlen = getValueFromKey(httphdr.c_str(), string("Content-Length"));
	int cl = strtoul(contentlen.c_str(), 0, 10);
	return cl;
}


bool HttpUtils::isAscIP(string ip) {
	DWORD j = 0;
	for (j = 0; j < ip.length(); j++)
	{
		if ((ip[j] >= '0' && ip[j] <= '9') || ip[j] == '.')
		{
			continue;
		}
		else {
			break;
		}
	}

	if (j == ip.length())
	{
		return true;
	}

	return false;
}


DWORD HttpUtils::getIPFromHost(string host)
{

	DWORD dwip = 0;

	return dwip;
}








string HttpUtils::getHttpHeader(const char * lphttpdata, int len) {


	char * lphdr = strstr((char*)lphttpdata, "\r\n\r\n");
	if (lphdr == FALSE)
	{
		return string(lphttpdata);
	}

	lphdr += strlen("\r\n\r\n");
	string httphdr = string(lphttpdata, lphdr - lphttpdata);

	return httphdr;
}


string HttpUtils::getUrl(const char * lppacket, int len) {
	string url = "";

// 	char * flag = strstr((char*)lppacket, "?");
// 	if (flag)
// 	{
// 		int len = flag + 1 - lppacket;
// 		url = string(lppacket, len);
// 		return url;
// 	}

	char * lphdr = strstr((char*)lppacket, " HTTP/1.1\r\n");
	if (lphdr)
	{
		int urllen = lphdr - lppacket;
		url = string(lppacket, urllen);
	}
	else {
		lphdr = strstr((char*)lppacket, " HTTP/1.0\r\n");
		if (lphdr)
		{
			int urllen = lphdr - lppacket;
			url = string(lppacket, urllen);
		}
	}
	
	return url;
}


//end with ?
string HttpUtils::getUrlRequest(const char * lppacket) {
	string url = "";

	char * flag = strstr((char*)lppacket, "?");
	if (flag)
	{
		int len = flag + 1 - lppacket;
		url = string(lppacket, len);
	}
	else {
		url = lppacket;
	}
	 
	return url;
}

//end without ?
string HttpUtils::getFileNameFromUrl(const char * lppacket, int len) {
	string url = "";

	int offset = 0;
	if (memcmp(lppacket, "GET /", 5) == 0)
	{
		offset = 4;
	}
	else if (memcmp(lppacket, "POST /", 6) == 0) {
		offset = 5;
	}
	else {
		//return url;
	}

	const char *packhdr = lppacket + offset;

	char * lphdr = strstr((char*)packhdr, " HTTP/1.1\r\n");
	if (lphdr)
	{
		int urllen = lphdr - packhdr;
		url = string(packhdr, urllen);
	}
	else {
		lphdr = strstr((char*)packhdr, " HTTP/1.0\r\n");
		if (lphdr)
		{
			int urllen = lphdr - packhdr;
			url = string(packhdr, urllen);
		}
	}

	int pos = url.find("?");
	if ( pos != -1)
	{
		url = url.substr(0, pos);
	}

	pos = url.find("&");
	if (pos != -1)
	{
		url = url.substr(0, pos);
	}
	return url;
}







int HttpUtils::getRange(const char * httphdr,int & begin,int & end) {
	string value = getValueFromKey(httphdr, string("Range"));
	if (value == "")
	{
		return -1;
	}
	else {
		string flag = "bytes=";
		int pos = value.find(flag);
		if (pos != -1)
		{
			value = value.substr(flag.length());
		}
	}

	if (value.back() == '-')
	{
		value = value.substr(0, value.length() - 1);
		begin = atoi(value.c_str());
		end = -1;
		return 0;
	}
	else {
		int pos = value.find("-");
		if (pos == -1)
		{
			printf("parse partial error\r\n");
			return -1;
		}

		string start = value.substr(0, pos);
		string over = value.substr(pos + 1);
		begin = atoi(start.c_str());
		end = atoi(over.c_str());
		return 0;
	}
}

string HttpUtils::getIPUserPath(unsigned long ulIP) {
	return HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;
}


string HttpUtils::getIPUserPath(unsigned long ulIP,string username) {
	return HttpUtils::getIPstr(ulIP) + "/" + username;
}

string HttpUtils::getIPstr(unsigned long ulIP) {
	unsigned char cip[4] = { 0 };
	memmove(cip, &ulIP, 4);
	char szip[64];
	int ret = wsprintfA(szip, "%u.%u.%u.%u", cip[0], cip[1], cip[2], cip[3]);

	return string(szip);
}


string HttpUtils::getIPv6str(unsigned char ipv6[]) {

	unsigned char szip[64];
	int ret = Asc2Hex::hex2str(ipv6, IPV6_IP_SIZE,0,szip);

	*(szip + ret) = 0;
	return string((char*)szip);
}

string HttpUtils::getIPPortStr(unsigned long ulIP,int port) {
	unsigned char cip[4] = { 0 };
	memmove(cip, &ulIP, 4);
	char szip[256];
	int ret = wsprintfA(szip, "%u.%u.%u.%u:%u", cip[0], cip[1], cip[2], cip[3], port);
	return string(szip);
}