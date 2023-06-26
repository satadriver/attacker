
#include "HttpUtils.h"
#include <iostream>
#include <vector>
#include "attacker.h"
#include "Packet.h"
#include "Public.h"
#include "dnsutils/DnsKeeper.h"
#include "Utils/AscHex.h"

using namespace std;

int HttpUtils::isHttpConnect(const char* lpdata) {
	if (memcmp(lpdata, "CONNECT ", 8) == 0)
	{
		return 8;
	}
	return 0;
}

int HttpUtils::isHttpPacket(const char* lpdata) {

	//HTTP 1.0
	if (memcmp(lpdata, "POST ", 5) == 0) {
		return 5;
	}
	else if (memcmp(lpdata, "GET ", 4) == 0)
	{
		return 4;
	}
	else if (memcmp(lpdata, "HEAD ", 5) == 0)
	{
		return 5;
	}

	//HTTP 1.1
	else if (memcmp(lpdata, "PUT ", 4) == 0)
	{
		return 4;
	}
	else if (memcmp(lpdata, "CONNECT ", 8) == 0)
	{
		return 8;
	}
	else if (memcmp(lpdata, "OPTIONS ", 8) == 0)
	{
		return 8;
	}
	else if (memcmp(lpdata, "DELETE ", 7) == 0)
	{
		return 7;
	}
	else if (memcmp(lpdata, "TRACE ", 6) == 0)
	{
		return 6;
	}

	return FALSE;
}




string HttpUtils::getValueFromKey(const char* lphttphdr, string  searchkey) {

	string key = "\r\n" + searchkey + ": ";
	char* phdr = strstr((char*)lphttphdr, key.c_str());
	if (phdr)
	{
		phdr += key.length();
		char* pend = strstr(phdr, "\r\n");
		int len = pend - phdr;
		if (pend && len > 0 && len < 256)
		{
			string value = string(phdr, len);
			return value;
		}
	}

	return "";
}


string HttpUtils::getValueFromKeyWithoutSpace(const char* lphttphdr, string searchkey) {

	string key = "\r\n" + searchkey + ":";
	char* phdr = strstr((char*)lphttphdr, key.c_str());
	if (phdr)
	{
		phdr += key.length();
		char* pend = strstr(phdr, "\r\n");
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
		if ((ip.at(j) >= '0' && ip.at(j) <= '9') || ip.at(j) == '.')
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
	if (host == "")
	{
		return FALSE;
	}

	DWORD dwip = 0;
	int pos = host.find(":");
	if (pos != -1)
	{
		host = host.substr(0, pos);
	}

	if (isAscIP(host))
	{
		dwip = inet_addr(host.c_str());
		if (dwip == INADDR_NONE)
		{
			return 0;
		}
		return dwip;
	}
	else {
		dwip = DnsKeeper::getDnsFromMap(host);
	}
	return dwip;
}







int HttpUtils::parseHttpHdr(const char* packet, int datalen, int& type, string& httphdr, char** httpdata, string& url, string& host, int& port) {

	char* data = (char*)packet;

	int flaglen = isHttpPacket(data);
	if (flaglen <= 0)
	{
		return -1;
	}

	data += flaglen;

	if (isHttpConnect(packet))
	{
		type = 4;
	}
	else if (memcmp(data, "http://", 7) == 0)
	{
		type = 2;
		data += 7;
	}
	else if (memcmp(data, "https://", 8) == 0)
	{
		type = 3;
		data += 8;
	}
	else {
		type = 1;
	}

	char* httpend = 0;

	if (type == 2 || type == 3 || type == 4)
	{
		httphdr = data;

		httpend = strstr((char*)data, " HTTP/1.");
		if (httpend <= 0)
		{
			httpend = strstr((char*)data, "\r\n");
			if (httpend <= 0)
			{
				httpend = strstr(data, "?");
				if (httpend <= 0)
				{
					return -1;
				}
				else {
					httpend++;
				}
			}
		}

		string fullurl = string(data, httpend - data);

		int pos = fullurl.find("?");
		if (pos > 0)
		{
			//get url end with "?"
			fullurl = fullurl.substr(0, pos + 1);
		}

		pos = fullurl.find("/");
		if (pos >= 0)
		{
			host = fullurl.substr(0, pos);
			url = fullurl.substr(pos);
		}
		else {
			host = fullurl;
			url = "";
		}

		pos = host.find(":");
		if (pos > 0)
		{
			host = host.substr(0, pos);
			string strport = host.substr(pos);
			port = atoi(strport.c_str());
		}

		return TRUE;
	}
	else {
		//http header end with "\r\n\r\n"
		httpend = strstr((char*)data, "\r\n\r\n");
		if (httpend <= 0)
		{
			return FALSE;
		}
		else {
			httphdr = string(packet, httpend + 4 - packet);
			*httpdata = httpend + 4;

			host = HttpUtils::getValueFromKey(httphdr.c_str(), "Host");
			if (host == "")
			{
				host = HttpUtils::getValueFromKeyWithoutSpace(httphdr.c_str(), "Host");
				if (host == "")
				{
					host = HttpUtils::getValueFromKey((char*)httphdr.c_str(), "HOST");
					if (host == "")
					{
						host = HttpUtils::getValueFromKey((char*)httphdr.c_str(), "host");
						if (host == "")
						{
							return -1;
						}
					}
				}
			}

			httpend = strstr((char*)data, " HTTP/1.");
			if (httpend <= 0)
			{
				httpend = strstr(data, "?");
				if (httpend <= 0)
				{
					return -1;
				}
				else {
					httpend++;
				}
			}

			url = string(data, httpend - data);

			//			string fullurl = string(data,httpend - data);
			// 			int pos = fullurl.find("?");
			// 			if (pos > 0)
			// 			{
			// 				//get url end with "?"
			// 				fullurl = fullurl.substr(0, pos + 1);
			// 			}
			//			url = fullurl;

			int pos = host.find(":");
			if (pos > 0)
			{
				host = host.substr(0, pos);
				string strport = host.substr(pos);
				port = atoi(strport.c_str());
			}

			return TRUE;
		}
	}
}







string HttpUtils::getHttpHeader(const char* data, int len, char** lphttpdata) {
	int ret = isHttpPacket(data);
	if (ret <= 0)
	{
		return "";
	}

	char* lphdr = strstr((char*)data, "\r\n\r\n");
	if (lphdr <= FALSE)
	{
		*lphttpdata = 0;
		return string(data);
	}

	lphdr += 4;
	string httphdr = string(data, lphdr - data);
	*lphttpdata = lphdr;
	return httphdr;
}


string HttpUtils::getLongUrl(const char* lppacket, int len) {
	string url = "";

	char* lphdr = strstr((char*)lppacket, " HTTP/1.1\r\n");
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
		else {
			url = string(lppacket);
		}
	}

	return url;
}






string HttpUtils::getUrl(const char* lppacket, int len) {
	string url = "";

	int offset = isHttpPacket(lppacket);
	if (offset <= 0)
	{
		return url;
	}

	const char* packhdr = lppacket + offset;

	char* lphdr = strstr((char*)packhdr, " HTTP/1.1\r\n");
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
		else {
			url = string(packhdr);
		}
	}

	int pos = url.find("?");
	if (pos != -1)
	{
		//get url end with "?"
		url = url.substr(0, pos);
	}

	return url;
}


vector<string> HttpUtils::getParamFromUrl(string url) {
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
				ret.push_back(substr);
				break;
			}
		}
	}
	return ret;
}

string HttpUtils::getValueFromHttp(string data, string k) {
	string key = k + "=";
	int keylen = key.length();

	int pos = data.find(key);
	if (pos > 0)
	{
		pos += keylen;

		int endpos = data.find("&", pos);
		if (endpos - pos > 0)
		{
			string v = data.substr(pos, endpos - pos);
			return v;
		}
	}

	return "";
}



int HttpUtils::getRange(const char* httphdr, int& begin, int& end) {
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


string HttpUtils::getIPUserPath(unsigned long ulIP, string username) {
	return HttpUtils::getIPstr(ulIP) + "/" + username;
}

string HttpUtils::getIPstr(unsigned long ulIP) {
	unsigned char cip[sizeof(unsigned long)] = { 0 };
	memmove(cip, &ulIP, sizeof(unsigned long));
	char szip[64] = { 0 };
	int ret = wsprintfA(szip, "%u.%u.%u.%u", cip[0], cip[1], cip[2], cip[3]);

	return string(szip);
}

string HttpUtils::getmac(unsigned char* mac) {
	char szmac[64];
	wsprintfA(szmac, "%x-%x-%x-%x-%x-%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return string(szmac);
}

string HttpUtils::getIPv6str(unsigned char ipv6[]) {

	unsigned char szip[16] = { 0 };
	int ret = AscHex::hex2asc(ipv6, IPV6_IP_SIZE, 0, szip);

	*(szip + ret) = 0;
	return string((char*)szip);
}

string HttpUtils::getIPPortStr(unsigned long ulIP, int port) {
	unsigned char cip[4] = { 0 };
	memmove(cip, &ulIP, 4);
	char szip[16] = { 0 };
	int ret = wsprintfA(szip, "%u.%u.%u.%u:%u", cip[0], cip[1], cip[2], cip[3], port);
	return string(szip);
}


string HttpUtils::getIPPortUrlStr(unsigned long ulIP, int port) {
	unsigned char cip[4] = { 0 };
	memmove(cip, &ulIP, 4);
	char szip[16] = { 0 };
	int ret = wsprintfA(szip, "%u.%u.%u.%u%%3A%u", cip[0], cip[1], cip[2], cip[3], port);
	return string(szip);
}

unsigned int HttpUtils::ipatoi(const char* cstrip) {

	char strip[256] = { 0 };
	lstrcpyA(strip, cstrip);

	const char* phigh = 0;
	const char* plow = 0;
	const char* phighlow = 0;
	const char* plowhigh = 0;
	int count = 0;

	phigh = strip;
	count++;

	int striplen = lstrlenA(strip);

	for (int i = 0; i < striplen; i++)
	{
		if (strip[i] == '.')
		{
			strip[i] = 0;

			if (count == 1)
			{
				phighlow = strip + i + 1;
				count++;
			}
			else if (count == 2)
			{
				phighlow = strip + i + 1;
				count++;
			}
			else if (count == 3)
			{
				phighlow = strip + i + 1;
				count++;
				break;
			}
			else {
				return 0;
			}
		}
	}

	if (count < 4)
	{
		return 0;
	}

	unsigned long high = strtoul(phigh, 0, 10);
	unsigned long highlow = strtoul(phighlow, 0, 10);
	unsigned long lowhigh = strtoul(plowhigh, 0, 10);
	unsigned long low = strtoul(plow, 0, 10);
	unsigned long ip = high + (highlow << 8) + (lowhigh << 16) + (low << 24);
	return ip;
}


/*
200 OK �ͻ�������ɹ�
301 Moved Permanently ���������ض���
302 Moved Temporarily ������ʱ�ض���
304 Not Modified �ļ�δ�޸ģ�����ֱ��ʹ�û�����ļ���
400 Bad Request ���ڿͻ����������﷨���󣬲��ܱ�����������⡣
401 Unauthorized ����δ����Ȩ�����״̬��������WWW-Authenticate��ͷ��һ��ʹ��
403 Forbidden �������յ����󣬵��Ǿܾ��ṩ���񡣷�����ͨ��������Ӧ�����и������ṩ�����ԭ��
404 Not Found �������Դ�����ڣ����磬�����˴����URL
500 Internal Server Error ��������������Ԥ�ڵĴ��󣬵����޷���ɿͻ��˵�����
502 Bad Gateway ���ش�����ͨ��������ζ�����η������ѹر�(����Ӧ����/����) ���������η�����������/����ʹ�ò�һ�µ�Э�齻�����ݡ�
503 Service Unavailable ��������ǰ���ܹ�����ͻ��˵�������һ��ʱ��֮�󣬷��������ܻ�ָ�������
*/


void HttpUtils::ipv4toipv6(unsigned char* ipv4, unsigned char* ipv6) {
	memset(ipv6, 0, 16);
	memcpy(ipv6 + 12, ipv4, 4);
}