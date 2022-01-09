
#include "MiaoPaiPlugin.h"
#include "../HttpUtils.h"


MiaoPaiPlugin::MiaoPaiPlugin(unsigned long ulIP, string filepath, string filename) {

	char * lpRespFormat = "HTTP/1.1 206 Partial Content\r\n"
		"Content-Type: application/java-archive\r\n"
		"Content-Length: 2584609\r\n"
		"Connection: keep-alive\r\n"
		"Content-Range: bytes 0-2584608/2584609\r\n"
		"Accept-Ranges: bytes\r\n\r\n";


	int ret = FALSE;
	return ;
}

int MiaoPaiPlugin::prepareRespData(unsigned long ulIP, string filepath, string filename) {
	return 0;
}


/*
GET /client/plugin.json?plugininfo=[]&t=52479186&unique_id=b7daf183-a6dd-3296-82f8-bb323ac8c7f8&version=7.2.00&AndroidId=A00000611E3E28&udid=97142F4CEC99E6E43508E5936CC09C44&channel=oppo_market HTTP/1.1
cp-os: android
cp-abid: 1-10
cp-sign: dda7494d236772e38a05c493e9c2304a
cp-sver: 6.0.1
cp-appid: 424
cp-uniqueId: b7daf183-a6dd-3296-82f8-bb323ac8c7f8
cp-time: 1552185498
cp-uuid: b7daf183-a6dd-3296-82f8-bb323ac8c7f8
cp-channel: oppo_market
cp-vend: miaopai
cp-ver: 7.2.00
Host: b-api.ins.miaopai.com
Connection: Keep-Alive
Accept-Encoding: gzip
User-Agent: okhttp/3.3.1

HTTP/1.1 200 OK
Date: Sun, 10 Mar 2019 02:38:17 GMT
Content-Type: application/json
Transfer-Encoding: chunked
Connection: keep-alive
Set-Cookie: aliyungf_tc=AQAAAOFkRgg48AkA9lQKcCEyv5Ga1H9n; Path=/; HttpOnly
Vary: Accept-Encoding
X-Powered-By: PHP/7.0.13
Cache-Control: no-cache, must-revalidate
Expires: Sun, 10 Mar 19 01:38:17 +0000
X-Frame-Options: Deny
DPOOL_HEADER: ins-others-472178998-t6f9l
Content-Encoding: gzip
Server: elb

*/