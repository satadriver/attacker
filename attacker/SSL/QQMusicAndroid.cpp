
#include "QQMusicAndroid.h"
#include "../cipher/CryptoUtils.h"
#include "../HttpUtils.h"



int QQMusicAndroid::isQQMusicUpdatePacket(string url, string host) {
	if (host == "dldir1.qq.com")
	{
		///music/clntupate/android/ml/MLPluginConfig.json
		if (strstr(url.c_str(), "/music/clntupate/android/ml/MLPluginConfig.json"))
		{
			return TRUE;
		}
	}

	return FALSE;
}

//--dex-file=/data/user/0/com.tencent.qqmusic/files/machine-learning-install/AudioFirstPiece.ml_1547383495244/classes.dex 
//--oat-file=/data/user/0/com.tencent.qqmusic/app_odex/classes.dex


int QQMusicAndroid::makeQQMusicUpdateResp(char * lpbuf, int iCounter, int limit, LPHTTPPROXYPARAM lpssl) {

	char *szformat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n"
		"Vary: Accept\r\n\r\n%s";

	int versioncode = 99;		//18

	char *conformat =
		"{\"packages\":[{"
		"\"versionCode\":%u,\"rules\":[],\"versionRegion\":\"\",\"plugins\":[{\"name\":\"AudioFirstPiece\",\"packageId\":\"audiofirstpiece\","
		"\"sampleRate\":10000,\"sampleRateHigh\":12,\"url\":\"http://%s/%s\","
		"\"md5\":\"%s\""
		"}]}]}";

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;

	char szfile1md5[256] = { 0 };
	unsigned char hex1md5[256] = { 0 };

	string zipfn = "qqmusic_plugin.zip";
	string filename1 = Public::getUserPluginPath(lpssl->username) + zipfn;

	int filesize = CryptoUtils::getUpdateFileMd5(filename1, szfile1md5, hex1md5, TRUE);
	char bufcontent[4096];
	int conlen = sprintf_s(bufcontent, 4096, conformat, versioncode,strip.c_str(), zipfn.c_str(), szfile1md5);
	int totallen = sprintf_s(lpbuf, limit, szformat, conlen, bufcontent);

	return totallen;
}


/*
GET dldir1.qq.com/music/clntupate/android/ml/MLPluginConfig.json HTTP/1.1
User-Agent: QQMusic 8090511(android 6.0.1)
Host: dldir1.qq.com
Connection: Keep-Alive
x-online-host: dldir1.qq.com
Accept-Encoding: gzip

HTTP/1.1 200 OK
Content-Length: 245
Last-Modified: Thu, 10 Jan 2019 11:18:49 GMT
Cache-Control: max-age=600
Content-Encoding: gzip
Server: nws_4.2.1_midcache
Date: Thu, 10 Jan 2019 11:25:18 GMT
Cache-Control: max-age=600
Expires: Thu, 10 Jan 2019 11:35:18 GMT
Content-Type: application/json
X-NWS-LOG-UUID: 98801002280863795
X-NWS-UUID-VERIFY: 41d2af0bcdadc50d35ab04430b655e20
Connection: keep-alive
X-Cache-Lookup: Cache Hit


{
"packages":[
{
"versionCode":19,
"rules":[],
"versionRegion":"",
"plugins":[
{
"name":"AudioFirstPiece",
"packageId":"audiofirstpiece",
"sampleRate":10000,
"sampleRateHigh":12,
"url":"http://dldir1.qq.com/music/clntupate/android/ml/plugin-audiofirstpiece.ml",
"md5":"303e51e014acccbcbf5daeeff600bfb0"
}
]
}
]
}
*/