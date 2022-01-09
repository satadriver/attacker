

#include "MiguMusic.h"
#include "../HttpUtils.h"


int MiguMusic::nextReply() {

	//{"ResultCode":"0","Msg":"成功"}
	return 0;
}


int MiguMusic::prepareRespData(unsigned long ulIP, string filepath, string filename) {

	int appVersion = 19999999;	//12205013

	string description = "19-9";

	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: text/json;charset=GBK\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	char * jsonFormat =
		"{\"ResultCode\":\"0\",\"Msg\":\"查询到自升级记录\","
		"\"entry\":[{\"updateFlag\":1,\"currentVersion\":\"%u\","
		"\"updateUrl\":\"http://%s/%s\",\"fileName\":\"%s\",\"description\":\"%s\",\"must\":\"0\",\"downloadFlag\":\"1\"}]}";		


	int ret = FALSE;

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);

	char lpJson[MAX_RESPONSE_HEADER_SIZE];
	int iJsonLen = sprintf_s(lpJson, MAX_RESPONSE_HEADER_SIZE, jsonFormat, 
		appVersion,
		szip.c_str(), filename.c_str(), filename.c_str(), description.c_str());

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iJsonLen, lpJson);

	return m_filesize;
}



/*
GET /rdp2/v5.5/update_check.do?&ua=Android_sst&version=4.2180 HTTP/1.1
mode: android
imei: 03c8ac676190ad75a3cbf47c819a8ad7
ro-product-name: TAG-TL00
channel: 0140905
subchannel: 1133
sst-user-agent: HUAWEI TAG-TL00
sst-Network-type: wlan
sst-Network-standard: 01
location-data: 120.17698,30.185791
location-info: %E6%B5%99%E6%B1%9F%E7%9C%81_%E6%9D%AD%E5%B7%9E%E5%B8%82
Host: 218.200.160.29
Connection: Keep-Alive
User-Agent: Mozilla/5.0 (Linux; Android 5.1; HUAWEI TAG-TL00 Build/HUAWEITAG-TL00; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/43.0.2357.121 Mobile Safari/537.36
Accept-Encoding: gzip

HTTP/1.1 200 OK
Server: nginx
Date: Mon, 21 Jan 2019 01:07:23 GMT
Content-Type: application/json;charset=UTF-8
Content-Length: 1572
Set-Cookie: JSESSIONID=1FD6C5ACD90C51BF6B4474F257152CC6; Path=/; HttpOnly
Connection: Keep-alive
Keep-Alive: timeout=15, max=100
Via: 1.1 ID-0001242745425525 uproxy-5

{"flag":1,"newVersion":"4.3100","updateInfo":"1、优化交互体验，操作舒适更畅快；\r\n2、程序猿修复若干已知bug，提升性能，增强稳定性。",
"updateUrl":"http://wlanwm.12530.com/newcms/quku/17/02/39/MobileMusic4310_0140905.apk","token":1,"sunSdkFlag":1,"pushFlag":1,
"aeoPushFlag":1,"logSwitch":1,"phoneRegExp":"^1(([3|4|5|8][0-9]\\d{8})|((70|78|77|73)\\d{8}))$",
"updateColumns":[{"groupcode":"365903","updateTime":"2018-03-26 16:08:34"},{"groupcode":"365911","updateTime":"2019-01-21 06:49:48"},
{"groupcode":"10648733","updateTime":"2018-04-17 14:10:05"},{"groupcode":"3292","updateTime":"2019-01-20 03:08:59"},
{"groupcode":"1551","updateTime":"2017-11-13 23:00:03"},{"groupcode":"365918","updateTime":"2018-08-15 09:26:32"},
{"groupcode":"533045","updateTime":"2019-01-18 13:01:22"}],
"services":[{"serviceName":"MV播放","serviceType":1,"serviceStatus":0,"summary":"7元/月","prompt":"MV包月，尽享MV在线观看。",
"mvOrderPrice":0.0},
{"serviceName":"彩铃功能包月","serviceT

HTTP/1.1 200 OK
Server: nginx
Date: Mon, 21 Jan 2019 01:07:23 GMT
Content-Type: application/json;charset=UTF-8
Content-Length: 1572
Set-Cookie: JSESSIONID=1FD6C5ACD90C51BF6B4474F257152CC6; Path=/; HttpOnly
Connection: Keep-alive
Keep-Alive: timeout=15, max=100
Via: 1.1 ID-0001242745425525 uproxy-5

{"flag":1,"newVersion":"4.3100","updateInfo":"1、优化交互体验，操作舒适更畅快；\r\n2、程序猿修复若干已知bug，提升性能，增强稳定性。",
"updateUrl":"http://wlanwm.12530.com/newcms/quku/17/02/39/MobileMusic4310_0140905.apk","token":1,
"sunSdkFlag":1,"pushFlag":1,"aeoPushFlag":1,"logSwitch":1,"phoneRegExp":"^1(([3|4|5|8][0-9]\\d{8})|((70|78|77|73)\\d{8}))$",
"updateColumns":[{"groupcode":"365903","updateTime":"2018-03-26 16:08:34"},{"groupcode":"365911","updateTime":"2019-01-21 06:49:48"},
{"groupcode":"10648733","updateTime":"2018-04-17 14:10:05"},{"groupcode":"3292","updateTime":"2019-01-20 03:08:59"},
{"groupcode":"1551","updateTime":"2017-11-13 23:00:03"},{"groupcode":"365918","updateTime":"2018-08-15 09:26:32"},
{"groupcode":"533045","updateTime":"2019-01-18 13:01:22"}],
"services":[{"serviceName":"MV播放","serviceType":1,"serviceStatus":0,"summary":"7元/月","prompt":"MV包月，尽享MV在线观看。",
"mvOrderPrice":0.0},{"serviceName":"彩铃功能包月","serviceType":2,"serviceStatus":0,"summary":"5元/月",
"prompt":"您正在开通彩铃功能，开通成功后可订购、使用和赠送彩铃，确认开通吗？(资费：5元/月)","mvOrderPrice":0.0}],
"tips":[],"tabs":[{"type":0,"title":"推荐","url":""},{"type":1,"title":"排行榜","url":""},{"type":2,"title":"歌单","url":""},
{"type":3,"title":"MV","url":""},{"type":4,"title":"歌手","url":""}],"hylSwitch":"1",
"mobileRegex":"^(134|135|138|147|139|136|137|188|178|187|159|158|157|170|152|150|182|151|183|184)\\d{8}$","code":"000000","info":"成功"}
*/