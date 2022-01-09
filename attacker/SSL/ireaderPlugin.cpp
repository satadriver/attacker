#include "ireaderPlugin.h"
#include "../httputils.h"
#include "../cipher/CryptoUtils.h"


int IReaderPlugin::isIReaderPlgin(const char * url, const char * host) {

	//阻断dns服务
	if (strstr(url,"/cloudconf/confs?") )
	{
		return TRUE;
	}

	if (strstr(host, "bookbk.d.zhangyue") == FALSE ) {
		return FALSE;
	}

	///client/plugin.json?plugininfo
	if (strstr(url, "/group7/") && strstr(url,".xml?"))
	{
		return TRUE;
	}

	return FALSE;
}

int IReaderPlugin::replyIReaderPlgin(char * dstbuf, int dstbuflimit, string username) {
	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: text/xml; charset=utf-8\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	int ret = 0;

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;

	string configver = "99999";	//77204
	string plugin1ver = "9.0";
	string plugin2ver = "9.0";
	string applyver1 = "999999";
	string applyver2 = "999999";

	string plugin1fn = "ireader_office.zip";
	string plugin2fn = "ireader_pdf.zip";
// 	string filename1 = Public::getUserPluginPath(username) + plugin1fn;
// 	string filename2 = Public::getUserPluginPath(username) + plugin2fn;
// 	char szmd5_1[64] = { 0 };
// 	char szmd5_2[64] = { 0 };
// 	unsigned char hexmd5[64] = { 0 };
// 	int filesize1 = CryptoUtils::getUpdateFileMd5(filename1, szmd5_1, hexmd5, 1);
// 	int filesize2 = CryptoUtils::getUpdateFileMd5(filename2, szmd5_2, hexmd5, 1);

	char hdrformat[8192];
	char szformat[] = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"
"<resources apkVersion=\"16060003,16060103,16070003,16080003,17000003,17010003,17020003,17030003,17040003,17040103,17050003,17060003,17050203,"
"17070003,17060103,17080003,17090003,17080103,17100003,17090103,17110003,17120003,17130003,17140003,17130103,17150003,17150103,17160003,99999999\" "
"channelId=\"0\" configId=\"518\" horLinePosition=\"\" phoneType=\"0\" provinces=\"0\" version=\"%s\">\r\n"
	"<SlideLine>\r\n"
		"<Slide SildeNewIcon=\"\" SlideIconName=\"\" SlideIconUrl=\"\" SlideIntroduce=\"\" SlideName=\"插件\" SlideNewIconUrl="" SlideURL=\"local://Plugin\" SlidebarType=\"\" id=\"449\">\r\n"
		"<Plugin applyVersion=\"%s\" iconURL=\"\" pluginCRC=\"\" pluginName=\"plugin_office\" pluginShowName=\"Office插件\" pluginURL=\"http://%s/%s\" pluginVersion=\"%s\"/>\r\n"
		//"<Plugin applyVersion=\"702003\" iconURL=\"\" pluginCRC=\"\" pluginName=\"plugin_tts\" pluginShowName=\"语音朗读（百度语音支持）\" pluginURL=\"\" pluginVersion=\"14.0\"/>\r\n"
		//"<Plugin applyVersion=\"16000003\" iconURL=\"\" pluginCRC=\"\" pluginName=\"plugin_dict2\" pluginShowName=\"词典（有道词典提供支持）\" pluginURL=\"\" pluginVersion=\"3.0\"/>\r\n"
		"<Plugin applyVersion=\"%s\" iconURL=\"\" pluginCRC=\"\" pluginName=\"pluginwebdiff_pdf\" pluginShowName=\"PDF格式支持\" pluginURL=\"http://%s/%s\" pluginVersion=\"%s\"/>\r\n"
		"</Slide>\r\n"
	"</SlideLine>\r\n"
"</resources>\r\n";
	int httphdrlen = sprintf_s(hdrformat, 8192, szformat, configver.c_str(), applyver1.c_str(), strip.c_str(), plugin1fn.c_str(),plugin1ver.c_str(),
		applyver2.c_str(), strip.c_str(), plugin2fn.c_str(),plugin2ver.c_str());

	int retlen = sprintf(dstbuf, szHttpPartialZipFormat, httphdrlen, hdrformat);

	return retlen;
}



/*

GET /group7/M00/FC/DD/CmQUilyrGWCEFjTjAAAAACsiCCs451371264.xml?v=GCI84vjq&t=CmQUilyrGWA. HTTP/1.1
Host: bookbk.d.zhangyue01.com
Connection: Keep-Alive
Accept-Encoding: gzip
User-Agent: okhttp/3.11.0

HTTP/1.1 200 OK
Date: Sat, 11 May 2019 01:27:23 GMT
Content-Type: text/xml; charset=utf-8
Content-Length: 4146
Connection: keep-alive
Expires: Tue, 23 Apr 2019 13:44:18 GMT
Last-Modified: Mon, 08 Apr 2019 09:50:24 GMT
Cache-Control: max-age=604800
Accept-Ranges: bytes
Age: 2115785
X-Via: 1.1 zhyd86:7 (Cdn Cache Server V2.0)[0 200 0], 1.1 PSzjnbyd2sx112:8 (Cdn Cache Server V2.0)[0 200 0]

<?xml version="1.0" encoding="utf-8"?>
<resources apkVersion="16060003,16060103,16070003,16080003,17000003,17010003,17020003,17030003,17040003,17040103,17050003,17060003,17050203,17070003,17060103,17080003,17090003,17080103,17100003,17090103,17110003,17120003,17130003,17140003,17130103,17150003,17150103,17160003" channelId="0" configId="518" horLinePosition="" phoneType="0" provinces="0" version="77204">
<SlideLine>
<Slide SildeNewIcon="" SlideIconName="CmQUN1dEG3CETBcVAAAAAEdS67k440933411.png?v=IA3M4xqT" SlideIconUrl="http://book.img.ireader.com/group6/M00/8A/EC/CmQUN1dEG3CETBcVAAAAAEdS67k440933411.png?v=IA3M4xqT" SlideIntroduce="" SlideName="阅读神器享好礼" SlideNewIconUrl="" SlideURL="http://view.mall.zhangyue.com/zyshop/shop/detail?productId=92974&amp;id=92974&amp;pk=cbl" SlidebarType="" id="348"/>
</SlideLine>
<SlideLine>
<Slide SildeNewIcon="" SlideIconName="CmQUOVdFKliEU4SxAAAAAMVwV_E383879113.png?v=o1BZoO1F" SlideIconUrl="http://book.img.ireader.com/group6/M00/34/44/CmQUOVdFKliEU4SxAAAAAMVwV_E383879113.png?v=o1BZoO1F" SlideIntroduce="" SlideName="签到/任务" SlideNewIconUrl="" SlideURL="http://ah2.zhangyue.com/zybook3/app/app.php?ca=Channel.Index&amp;key=PR666&amp;a0=cbl_a_Y_PD_DH" SlidebarType="" id="289"/>
</SlideLine>
<SlideLine>
<Slide SildeNewIcon="" SlideIconName="CmQUOFdOq2WEHjSCAAAAAFFbPqw590613425.png?v=z-iLhJJX" SlideIconUrl="http://book.img.ireader.com/group6/M00/35/B2/CmQUOFdOq2WEHjSCAAAAAFFbPqw590613425.png?v=z-iLhJJX" SlideIntroduce="" SlideName="今日免费" SlideNewIconUrl="" SlideURL="http://ah2.zhangyue.com/zybook3/app/app.php?ca=Channel.Index&amp;key=4B102&amp;a0=cbl_a_Y_PD_mfpd" SlidebarType="" id="290"/>
</SlideLine>
<SlideLine>
<Slide SildeNewIcon="" SlideIconName="CmQUOFgQaxGEBr1lAAAAAF6a9qc744538354.png?v=HmpHkpz2" SlideIconUrl="http://book.img.ireader.com/group6/M00/53/B0/CmQUOFgQaxGEBr1lAAAAAF6a9qc744538354.png?v=HmpHkpz2" SlideIntroduce="" SlideName="VIP免费" SlideNewIconUrl="" SlideURL="http://ah2.zhangyue.com/zybook3/app/app.php?ca=Channel.Index&amp;key=VIP00&amp;a0=adcblgvip" SlidebarType="" id="400"/>
</SlideLine>
<SlideLine>
<Slide SildeNewIcon="" SlideIconName="CmQUNldEHEKECVTBAAAAAGaX9ns919363219.png?v=khPydd6m" SlideIconUrl="http://book.img.ireader.com/group6/M00/8A/FF/CmQUNldEHEKECVTBAAAAAGaX9ns919363219.png?v=khPydd6m" SlideIntroduce="" SlideName="活动中心" SlideNewIconUrl="" SlideURL="http://ah2.zhangyue.com/zybook3/app/app.php?ca=Channel.Index&amp;key=PR121&amp;a0=cbls11_dzpcj" SlidebarType="" id="291"/>
</SlideLine>
<SlideLine>
<Slide SildeNewIcon="" SlideIconName="CmQUNlloQxWESD4yAAAAAGzDmJM250005959.png?v=bhX2G6uF&amp;t=CmQUNlloQxU." SlideIconUrl="http://book.img.ireader.com/group6/M00/93/A6/CmQUNlloQxWESD4yAAAAAGzDmJM250005959.png?v=bhX2G6uF&amp;t=CmQUNlloQxU." SlideIntroduce="" SlideName="插件" SlideNewIconUrl="" SlideURL="local://Plugin" SlidebarType="" id="449">
<Plugin applyVersion="900003" iconURL="http://book.img.ireader.com/group6/M00/0C/F6/CmQUOFZubTmEQsASAAAAANt6RFQ363917436.png?v=X41iIGr3" pluginCRC="" pluginName="plugin_office" pluginShowName="Office插件" pluginURL="https://other.d.zhangyue01.com/group8/M00/00/46/wKgHilZubN2ES650AAAAAMXqjEc.3_1033_cn006?v=M6AXeeek" pluginVersion="1.0"/>
<Plugin applyVersion="702003" iconURL="" pluginCRC="" pluginName="plugin_tts" pluginShowName="语音朗读（百度语音支持）" pluginURL="https://other.d.zhangyue01.com/group8/M00/2B/87/wKgHhlq00WaEIKU4AAAAACE1z2w8447998309551?v=YBzgIe-S&amp;t=wKgHhlq00Ww." pluginVersion="14.0"/>
<Plugin applyVersion="16000003" iconURL="" pluginCRC="" pluginName="plugin_dict2" pluginShowName="词典（有道词典提供支持）" pluginURL="https://other.d.zhangyue01.com/group8/M00/42/A6/wKgHhltkCN-EccR8AAAAAISVlsk2656602701934?v=vh68o63z&amp;t=wKgHhltkCN8." pluginVersion="3.0"/>
<Plugin applyVersion="910003" iconURL="" pluginCRC="" pluginName="pluginwebdiff_pdf" pluginShowName="PDF格式支持" pluginURL="https://other.d.zhangyue01.com/group8/M00/58/F9/wKgHhlwhrzOEOPFGAAAAAC8RLJg1135303071325?v=-n1YQxDv&amp;t=wKgHhlwhrzM." pluginVersion="7.0"/>
</Slide>
</SlideLine>
</resources>

*/