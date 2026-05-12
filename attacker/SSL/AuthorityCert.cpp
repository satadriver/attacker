
#include "AuthorityCert.h"
#include <WINSOCK2.H>
#include "sslPublic.h"
#include "sslPacket.h"
#include "SSLProxy.h"
#include "sslproxylistener.h"
#include "../HttpUtils.h"
#include "..\\include\\openssl\\ssl.h"
#include "..\\include\\openssl\\err.h"
#include <fcntl.h>
#include "MakeCert.h"
#include "HttpProxy.h"
#include "../Public.h"
#include "../utils/BaseSocket.h"
#include "../attacker.h"
#include "../Utils/Tools.h"


int AuthorityCert::processAuthorCert(string host,string certname, LPSSLPROXYPARAM spp) {
	int iRet = 0;

	if (spp->version == 0x0303 || spp->version == 0x0203 || spp->version == 0x0103)
	{
		spp->ctxToClient = SSL_CTX_new(TLSv1_2_server_method());
	}
	else {
		spp->ctxToClient = SSL_CTX_new(SSLv23_server_method());
	}

	if (spp->ctxToClient <= 0)
	{
		log("%s %d %s SSL_CTX_new error\n",__FUNCTION__,__LINE__, host.c_str());
		return FALSE;
	}

	SSL_CTX_set_verify(spp->ctxToClient, SSL_VERIFY_NONE, 0);

	string cafilename = gLocalPath + CA_CERT_PATH + "\\" + DIGICERTCA;
	iRet = SSL_CTX_load_verify_locations(spp->ctxToClient, cafilename.c_str(), 0);
	if (iRet != 1)
	{
		log("%s %d  %s SSL_CTX_load_verify_locations error\n", __FUNCTION__, __LINE__, host.c_str());
		return FALSE;
	}


	SSL_CTX_set_default_passwd_cb_userdata(spp->ctxToClient, "");

	string certfilename = gLocalPath + CA_CERT_PATH + "\\" + certname + ".chain.crt";
	iRet = SSL_CTX_use_certificate_chain_file(spp->ctxToClient, certfilename.c_str());
	if (iRet <= 0)
	{
		log("%s %d %s SSL_CTX_use_certificate_file error\n", __FUNCTION__, __LINE__, host.c_str());
		return FALSE;
	}

	string keyfilename = gLocalPath + CA_CERT_PATH + "\\" + certname +".key";
	iRet = SSL_CTX_use_PrivateKey_file(spp->ctxToClient, keyfilename.c_str(), SSL_FILETYPE_PEM);
	if (iRet <= 0)
	{
		log("%s %d %s SSL_CTX_use_certificate_file error\n", __FUNCTION__, __LINE__, host.c_str());
		return FALSE;
	}


	iRet = SSL_CTX_check_private_key(spp->ctxToClient);
	if (iRet <= 0)
	{
		log("%s %d %s Private key does not match the certificate public key\n", __FUNCTION__, __LINE__, host.c_str());
		return FALSE;
	}

	spp->SSLToClient = SSL_new(spp->ctxToClient);
	if (spp->SSLToClient <= 0)
	{
		log("%s %d %s SSL_new error\n", __FUNCTION__, __LINE__, host.c_str());
		return FALSE;
	}


	iRet = SSL_set_fd(spp->SSLToClient, spp->sockToClient);
	if (iRet != 1)
	{
		log("%s %d %s SSL_set_fd errorcode:%d,description:%s,return:%d\n", __FUNCTION__, __LINE__, host.c_str(),
			SSL_get_error(spp->SSLToClient, iRet),
			SSL_state_string_long(spp->SSLToClient), iRet);
		return FALSE;
	}

	iRet = SSL_accept(spp->SSLToClient);
	if (iRet != 1)
	{
		log("%s %d SSL_accept %s errorcode:%d,description:%s,return:%d\n", __FUNCTION__, __LINE__, host.c_str(),
			SSL_get_error(spp->SSLToClient, iRet),SSL_state_string_long(spp->SSLToClient), iRet);
		return FALSE;
	}

	iRet = SSLProxy::SSL_ProxyMain(spp);
	return iRet;
}