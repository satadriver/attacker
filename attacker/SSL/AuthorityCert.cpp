
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


int AuthorityCert::processAuthorCert(string host,string certname, LPSSLPROXYPARAM pstSSLProxyParam) {
	int iRet = 0;

	if (pstSSLProxyParam->version == 0x0303 || pstSSLProxyParam->version == 0x0203 || pstSSLProxyParam->version == 0x0103)
	{
		pstSSLProxyParam->ctxToClient = SSL_CTX_new(TLSv1_2_server_method());
	}
	else {
		pstSSLProxyParam->ctxToClient = SSL_CTX_new(SSLv23_server_method());
	}

	if (pstSSLProxyParam->ctxToClient <= 0)
	{
		printf("processAuthorCert %s SSL_CTX_new error\n", host.c_str());
		return FALSE;
	}

	SSL_CTX_set_verify(pstSSLProxyParam->ctxToClient, SSL_VERIFY_NONE, 0);	

	string cafilename = gLocalPath + CA_CERT_PATH + "\\" + DIGICERTCA;
	iRet = SSL_CTX_load_verify_locations(pstSSLProxyParam->ctxToClient, cafilename.c_str(), 0);
	if (iRet != 1)
	{
		printf("processAuthorCert %s SSL_CTX_load_verify_locations error\n", host.c_str());
		return FALSE;
	}


	SSL_CTX_set_default_passwd_cb_userdata(pstSSLProxyParam->ctxToClient, "");

	string certfilename = gLocalPath + CA_CERT_PATH + "\\" + certname + ".chain.crt";
	iRet = SSL_CTX_use_certificate_chain_file(pstSSLProxyParam->ctxToClient, certfilename.c_str());
	if (iRet <= 0)
	{
		printf("processAuthorCert %s SSL_CTX_use_certificate_file error\n", host.c_str());
		return FALSE;
	}

	string keyfilename = gLocalPath + CA_CERT_PATH + "\\" + certname +".key";
	iRet = SSL_CTX_use_PrivateKey_file(pstSSLProxyParam->ctxToClient, keyfilename.c_str(), SSL_FILETYPE_PEM);
	if (iRet <= 0)
	{
		printf("processAuthorCert %s SSL_CTX_use_certificate_file error\n", host.c_str());
		return FALSE;
	}


	iRet = SSL_CTX_check_private_key(pstSSLProxyParam->ctxToClient);
	if (iRet <= 0)
	{
		printf("processAuthorCert %s Private key does not match the certificate public key\n", host.c_str());
		return FALSE;
	}

	pstSSLProxyParam->SSLToClient = SSL_new(pstSSLProxyParam->ctxToClient);
	if (pstSSLProxyParam->SSLToClient <= 0)
	{
		printf("processAuthorCert %s SSL_new error\n", host.c_str());
		return FALSE;
	}


	iRet = SSL_set_fd(pstSSLProxyParam->SSLToClient, pstSSLProxyParam->sockToClient);
	if (iRet != 1)
	{
		printf("processAuthorCert %s SSL_set_fd errorcode:%d,description:%s,return:%d\n", host.c_str(),
			SSL_get_error(pstSSLProxyParam->SSLToClient, iRet),
			SSL_state_string_long(pstSSLProxyParam->SSLToClient), iRet);
		return FALSE;
	}

	iRet = SSL_accept(pstSSLProxyParam->SSLToClient);
	if (iRet != 1)
	{
		printf("processAuthorCert SSL_accept %s errorcode:%d,description:%s,return:%d\n", host.c_str(),
			SSL_get_error(pstSSLProxyParam->SSLToClient, iRet),
			SSL_state_string_long(pstSSLProxyParam->SSLToClient), iRet);
		return FALSE;
	}

	iRet = SslProxy::SSLProxy(pstSSLProxyParam);
	return iRet;
}