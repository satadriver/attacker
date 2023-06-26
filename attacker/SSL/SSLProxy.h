

#pragma once

#ifndef SSLPROXY_H_H_H
#define SSLPROXY_H_H_H

#include "sslPublic.h"
#include "../utils/Lock.h"

#define PEEK_SERVERNAME_BUF_SIZE 2048


class SslProxy {
public:
	SslProxy();
	~SslProxy();

	SslProxy * mInstance;

	static int SslProxy::ReadPendingData(char * lpdata, int size, SSL * ssl);

	static int SslProxy::SSLProxy(LPSSLPROXYPARAM pstSSLProxyParam);



	static int SslProxy::SSLConnectionMain(LPSSLPROXYPARAM pstSSLProxyParam);

	static int __stdcall SslProxy::SSLConnection(LPWORKCONTROL param);

	static int SslProxy::getServerNameFromClientHello(char * data, int len,unsigned char * servername,int & version);

};

#endif