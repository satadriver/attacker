#pragma once




#ifndef SSLPROXYLISTENER_H_H_H
#define SSLPROXYLISTENER_H_H_H

class SSLProxyListener {
public:
	SSLProxyListener();
	~SSLProxyListener();

	SSLProxyListener* mInstance;

	int mSock;

	static int	__stdcall listener(SSLProxyListener*);

};

#endif