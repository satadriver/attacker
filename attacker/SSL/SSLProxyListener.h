#pragma once




#ifndef SSLPROXYLISTENER_H_H_H
#define SSLPROXYLISTENER_H_H_H

class SslProxyListener {
public:
	SslProxyListener();
	~SslProxyListener();

	SslProxyListener * mInstance;

	int mSock;

	static int	__stdcall listener(SslProxyListener*);

};

#endif