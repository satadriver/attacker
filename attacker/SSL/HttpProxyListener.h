


#pragma once

#ifndef HTTPPROXYLISTENER_H_H_H
#define HTTPPROXYLISTENER_H_H_H



class HttpProxyListener {
public:

	HttpProxyListener();

	~HttpProxyListener();

	int mSock;
	HttpProxyListener * mInstance;

	static int __stdcall listener(HttpProxyListener *);

};


#endif