#pragma once



#ifndef OTHERLISTENER_H_H_H
#define OTHERLISTENER_H_H_H

#include <iostream>
#include <windows.h>

using namespace std;


class OtherListener {
public:
	OtherListener * mInstance;
	int mSock;

	int mPort;

	OtherListener(int port);
	~OtherListener();

	static int	__stdcall OtherListener::listener(OtherListener *);
};

#endif
