#pragma once



#ifndef MYLISTENER_H_H_H
#define MYLISTENER_H_H_H

#include <iostream>
#include <windows.h>

using namespace std;


class MyListener {
public:
	MyListener* mInstance;
	int mSock;

	int mPort;

	MyListener(int port);
	~MyListener();

	static int	__stdcall listener(MyListener*);
};

#endif
