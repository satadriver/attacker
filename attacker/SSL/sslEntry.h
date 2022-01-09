#pragma once

#ifndef SSLENTRY_H_H_H
#define SSLENTRY_H_H_H

#include <iostream>
#include <string>
#include <windows.h>
#include <vector>

using namespace std;

#define HTTP_WORK_THREAD_CNT 64
#define SSL_WORK_THREAD_CNT 64

class SSLEntry {
public:
	static int sslEntry(unsigned long serverip,unsigned long localip, string path, int control, 
		vector<string>gDnsAttackList, vector<string>gHostAttackList, int mode);
};

#endif