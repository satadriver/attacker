#pragma once

#ifndef SSLENTRY_H_H_H
#define SSLENTRY_H_H_H

#include <iostream>
#include <string>
#include <windows.h>
#include <vector>

using namespace std;

#define HTTP_WORK_THREAD_CNT	32
#define SSL_WORK_THREAD_CNT		32

class SSLEntry {
public:
	static int SslEntry(int control, vector<string>hostlist, vector<string>targetlist);
};

#endif