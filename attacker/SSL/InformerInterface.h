#pragma once

#include <unordered_map>
#include <iostream>
#include <windows.h>
#include "../utils/Lock.h"

#define IPV4_ONLINE_FILENAME "ipv4_online.txt"

#define CLIENTIP_WAIT_DELAY				600
#define CLIENTIP_WAIT_SPLITDELAY		30

#define IPV4_REPLACE_IPV6_VALUE			0x12345678



#include <string>
using namespace std;


struct cmp {
	bool operator()(const char *s1, const char *s2) const {
		return std::strcmp(s1, s2) == 0;
	}
};

struct hash_func {
	size_t operator()(const char *str) const {

		//return std::_Hash_seq((unsigned char *)str, 16);
	}
};

class InformerInterface {
public:
	InformerInterface* mInstance;

	CRITICAL_SECTION mCS;

	unordered_map<char*, string *, hash_func, cmp> gIPV6TargetMap;

	unordered_map <string, string> gIPV4TargetMap;

	InformerInterface();
	~InformerInterface();

	int storeTarget(string key,string username);

	static string getTarget(string key);

	static string getTarget(unsigned long ip,string host);

	static int __stdcall InformerInterface::online(InformerInterface*);
};