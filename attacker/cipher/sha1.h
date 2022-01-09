#pragma once




class MySha1 {
public:
	static int getsha1(const char * filename, char * out, int flag);
	static int getsha1(unsigned char * data, int len, char * out, int flag);
};