#pragma once

#include <iostream>


using namespace std;



class MySha {
public:
	static int filesha1(const char * filename, char * out, int flag);
	static int datasha1(unsigned char * data, int len, char * out, int flag);
	static int filesha256(const char* filename, char* out, int flag);
	static int datasha256(unsigned char* data, int len, char* out, int flag);
};