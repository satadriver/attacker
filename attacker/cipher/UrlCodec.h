#pragma once

#include <iostream>

using namespace std;

class UrlCodec {
public:
	static int UrlCodec::urlencode(char* in_str, int insize, char* out_str, int outsize);
	static int urldecode(char * src,int srclen);
};
