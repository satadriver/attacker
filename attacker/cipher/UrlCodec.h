#pragma once

#include <iostream>

using namespace std;

class UrlCodec {
public:
	static int urlencode(char * src,char *dst);
	static int urldecode(char * src);
};
