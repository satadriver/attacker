#pragma once


class AscHex {
public:
	static int asc2hex(const unsigned char* asc, int asclen, unsigned char* hex);
	static int hex2asc(const unsigned char* hex, int hexlen, int lowercase, unsigned char* asc);

};