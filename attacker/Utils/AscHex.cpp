
#include <windows.h>
#include "AscHex.h"


int AscHex::hex2asc(const unsigned char* hex, int hexlen, int lowercase, unsigned char* asc) {
	int casevalue = 55;
	if (lowercase)
	{
		casevalue = 87;
	}

	int i = 0, j = 0;

	for (; i < hexlen; i++)
	{
		unsigned char c = hex[i];
		unsigned char c1 = c >> 4;
		if (c1 >= 0 && c1 <= 9)
		{
			c1 += 0x30;
		}
		else {
			c1 += casevalue;		//uppercase is 55,87 is lowercase
		}
		unsigned char c2 = c & 0xf;
		if (c2 >= 0 && c2 <= 9)
		{
			c2 += 0x30;
		}
		else {
			c2 += casevalue;
		}
		asc[j++] = c1;
		asc[j++] = c2;
	}

	*(asc + j) = 0;
	return j;
}


int AscHex::asc2hex(const unsigned char* asc, int asclen, unsigned char* hex) {

	int i = 0, j = 0;
	for (; i < asclen; i += 2, j++)
	{
		unsigned char c = asc[i];
		unsigned char c1 = asc[i + 1];
		if (c1 >= '0' && c1 <= '9')
		{
			c1 -= 0x30;
		}
		else if ((c1 >= 'a' && c1 <= 'f'))
		{
			c1 -= 87;
		}
		else if ((c1 >= 'A' && c1 <= 'F'))
		{
			c1 -= 55;
		}
		else {
			return FALSE;
		}

		if (c >= '0' && c <= '9')
		{
			c -= 0x30;
		}
		else if ((c >= 'a' && c <= 'f'))
		{
			c -= 87;
		}
		else if ((c >= 'A' && c <= 'F'))
		{
			c -= 55;
		}
		else {
			return FALSE;
		}

		unsigned char tmp = (c1 << 16) | c;

		hex[j] = tmp;
	}

	return j;
}



