#include <stdio.h>
#include <string.h>
#include <string>
#include <iostream>
#include "UrlCodec.h"

using namespace std;

int htoi(char *s)
{
	int value =0;
	int c;

	c = ((unsigned char *)s)[0];
	if (isupper(c))
		c = tolower(c);
	value = ( (c >= '0' && c <= '9') ? (c - '0') : (c - 'a' + 10) ) * 16;

	c = ((unsigned char *)s)[1];
	if (isupper(c))
		c = tolower(c);
	value = value + ((c >= '0' && c <= '9') ? (c - '0') : (c - 'a' + 10));

	return (value);
}



int UrlCodec::urldecode(char * in_str)
{
	int in_str_len = strlen(in_str);

	char *dest = (char*)in_str;
	char *data = (char*)in_str;

	while (in_str_len) {
		if (*data == '+') {
			*dest = ' ';
		}
		else if (*data == '%' && in_str_len >= 2 && isxdigit( *(data + 1))&& isxdigit( *(data + 2))) {
			*dest = (char)htoi(data + 1);
			data += 2;
			in_str_len -= 2;
		}
		else {
			*dest = *data;
		}
		data++;
		dest++;
		in_str_len--;
	}
	*dest = '\0';

	return dest - in_str;
}




//仅不编码 -_. 其余全部编码，空格会被编码为 +

int UrlCodec::urlencode(char * in_str,char * out_str)
{
	int in_str_len = strlen(in_str);
	int out_str_len = 0;

	register unsigned char c;
	unsigned char *to, *start;
	unsigned char const *from, *end;
	unsigned char hexchars[] = "0123456789ABCDEF";

	from = (unsigned char *)in_str;
	end = (unsigned char *)in_str + in_str_len;
	start = to = (unsigned char*)out_str;

	while (from < end) {
		c = *from++;

		if (c == ' ') {
			*to++ = '+';
		}
		else if ((c < '0' && c != '-' && c != '.') ||
			(c < 'A' && c > '9') ||
			(c > 'Z' && c < 'a' && c != '_') ||
			(c > 'z')) {
			to[0] = '%';
			to[1] = hexchars[c >> 4];
			to[2] = hexchars[c & 15];
			to += 3;
		}
		else {
			*to++ = c;
		}
	}
	*to = 0;

	out_str_len = to - start;

	return out_str_len;
}


