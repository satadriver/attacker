#include <stdio.h>
#include "Code.h"
#include <windows.h>
#include <iostream>
#include <string>

using namespace std;


int Code::gbk2utf8(const char * gbk, int gbklen, char *utf8,int utf8limit) {
	int unibufsize = gbklen + 1024;
	wchar_t * unicode = new wchar_t [unibufsize];
	memset(unicode, 0, unibufsize * 2);
	int unicodelen = MultiByteToWideChar(CP_ACP, 0, gbk, -1, unicode, unibufsize);
	if (unicodelen <= 0)
	{
		delete[] unicode;
		return FALSE;
	}

	int utf8len = WideCharToMultiByte(CP_UTF8, 0, unicode, -1, utf8, utf8limit,0,0);
	delete[]unicode;
	if (utf8len <= 0)
	{
		return FALSE;
	}
	
	*(utf8 + utf8len) = 0;
	
	return utf8len;
}


int Code::utf82gbk(const char * utf8, int utf8len, char * gbk,int gbklimit) {
	int unilen = utf8len + 1024;
	wchar_t * unicode = new wchar_t[unilen];
	memset(unicode, 0, unilen * 2);
	int unicodelen = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, unicode, unilen);
	if (unicodelen <= 0)
	{
		delete[] unicode;
		return FALSE;
	}

	int gbklen = WideCharToMultiByte(CP_ACP, 0, unicode, -1, gbk, gbklimit, 0, 0);
	delete[]unicode;
	if (gbklen <= 0)
	{
		return FALSE;
	}
	*(gbk + gbklen) = 0;
	
	return gbklen;
}


//URL 编码
std::string urlencode(std::string encode)
{
	std::string result;
	for (unsigned int i = 0; i < static_cast<unsigned int>(encode.length()); i++)
	{
		char ch = encode[i];
		if (ch == ' ')
		{
			result += '+';
		}
		else if (ch >= 'A' && ch <= 'Z') {
			result += ch;
		}
		else if (ch >= 'a' && ch <= 'z') {
			result += ch;
		}
		else if (ch >= '0' && ch <= '9') {
			result += ch;
		}
		else if (ch == '-' || ch == '-' || ch == '.' || ch == '!' || ch == '~' || ch == '*' || ch == '\'' || ch == '(' || ch == ')') {
			result += ch;
		}
		else {
			result += '%';
			//result += iconv::char_to_hex(ch);
		}
	}
	return result;
}

//URL 解码
std::string urldecode(std::string decode)
{
	std::string result;
	for (unsigned int i = 0; i < static_cast<unsigned int>(decode.length()); i++)
	{
		switch (decode[i])
		{
		case '+':
			result += ' ';
			break;
		case '%':
			if (isxdigit(decode[i + 1]) && isxdigit(decode[i + 2]))
			{
				//result += iconv::hex_to_char(decode[i + 1], decode[i + 2]);
				i += 2;
			}
			else {
				result += '%';
			}
			break;
		default:
			result += decode[i];
			break;
		}
	}
	return result;
}


/************************************************************************/
/*函数名：urlDecode
/*功   能：将encodeed的url中那些可以不用编码的字符decode
/*返回值：返回decode之后的url
/************************************************************************/
string urlDecode(string url)
{
	string result = "", hexStr = "";
	int hex = 0;
	for (size_t i = 0; i < url.length(); i++)
	{
		switch (url[i])
		{
		case '+':
			result += ' ';
			break;
		case '%':
			if (isxdigit(url[i + 1]) && isxdigit(url[i + 2]))
			{
				hexStr = url.substr(i + 1, 2);
				hex = stoi(hexStr, 0, 16);
				//字母和数字[0-9a-zA-Z]、一些特殊符号[$-_.+!*'(),] 、以及某些保留字[$&+,/:;=?@]
				//可以不经过编码直接用于URL
				if ((hex >= 48 && hex <= 57) ||     //0-9
					(hex >= 97 && hex <= 122) ||   //a-z
					(hex >= 65 && hex <= 90) ||    //A-Z
												   //一些特殊符号及保留字[$-_.+!*'(),]  [$&+,/:;=?@]
					hex == 0x21 || hex == 0x24 || hex == 0x26 || hex == 0x27 || hex == 0x28 || hex == 0x29
					|| hex == 0x2a || hex == 0x2b || hex == 0x2c || hex == 0x2d || hex == 0x2e || hex == 0x2f
					|| hex == 0x3A || hex == 0x3B || hex == 0x3D || hex == 0x3f || hex == 0x40 || hex == 0x5f
					)
				{
					result += char(hex);
					i += 2;
				}
				else {
					result += '%';
				}	
			}
			else {
				result += '%';
			}
			break;
		default:
			result += url[i];
			break;
		}
	}
	return result;
}