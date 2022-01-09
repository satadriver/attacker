#pragma once


//转换比例大多为4:3，utf8用6bit标识一个字节
class Code {
public:
	static int gbk2utf8(const char * gbk, int gbklen, char *utf8, int utf8limit);
	static int utf82gbk(const char * utf8, int utf8len, char * gbk, int gbklimit);


};