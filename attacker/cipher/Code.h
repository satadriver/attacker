#pragma once


//ת���������Ϊ4:3��utf8��6bit��ʶһ���ֽ�
class Code {
public:
	static int gbk2utf8(const char * gbk, int gbklen, char *utf8, int utf8limit);
	static int utf82gbk(const char * utf8, int utf8len, char * gbk, int gbklimit);


};