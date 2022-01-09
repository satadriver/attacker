#pragma once
#include <windows.h>
#include <iostream>
#include "..\\ReplaceSignature.h"

using namespace std;

class WPSMobile :public ReplaceSignature{
public:
	WPSMobile();
	WPSMobile(unsigned long ulip,string filepath,string filename);
	int prepareRespData(unsigned long ulIP, string filepath, string filename);
};


/*
GET /wps/download/android/kingsoftoffice_2052/updatenew/version/version_zh-CN.xml HTTP/1.1
Host: kad.www.wps.cn
Connection: Keep-Alive


HTTP/1.1 200 OK
Content-Type: text/xml; charset=utf-8
Connection: keep-alive
Date: Mon, 11 Mar 2019 00:48:23 GMT
Cache-Control: max-age=900
ETag: "5c77912e-411"
Last-Modified: Thu, 28 Feb 2019 07:43:42 GMT
Age: 8
X-Cache-Status: HIT
Expires: Mon, 11 Mar 2019 01:03:23 GMT
X-Powered-By: LinkingCloud
Content-Length: 1041
X-Cache-Info: HIT from MZJ-JH-A-TM1
X-Cache-Info: HIT from TJS-XZ-1-3A2
Accept-Ranges: bytes
Server: KSOWS
X-Cache-Status: HIT

<?xml version="1.0" encoding="UTF-8"?>
<moffice>
<version>11.5</version>
<packname>moffice_2052.apk</packname>
<bytes>38864987</bytes>
<infos>
<info>亲爱的用户，V11.5 版本正式发布了，本次升级共有46处新增和改进的功能点，部分修改如下： </info>
<info></info>
<info>【文档管理】</info>
<info>新增：批量移动文档，快捷管理更方便</info> 
<info>新增：安全文档支持权限申请</info> 
<info>优化：星标文档支持在首页置顶显示，方便快速查找</info>
<info>优化：首页新增文档搜索输入框，查找文档更便捷</info>
<info></info>
<info></info>
<info>【电子表格】</info>
<info>优化：对表格的输入面板进行了优化</info>
<info></info>
<info></info>
<info>【演示播放】</info>
<info>新增：支持设置幻灯片图片背景</info>
<info></info>
<info></info>
<info>【拍照扫描】</info>
<info>优化：适配大屏、刘海屏手机</info>
<info></info>
</infos>
</moffice>
*/