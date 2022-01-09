#pragma once
#pragma once



#ifndef YOUKU_H_H_H
#define YOUKU_H_H_H

#include "..\\ReplaceSignature.h"

class YouKuPlugin :public ReplaceSignature {
public:
	int prepareRespData(unsigned long ulIP, string filepath, string filename);
	int YouKuPlugin::prepareRespData_old(unsigned long ulIP, string filepath, string filename);
};
#endif


/*
POST /api/op.rec.app.checkUpdate HTTP/1.1
Charset: UTF-8
Content-Type: application/json; charset=utf-8
User-Agent: Dalvik/2.1.0 (Linux; U; Android 6.0.1; OPPO A57 Build/MMB29M)
Host: open.sjzs-api.25pp.com
Connection: Keep-Alive
Accept-Encoding: gzip
Content-Length: 337

{"id":-4126478986892719460,"client":{"caller":"secret.pp.client","ex":{"osVersion":23}},
"data":{"isp":"46011","versionName":"0","ch":"PA_15","packageName":"com.pp.sdk.apk",
"versionCode":"0","productId":2015,"ip":"172.24.58.2","updateType":0,"sdkVersionCode":"6",
"prov":"","net":"wifi","rom":23},"sign":"bdef658b00e55bb3894847376dd68ab0"}HTTP/1.1 200 OK
Date: Wed, 20 Feb 2019 10:33:08 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 630
Connection: keep-alive
Cache-Control: no-cache

{"data":{"app":{"appId":-1,"versionCode":"112","productId":"2015","packageName":"com.pp.sdk.apk","versionName":"1.1.2",
"updateDes":"......SDK............112......",
"downloadUrl":"http://sjzs-api.25pp.com/stat/upgrade?settingId\u003d2424\u0026targetUrl\u003dhttp%3A%2F%2Fandroid-apps.25pp.com%2Fppandroid%2Fplugin%2Fyoukuplugin_112_20190114150417.apk\u0026size\u003d675096\u0026md5\u003d1a6267dd4dceac5a2b237080ac1df6fa",
"updateTime":1548777600000,"size":675096,"isForceUpdate":0,"name":"","iconUrl":"","trailUpdate":0,"backgroundImg":""},"isNeedUpdate":1},
"id":"-4126478986892719460","state":{"code":2000000,"msg":"Ok","tips":""}}
*/