
#include "qunar.h"
#include "../HttpUtils.h"


int Qunar::prepareRespData(unsigned long ulIP, string filepath, string filename) {

	int ret = 0;
	char * lpRespFormat =
		"HTTP/1.1 200 OK\r\nContent-Type: application/json;charset=UTF-8\r\nContent-Length: %u\r\n"
		"Connection: keep-alive\r\n\r\n%s";

	char * lpRespContentFormat =
		"{\"status\":0,\"message\":\"成功\","
		"\"data\":{\"hlist\":[{\"hybridId\":\"mob_uc\","
		"\"patchUrl\":\"http://%s/%s\",\"score\":0,\"md5\":\"%s\",\"force\":false,"
		"\"url\":\"http://%s/%s\",\"version\":%u}],\"offline_hlist\":[]}}";

	string szip = HttpUtils::getIPstr(ulIP) + "/" + G_USERNAME;

	ret = getUpdateFileMd5(filepath + filename, TRUE);

	int version = 999;

	char tmpbuf[4096] = { 0 };
	int tmplen = sprintf(tmpbuf, lpRespContentFormat, szip.c_str(), filename.c_str(), m_szmd5, szip.c_str(), filename.c_str(), version);
	m_iRespSize = sprintf(m_lpResp, lpRespFormat, tmplen, tmpbuf);
	return m_iRespSize;
}



/*
POST /hybridUpgrade HTTP/1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: QSpiderAndroid
qrid: 1550393027463
connection: keep-alive
Cookie: _v=; QN270=864590033215752%2C60001132%2CC4508%2CB5260C75-2844-4D2E-89A8-A10668DA5CE3; QN241={"uid":"864590033215752","gid":"B5260C75-2844-4D2E-89A8-A10668DA5CE3","pid":"10010","cid":"C4508","uuid":"","lt":0,"scheme":"qunaraphone","vid":"60001132","usid":"","atomversion":{"voice":"37","intercar":"36","hotel":"56","bus":"45","open":"18","framework":"8","order":"40","pay":"45","sight":"48","hy":"29","im":"15","attemper":"29","collab":"24","vacation":"66","flight":"84","car":"63","imsdk":"13","uc":"44","patch":"10","share":"13","browser":"41","train":"65","gb":"50","carpool":"12","mv":"20","alexhome":"66","gongyu":"27","hwpush":"2"}}; csrfToken=4Owd9FB4cwbzydL; _t=; _s=; _q=; QN48=tc_970ad50814fdcd8a_168fa98730f_a95e; QN1=00000800060010fd1648dd82
Content-Length: 1386
Host: exbizcom.qunar.com

cparam=%7B%22cid%22%3A%22C4508%22%2C%22gid%22%3A%22%22%2C%22model%22%3A%22HUAWEI+CAZ-AL10%22%2C%22nt%22%3A%22%5C%22460shoufei%5C%22%22%2C%22osVersion%22%3A%227.0%22%2C%22pid%22%3A%2210010%22%2C%22uid%22%3A%22%22%2C%22vid%22%3A%2260001132%22%7D&module=%7B%22alexhome%22%3A%2266%22%2C%22attemper%22%3A%2229%22%2C%22browser%22%3A%2241%22%2C%22bus%22%3A%2245%22%2C%22car%22%3A%2263%22%2C%22carpool%22%3A%2212%22%2C%22collab%22%3A%2224%22%2C%22flight%22%3A%2284%22%2C%22framework%22%3A%228%22%2C%22gb%22%3A%2250%22%2C%22gongyu%22%3A%2227%22%2C%22hotel%22%3A%2256%22%2C%22hwpush%22%3A%222%22%2C%22hy%22%3A%2229%22%2C%22im%22%3A%2215%22%2C%22imsdk%22%3A%2213%22%2C%22intercar%22%3A%2236%22%2C%22mv%22%3A%2220%22%2C%22open%22%3A%2218%22%2C%22order%22%3A%2240%22%2C%22patch%22%3A%2210%22%2C%22pay%22%3A%2245%22%2C%22share%22%3A%2213%22%2C%22sight%22%3A%2248%22%2C%22train%22%3A%2265%22%2C%22uc%22%3A%2244%22%2C%22vacation%22%3A%2266%22%2C%22voice%22%3A%2237%22%7D&hlist=%5B%7B%22hybridId%22%3A%22mob_uc%22%2C%22length%22%3A1744937%2C%22md5%22%3A%222163a95cb303458889a6ecdb1b48aa2b%22%2C%22version%22%3A75%7D%2C%7B%22hybridId%22%3A%22bnbrn_android%22%2C%22length%22%3A400022%2C%22md5%22%3A%22aeb885134f31ebaa1180cb48af52615a%22%2C%22version%22%3A7%7D%5D&current=%7B%22hybridId%22%3A%22mob_uc%22%2C%22length%22%3A1744937%2C%22md5%22%3A%222163a95cb303458889a6ecdb1b48aa2b
%22%2C%22version%22%3A75%7D


HTTP/1.1 200 OK
Date: Sun, 17 Feb 2019 08:43:48 GMT
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
Vary: Accept-Encoding
Server: Server: QWS/1.0
Req-ID: 00000780074010fd2620281f

169
{"status":0,"message":"成功","data":{"hlist":[{"hybridId":"mob_uc","patchUrl":"https://wap.qunarcdn.com/fed_download/xdiff/152335955577072.xdiff","score":0,"md5":"hHZvoSIw1hS4jfeUnQA7pTCV3gYyPAB3+WfNx93UAv8FAyeGgph8Esfsbw==","force":false,"url":"https://wap.qunarcdn.com/fed_download/xdiffAll/mob_uc_146_20180410072444.qp","version":146}],"offline_hlist":[]}}

*/