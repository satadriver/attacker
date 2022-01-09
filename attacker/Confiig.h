#pragma once

#ifndef CONFIG_H_H_H
#define CONFIG_H_H_H

#include <string>
#include <iostream>
#include <vector>

using namespace std;


class Config {
public:
	static int Config::parseDnsCfg(string fn, vector <string> & DnsAttackList);

	static vector<string> parseAttackCfg(string fn, unsigned long *dnsip, int *speed,int * flag ,int * runmode,char * gwmac,string &servername);

	static int shiftDnsFormat(vector<string> & dnses);
};

#endif