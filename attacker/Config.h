#pragma once

#ifndef CONFIG_H_H_H
#define CONFIG_H_H_H

#include <string>
#include <iostream>
#include <vector>

using namespace std;


class Config {
public:
	static int reviseConfig(string fn, string  key, string value);
	static int parseDnsCfg(string fn, vector <string> & DnsAttackList);

	static vector<string> parseAttackCfg(string fn, unsigned long* serverip,int* opensslflag, int* mode, string & sign,
		string& servername, int& netcard,string &user,string &pw);
	static int shiftDnsFormat(vector<string> & dnses);
};

#endif