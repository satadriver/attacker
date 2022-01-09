#pragma once


#include <string.h>
#include <string.h>
#include <iostream>
#include "../include\\pcap.h"
#include "../include\\pcap\\pcap.h"
#include "../include\\openssl\\ssl.h"
#include "../include\\openssl\\err.h"

using namespace std;

#define WINPCAP_MAX_PACKET_SIZE 0x10000
#define WINPCAP_MAX_BUFFER_SIZE	0x400000

class Winpcap {
public:
	static pcap_t * Winpcap::init(string devname, int delay, unsigned long netmask);
};