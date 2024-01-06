#pragma once

#include <iostream>
#include <tins/tins.h>

using namespace std;
using namespace Tins;

class Analysis {
private:
	static int totalIPV4;
	static int totalIPV6;
	static int totalUDP;
	static int totalTCP;
	//most common source ip
	//most common destination ip
public:
	Analysis();
	void GatherStatistics(PDU& pdu);
	void Print();
};