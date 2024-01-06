#pragma once

#include <iostream>
#include <tins/tins.h>
#include "MaxHeap.h"

using namespace std;
using namespace Tins;

class Analysis {
private:
	static int totalIPV4;
	static int totalIPV6;
	static int totalUDP;
	static int totalTCP;
	static int totalBytes;
	Heap DstHeap;
	static string mostCommonDstIp;
	Heap SrcHeap;
	static string mostCommonSrcIp;

public:
	Analysis();
	void GatherStatistics(PDU& pdu);
	void Print();
};