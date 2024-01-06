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
	Heap DstHeap;
	static string mostCommonDstIp;
	Heap SrcHeap;
	static string mostCommonSrcIp;
	Heap DstPortHeap;
	static string mostCommonDstPortIp;
	Heap SrcPortHeap;
	static string mostCommonSrcPortIp;

public:
	Analysis();
	void GatherStatistics(PDU& pdu);
	void Print();
};