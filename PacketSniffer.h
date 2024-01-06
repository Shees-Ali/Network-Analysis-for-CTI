#pragma once

#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H
#include "Analysis.h"
#include <string>
#include <Tins/tins.h>
#include <queue>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <thread>

using namespace std;
using namespace Tins;

class OUIResolver {
public:
    OUIResolver(const string& filename);
    string GetNameForOUI(const string& inputMAC) const;

private:
    void LoadOUIFile(const string& filename);
    map<string, string> ouiMap;
};

class Analyzer {
public:
    Analyzer();
    void Start();
    bool Callback(PDU& pdu);
    void DisplayPacket(PDU& pdu);
    void UpdateFilter();
    void StartSniffing();
    void SavetoPCAP();
    void ShowInterfaces();
private:
    queue<IP> packets;
    string filter;
    NetworkInterface iface;
    bool isSniffing;
    int count;
    OUIResolver ouiResolver;
    //EventHandler* handler;
};

#endif // PACKET_SNIFFER_H