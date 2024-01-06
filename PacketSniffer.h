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

class LayerFilter {
public:
    string FilterDataLinkLayer(const PDU& pdu);
    string FilterNetworkLayer(const PDU& pdu);
    string FilterTransportLayer(const PDU& pdu);
};


//class EventHandler {
//private:
//    DWORD cNumRead, fdwMode, i;
//    INPUT_RECORD irInBuf[128];
//    int counter;
//    HANDLE hStdin;
//    DWORD fdwSaveOldMode;
//    Analyzer* analyzer;
//
//    VOID ErrorExit(string lpszMessage);
//
//    VOID KeyEventProc(KEY_EVENT_RECORD ker);
//
//public:
//    EventHandler(Analyzer* analyzer);
//    //EventHandler();
//    void EventListener();
//};

class Analyzer {
public:
    Analyzer();
    void Start();
    bool Callback(PDU& pdu);
    void DisplayPacket(PDU& pdu);
    void UpdateFilter();
    void StartSniffing();
    void StopSniffing();
    void SavetoPCAP();
    void StartThreads();
private:
    queue<IP> packets;
    string filter;
    bool isSniffing;
    int count;
    OUIResolver ouiResolver;
    //EventHandler* handler;
};

#endif // PACKET_SNIFFER_H