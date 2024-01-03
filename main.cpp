#include <tins/tins.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <queue>
#include <Windows.h>
#include <conio.h>

using namespace std;
using namespace Tins;

class OUIResolver {
public:
    OUIResolver(const string& filename) {
        LoadOUIFile(filename);
    }

    string GetNameForOUI(const string& inputMAC) const {
        // Extract the first 6 characters (OUI) from the input MAC address
        string inputOUI = inputMAC.substr(0, 8);
        // Convert the input OUI to uppercase for case-insensitive comparison
        transform(inputOUI.begin(), inputOUI.end(), inputOUI.begin(), ::toupper);
        auto it = ouiMap.find(inputOUI);

        if (it != ouiMap.end()) {
            return it->second + "_" + inputOUI;
        }
        else {
            return inputOUI;
        }
    }
private:
    void LoadOUIFile(const string& filename) {
        // Open the file
        ifstream file(filename);
        if (!file.is_open()) {
            cerr << "Error opening the file." << endl;
            return;
        }
        // Read the file and populate the map
        string line;
        while (getline(file, line)) {
            istringstream iss(line);
            string identifier, name;
            if (iss >> identifier >> ws && getline(iss, name)) {
                ouiMap[identifier] = name;
            }
        }
        file.close();
    }
    map<string, string> ouiMap;
}; OUIResolver ouiResolver("assets/ouidb.txt");

class LayerFilter {

public:
    // Function for checking if Data Link Layer is Ethernet or Wifi
    string FilterDataLinkLayer(const PDU& pdu) {
        string layerName = "";
    }

    // Function for checking if Network layer is IPv4 or IPv6 
    string FilterNetworkLayer(const PDU& pdu) {

    }

    // Function for checking if Transport Layer is UDP or TCP
    string FilterTransportLayer(const PDU& pdu) {

    }

    bool checkIfIpv4(PDU& pdu) {
    }

    bool checkIfIpv6() {

    }

    bool checkIfEthernet() {

    }

    bool checkIfWIFI() {

    }

    bool checkIfUBP() {

    }

    bool checkIfTCP() {

    }
};

class NetworkAnalyzer {
    queue<IP> packets;
    string filter;
public:
    NetworkAnalyzer() {
        // Only capture udp packets sent to port 53
        filter = "udp and dst port 53";
    }
    bool Callback(PDU& pdu) {
        // The packet probably looks like this:
        //
        // EthernetII / IP / UDP / RawPDU
        DisplayPacket(pdu);
        return true;
    }

    void DisplayPacket(PDU& pdu) {
        EthernetII eth = pdu.rfind_pdu<EthernetII>();
        string src_range = HWAddress<6>(eth.src_addr()).to_string();
        string dst_range = HWAddress<6>(eth.dst_addr()).to_string();
        cout << "Src: " << ouiResolver.GetNameForOUI(src_range) << ",";
        cout << "Dst: " << ouiResolver.GetNameForOUI(dst_range) << endl;


        if (pdu.find_pdu<IP>()) {
            IP ip = pdu.rfind_pdu<IP>();
            packets.push(ip);
            cout << "Src IP: " << ip.src_addr() << ",";
            cout << "Dst IP: " << ip.dst_addr() << endl;
        }

            // Retrieve the RawPDU layer, and construct a 
            // DNS PDU using its contents.
            // Retrieve the queries and print the domain name:
            DNS dns = pdu.rfind_pdu<RawPDU>().to<DNS>();
            for (const auto& query : dns.queries()) {
                cout << "Domain Name :" << query.dname() << endl;
            }
    };

    void StartSniffing() {
        // Sniff on the default interface
        NetworkInterface iface = NetworkInterface::default_interface();
        SnifferConfiguration config;
        config.set_promisc_mode(true);
        config.set_filter(filter);
        Sniffer sniffer(iface.name(), config);
        // Start the capture
        sniffer.sniff_loop(make_sniffer_handler(this, &NetworkAnalyzer::Callback));
    }

    void SavetoPCAP() {
        PacketWriter writer = PacketWriter("sniffer_obj.pcap", DataLinkType<IP>());
        while (!packets.empty()) {
            // getting the latest packet
            writer.write(packets.front());
            // removing front element of queue
            packets.pop();
        }
    }
};


int main(int argc, char* argv[]) {
    NetworkAnalyzer analyzer;
    analyzer.StartSniffing();
}