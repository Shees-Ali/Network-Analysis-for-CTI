#include <tins/tins.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>

using namespace std;
using namespace Tins;

string getNameForOUI(const string& inputOUI) {
    // Open the file
    ifstream file("assets/ouidb.txt"); // Replace "oui.txt" with the actual filename
    if (!file.is_open()) {
        return "Error opening the file.";
    }
    map<string, string> ouiMap;
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
    string uppercasedOUI = inputOUI;
    transform(uppercasedOUI.begin(), uppercasedOUI.end(), uppercasedOUI.begin(), ::toupper);
    // Search for the name in the map
    auto it = ouiMap.find(uppercasedOUI);
    if (it != ouiMap.end()) {
        return it->second;
    }
    else {
        return "Name not found for the given OUI.";
    }
}

bool callback(const PDU& pdu) {
    // The packet probably looks like this:
    //
    // EthernetII / IP / UDP / RawPDU
    //
    // So we retrieve the RawPDU layer, and construct a 
    // DNS PDU using its contents.
    EthernetII eth = pdu.rfind_pdu<EthernetII>();
    auto src_range = HWAddress<6>(eth.dst_addr()) / 24;
    auto dst_range = HWAddress<6>(eth.src_addr()) / 24;

    DNS dns = pdu.rfind_pdu<RawPDU>().to<DNS>();
    //const UDP& udp = pdu.rfind_pdu<UDP>();
    ////cout << udp.extract_metadata();
    //// Retrieve the queries and print the domain name:
    for (const auto& query : dns.queries()) {
        cout << query.dname() << std::endl;
    }
    return true;
}

int main(int argc, char* argv[]) {
    NetworkInterface iface = NetworkInterface::default_interface();
    // Sniff on the provided interface in promiscuos mode
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    // Only capture udp packets sent to port 53
    config.set_filter("udp and dst port 53");
    Sniffer sniffer(iface.name(), config);
    // Start the capture
    sniffer.sniff_loop(callback);
}