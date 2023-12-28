#include <tins/tins.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>

using namespace std;
using namespace Tins;

class OUIResolver {
public:
    OUIResolver(const string& filename) {
        loadOUIFile(filename);
    }

    string getNameForOUI(const string& inputMAC) const {
        // Extract the first 6 characters (OUI) from the input MAC address
        string inputOUI = inputMAC.substr(0, 8);
        // Convert the input OUI to uppercase for case-insensitive comparison
        transform(inputOUI.begin(), inputOUI.end(), inputOUI.begin(), ::toupper);
        cout << inputOUI << endl;
        // Search for the name in the map
        auto it = find_if(ouiMap.begin(), ouiMap.end(),
            [&inputOUI](const auto& pair) {
                return pair.first == inputOUI;
            }
        );

        return (it != ouiMap.end()) ? it->second : "Name not found for the given OUI.";
    }

private:
    void loadOUIFile(const string& filename) {
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
};

OUIResolver ouiResolver("assets/ouidb.txt");

bool callback(const PDU& pdu) {
    // The packet probably looks like this:
    //
    // EthernetII / IP / UDP / RawPDU
    //
    // So we retrieve the RawPDU layer, and construct a 
    // DNS PDU using its contents.
    EthernetII eth = pdu.rfind_pdu<EthernetII>();
    string src_range = HWAddress<6>(eth.src_addr()).to_string();
    string dst_range = HWAddress<6>(eth.dst_addr()).to_string();
    cout << ouiResolver.getNameForOUI(src_range) << endl;
    DNS dns = pdu.rfind_pdu<RawPDU>().to<DNS>();
    //const UDP& udp = pdu.rfind_pdu<UDP>();
    ////cout << udp.extract_metadata();
    //// Retrieve the queries and print the domain name:
    for (const auto& query : dns.queries()) {
        cout << query.dname() << endl;
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