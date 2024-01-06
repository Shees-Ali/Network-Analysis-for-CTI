#include "PacketSniffer.h"
#include "Analysis.h"

using namespace std;
using namespace Tins;

template <class T>
void takeInput(T& refrence)
{
    cin >> refrence;
    while (!cin)
    {
        cout << "Invalid Input, Try Again: ";
        cin.clear();
        fflush(stdin);
        cin >> refrence;
    }
}

OUIResolver::OUIResolver(const string& filename) {
    LoadOUIFile(filename);
}

string OUIResolver::GetNameForOUI(const string& inputMAC) const {
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

void OUIResolver::LoadOUIFile(const string& filename) {
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

Analyzer::Analyzer() : ouiResolver("assets/ouidb.txt") {
    //this->handler = new EventHandler();
    isSniffing = true;
    // Only capture UDP packets sent to port 53
    filter = "udp and dst port 53";
    iface = NetworkInterface::default_interface();
}

void showFinalAnalysis() {
    Analysis analysis;
    analysis.Print();

    cout << endl;
    system("pause");
    return;
}

void Analyzer::Start() {
    system("cls");
    int choice;
    cout << "------------ Network Analyzer for CTI ------------" << endl << endl;
    cout << "Filter :" << filter << endl << endl;
    wcout << "Default Interface :" << iface.friendly_name() << endl << endl;

    cout << "Select from below options :" << endl;
    cout << "1. Update Filter" << endl;
    cout << "2. Show Network Interfaces" << endl;
    cout << "3. Start Sniffing" << endl;
    cout << "4. Analyze Last Sniffing Session" << endl;
    cout << "5. Save Last Sniffing Session to PCAP file." << endl;
    cout << "6. Exit" << endl;
    cout << "Enter :";
    takeInput(choice);
    switch (choice)
    {
    case 1:
        UpdateFilter();
        break;
    case 2:
        ShowInterfaces();
        break;
    case 3:
        StartSniffing();
        break;
    case 4:
        if (!packets.empty()) {
            showFinalAnalysis();
        }
        else {
            cout << endl << "No Stored Session !" << endl;
        }
        break;
    case 5:
        if (!packets.empty()) {
            SavetoPCAP();
        }
        else {
            cout << endl << "No Stored Session !" << endl;
        }
        break;
    case 6:
        cout << "Closing !!!";
        exit(1);
    default:
        cout << "Invalid Choice !!!" << endl;
        Start();
        break;
    }
}

bool Analyzer::Callback(PDU& pdu) {
    // The packet probably looks like this:
    //
    // EthernetII / IP / UDP / RawPDU
    DisplayPacket(pdu);
    Sleep(1000);
    if (packets.size() >= count) {
        isSniffing = false;
        return isSniffing;
    }
    return isSniffing;
}

void Analyzer::DisplayPacket(PDU& pdu) {
    // Get the Ethernet PDU and convert src and dst address to valid Mac Addresses.
    EthernetII eth = pdu.rfind_pdu<EthernetII>();
    string src_range = HWAddress<6>(eth.src_addr()).to_string();
    string dst_range = HWAddress<6>(eth.dst_addr()).to_string();

    // Calling function to strip the OUI and get its name from the Mac Address.
    cout << "Src: " << ouiResolver.GetNameForOUI(src_range) << ",";
    cout << "Dst: " << ouiResolver.GetNameForOUI(dst_range) << endl;

    // Check if IP PDU exists, if it does then display source and destination IP addresses.
    if (pdu.find_pdu<IP>()) {
        IP ip = pdu.rfind_pdu<IP>();
        // Save the IP Packet to Queue in order to save to PCAP file later
        packets.push(ip);
        cout << "Src IP: " << ip.src_addr() << ",";
        cout << "Dst IP: " << ip.dst_addr() << endl;
    }

    // Check If UDP PDU exists, if it does then display corresponding info
    if (pdu.find_pdu<UDP>()) {
        UDP udp = pdu.rfind_pdu<UDP>();
        cout << "User Datagram Protocol, Src Port :" << udp.sport();
        cout << ", Dst Port :" << udp.dport() << endl;
        cout << "Size :" << udp.size() << " Bytes Captured" << endl;
    }

    // Check If TCP PDU exists, if it does then display corresponding info
    if (pdu.find_pdu<TCP>()) {
        TCP tcp = pdu.rfind_pdu<TCP>();
        cout << "Transfer Control Protocol, Src Port :" << tcp.sport();
        cout << ", Dst Port :" << tcp.dport() << endl;
        cout << "Size :" << tcp.size()  << " Bytes Captured" << endl;
    }

    
    // Retrieve the RawPDU layer, and construct a 
    // DNS PDU using its contents.
    // Retrieve the queries and print the domain name:
    DNS dns = pdu.rfind_pdu<RawPDU>().to<DNS>();
    for (const auto& query : dns.queries()) {
        cout << "Domain Name :" << query.dname() << endl;
    }

    cout << endl << endl << endl;

    Analysis analysis;
    analysis.GatherStatistics(pdu);
}

void Analyzer::UpdateFilter() {
    system("cls");
    string ip_addr = iface.ipv4_address().to_string();
    // Implementation for updating the filter
    cout << "Filter :" << filter << endl;

    cout << endl << "Below are the available filters :" << endl;
    cout << "1) ---Only retrieve IP Packets which are sent from " << ip_addr << endl;
    cout << "   ip src " << ip_addr << endl << endl;
    cout << "2) ---Retrieve packets that are from/to port 443" << endl;
    cout << "   tcp and port 443" << endl << endl;
    cout << "3) ---Retrieve UDP datagrams that have destination as port 53" << endl;
    cout << "   udp and dst port 53" << endl << endl;

    int choice;
    cout << "Enter filter index :";
    takeInput(choice);
    switch (choice)
    {
    case 1:
        filter = "ip src " + ip_addr;
        break;
    case 2:
        filter = "tcp";
        break;
    case 3:
        filter = "udp and dst port 53";
        break;
    default:
        cout << "Wrong Selection !!";
        UpdateFilter();
        break;
    }

    cout << endl << "Filter Updated !" << endl;
    cout << endl;
    system("pause");
    Start();
}

void Analyzer::ShowInterfaces() {
    system("cls");
    int i = 1;
    cout << "Interfaces :" << endl << endl;
    vector<NetworkInterface> interfaces = NetworkInterface::all();
    // Now iterate them
    for (const NetworkInterface& iface : interfaces) {
        cout << i << ") ";
        // First print the name (GUID)
        cout << "Interface name: " << iface.name();
        // Print the friendly name, a wstring that will contain something like 
        wcout << " (" << iface.friendly_name() << ")" << endl;
        cout << "Interface MAC Address: " << iface.hw_address() << endl << endl;
        cout << "Interface IPv4 Address: " << iface.ipv4_address() << endl << endl;
        vector<NetworkInterface::IPv6Prefix> ipv6 = iface.ipv6_addresses();
        if (!ipv6.empty()) {
            cout << "Interface IPv6 Addresses: " << iface.ipv4_address() << endl << endl;
            for (const NetworkInterface::IPv6Prefix& v6 : ipv6)
            {
                cout << v6.address << endl;
            }
        }
        i++;
    }

    cout << endl;
    system("pause");
    Start();
}

void Analyzer::StartSniffing() {
    system("cls");
    isSniffing = true;
    cout << "Enter the number of packets you want to sniff :";
    takeInput(count);
    // Sniff on the default interface
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter(filter);
    config.set_immediate_mode(false);
    Sniffer sniffer(iface.name(), config);
    // Start the capture
    sniffer.sniff_loop(make_sniffer_handler(this, &Analyzer::Callback));
    // Pause and wait for User Input
    cout << endl;
    system("pause");
    // Start the program again
    Start();
}

void Analyzer::SavetoPCAP() {
    PacketWriter writer = PacketWriter("sniffer_obj.pcap", DataLinkType<IP>());
    while (!packets.empty()) {
        // getting the latest packet
        writer.write(packets.front());
        // removing front element of queue
        packets.pop();
    }
    cout << "Saved to sniffer_obj.pcap !" << endl << endl;
    system("pause");
    Start();
}

