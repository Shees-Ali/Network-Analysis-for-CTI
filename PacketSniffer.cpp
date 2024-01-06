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

HANDLE hStdin;
DWORD fdwSaveOldMode;

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

string LayerFilter::FilterDataLinkLayer(const PDU& pdu) {
    // Implementation for filtering Data Link Layer (Ethernet or Wifi)
    // ...
    return "";
}

string LayerFilter::FilterNetworkLayer(const PDU& pdu) {
    // Implementation for filtering Network Layer (IPv4 or IPv6)
    // ...
    return "";
}

string LayerFilter::FilterTransportLayer(const PDU& pdu) {
    // Implementation for filtering Transport Layer (UDP or TCP)
    // ...
    return "";
}

Analyzer::Analyzer() : ouiResolver("assets/ouidb.txt") {
    //this->handler = new EventHandler();
    isSniffing = true;
    // Only capture UDP packets sent to port 53
    filter = "udp and dst port 53";
}

void showFinalAnalysis() {
    Analysis analysis;
    analysis.Print();
}

void Analyzer::Start() {
    system("cls");
    int choice;
    cout << "------------ Network Analyzer for CTI ------------" << endl;
    cout << "Filter :" << filter << endl << endl;
    cout << "Select from below options :" << endl;
    cout << "1. Update Filter" << endl;
    cout << "2. Start Sniffing" << endl;
    cout << "3. Analyze Last Sniffing Session" << endl;
    cout << "4. Save Last Sniffing Session to PCAP file." << endl;
    cout << "Enter :";
    takeInput(choice);
    switch (choice)
    {
    case 1:
        UpdateFilter();
        break;
    case 2:
        StartSniffing();
        break;
    case 3:
        showFinalAnalysis();
        break;
    case 4:
        SavetoPCAP();
        break;
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
    if (packets.size() == (count-1)) {
        return false;
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
    }

    // Retrieve the RawPDU layer, and construct a 
    // DNS PDU using its contents.
    // Retrieve the queries and print the domain name:
    DNS dns = pdu.rfind_pdu<RawPDU>().to<DNS>();
    for (const auto& query : dns.queries()) {
        cout << "Domain Name :" << query.dname() << endl;
    }

    Analysis analysis;
    analysis.GatherStatistics(pdu);

    cout << endl;
}

void Analyzer::UpdateFilter() {
    // Implementation for updating the filter
    // ...
}

void Analyzer::StartSniffing() {
    system("cls");
    isSniffing = true;
    cout << "Enter the number of packets you want to sniff :";
    takeInput(count);
    // Sniff on the default interface
    NetworkInterface iface = NetworkInterface::default_interface();
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter(filter);
    Sniffer sniffer(iface.name(), config);
    // Start the capture
    sniffer.sniff_loop(make_sniffer_handler(this, &Analyzer::Callback));
    // Start the program again
    Start();
}

//void Analyzer::StartThreads() {
//    // Utilizing threading to run the functions simultaneously.
//    thread snifferThread(&Analyzer::StartSniffing, this);
//    thread eventListenerThread(&EventHandler::EventListener, handler);
//    // Wait for both threads to end
//    snifferThread.join();
//    eventListenerThread.join();
//}

void Analyzer::StopSniffing() {
    isSniffing = false;
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
}

//EventHandler::EventHandler(Analyzer* analyzer) {
//    this->analyzer = analyzer;
//}
//EventHandler::EventHandler() {}
//
//void EventHandler::EventListener() {
//    // Get the standard input handle.
//    hStdin = GetStdHandle(STD_INPUT_HANDLE);
//    if (hStdin == INVALID_HANDLE_VALUE)
//        ErrorExit("GetStdHandle");
//    // Save the current input mode, to be restored on exit.
//    if (!GetConsoleMode(hStdin, &fdwSaveOldMode))
//        ErrorExit("GetConsoleMode");
//    // Loop to read and handle the next 100 input events.
//    while (counter++ <= 100)
//    {
//        // Wait for the events.
//        if (!ReadConsoleInput(
//            hStdin,      // input buffer handle
//            irInBuf,     // buffer to read into
//            128,         // size of read buffer
//            &cNumRead)) // number of records read
//            ErrorExit("ReadConsoleInput");
//
//        // Dispatch the events to the appropriate handler.
//        for (i = 0; i < cNumRead; i++)
//        {
//            switch (irInBuf[i].EventType)
//            {
//            case KEY_EVENT: // keyboard input
//                KeyEventProc(irInBuf[i].Event.KeyEvent);
//                break;
//
//            case MOUSE_EVENT: // mouse input
//                break;
//
//            case WINDOW_BUFFER_SIZE_EVENT: // scrn buf. resizing
//                break;
//
//            case FOCUS_EVENT:  // disregard focus events
//
//            case MENU_EVENT:   // disregard menu events
//                break;
//
//            default:
//                ErrorExit("Unknown event type");
//                break;
//            }
//        }
//    }
//    // Restore input mode on exit.
//    SetConsoleMode(hStdin, fdwSaveOldMode);
//}
//
//VOID EventHandler::ErrorExit(string lpszMessage)
//{
//    fprintf(stderr, "%s\n", lpszMessage.c_str());
//
//    // Restore input mode on exit.
//
//    SetConsoleMode(hStdin, fdwSaveOldMode);
//
//    ExitProcess(0);
//}
//
//VOID EventHandler::KeyEventProc(KEY_EVENT_RECORD ker)
//{
//    if (ker.bKeyDown)
//        return;
//    char pressedKey = (char)ker.wVirtualKeyCode;
//    switch (pressedKey)
//    {
//    case 'Q':
//        cout << endl << "Quitting Sniffing" << endl;
//        //analyzer->StopSniffing();
//        break;
//    case 'S':
//        cout << endl << "Saving to PCAP File" << endl;
//  /*      analyzer->StopSniffing();
//        analyzer->SavetoPCAP();*/
//        break;
//    default:
//        break;
//    }
//}
