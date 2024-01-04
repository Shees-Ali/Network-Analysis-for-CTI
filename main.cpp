#include <tins/tins.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <queue>
#include <windows.h>
#include <conio.h>
#include <thread>

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
};

class NetworkAnalyzer {
	queue<IP> packets;
	string filter;
	bool isSniffing;
public:
	NetworkAnalyzer() {
		isSniffing = true;
		// Only capture udp packets sent to port 53
		filter = "udp and dst port 53";
	}
	void Start() {
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
		default:
			cout << "Invalid Choice !!!" << endl;
			Start();
			break;
		}
	} 

	bool Callback(PDU& pdu) {
		// The packet probably looks like this:
		//
		// EthernetII / IP / UDP / RawPDU
		DisplayPacket(pdu);
		return isSniffing;
	}

	void DisplayPacket(PDU& pdu) {
		// Get the Ethernet PDU and convert src and dst address to valid Mac Addresses.
		EthernetII eth = pdu.rfind_pdu<EthernetII>();
		string src_range = HWAddress<6>(eth.src_addr()).to_string();
		string dst_range = HWAddress<6>(eth.dst_addr()).to_string();

		// Calling function to strip the OUI and get it's name from the Mac Address.
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

		cout << endl;
	};

	void UpdateFilter() {
		//system("cls");
		//string updated_filter;
		//cout << "Current Filter :" << filter;
		//cout << endl << "Enter Updated Filter :";
		//getline(cin ,updated_filter);

		//filter = updated_filter;
		//cout << "Filter Updated !";
		//Start();
	}

	void StartSniffing() {
		// Clear Console Screen
		system("cls");

		//std::cout << '-' << std::flush;
		//for (;;) {
		//	Sleep(10);
		//	std::cout << "\b\\" << std::flush;
		//	Sleep(10);
		//	std::cout << "\b|" << std::flush;
		//	Sleep(10);
		//	std::cout << "\b/" << std::flush;
		//	Sleep(10);
		//	std::cout << "\b-" << std::flush;
		//}

		isSniffing = true;
		// Sniff on the default interface
		NetworkInterface iface = NetworkInterface::default_interface();
		SnifferConfiguration config;
		config.set_promisc_mode(true);
		config.set_filter(filter);
		Sniffer sniffer(iface.name(), config);
		// Start the capture
		sniffer.sniff_loop(make_sniffer_handler(this, &NetworkAnalyzer::Callback));
	}

	void StopSniffing() {
		isSniffing = false;
		Start();
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

class EventHandler {
	DWORD cNumRead, fdwMode, i;
	INPUT_RECORD irInBuf[128];
	int counter = 0;
	NetworkAnalyzer* analyzer;

	VOID ErrorExit(string lpszMessage)
	{
		fprintf(stderr, "%s\n", lpszMessage);

		// Restore input mode on exit.

		SetConsoleMode(hStdin, fdwSaveOldMode);

		ExitProcess(0);
	}

	VOID KeyEventProc(KEY_EVENT_RECORD ker)
	{
		if (ker.bKeyDown)
			return;
		char pressedKey =  (char)ker.wVirtualKeyCode;
		switch (pressedKey)
		{
		case 'Q':
			cout << endl << "Quiting Sniffing" << endl;
			analyzer->StopSniffing();
			break;
		case 'S':
			cout << endl << "Saving to PCAP File" << endl;
			analyzer->StopSniffing();
			analyzer->SavetoPCAP();
			break;
		default:
			break;
		}
	}
public:
	EventHandler(NetworkAnalyzer* analyzer) {
		this->analyzer = analyzer;
	}

	void EventListener() {
		// Get the standard input handle.
		hStdin = GetStdHandle(STD_INPUT_HANDLE);
		if (hStdin == INVALID_HANDLE_VALUE)
			ErrorExit("GetStdHandle");
		// Save the current input mode, to be restored on exit.
		if (!GetConsoleMode(hStdin, &fdwSaveOldMode))
			ErrorExit("GetConsoleMode");
		// Loop to read and handle the next 100 input events.
		while (counter++ <= 100)
		{
			// Wait for the events.
			if (!ReadConsoleInput(
				hStdin,      // input buffer handle
				irInBuf,     // buffer to read into
				128,         // size of read buffer
				&cNumRead)) // number of records read
				ErrorExit("ReadConsoleInput");

			// Dispatch the events to the appropriate handler.
			for (i = 0; i < cNumRead; i++)
			{
				switch (irInBuf[i].EventType)
				{
				case KEY_EVENT: // keyboard input
					KeyEventProc(irInBuf[i].Event.KeyEvent);
					break;

				case MOUSE_EVENT: // mouse input
					break;

				case WINDOW_BUFFER_SIZE_EVENT: // scrn buf. resizing
					break;

				case FOCUS_EVENT:  // disregard focus events

				case MENU_EVENT:   // disregard menu events
					break;

				default:
					ErrorExit("Unknown event type");
					break;
				}
			}
		}
		// Restore input mode on exit.
		SetConsoleMode(hStdin, fdwSaveOldMode);
	}
};

int main(int argc, char* argv[]) {
	NetworkAnalyzer analyzer;
	EventHandler handler(&analyzer);

	// Utilizing threading to run the functions simultaneously.
	thread snifferThread(&NetworkAnalyzer::Start, &analyzer);
	thread eventListenerThread(&EventHandler::EventListener, &handler);

	// Wait for both threads to end
	snifferThread.join();
	eventListenerThread.join();
}