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
	bool isSniffing;
public:
	NetworkAnalyzer() {
		isSniffing = true;
		// Only capture udp packets sent to port 53
		filter = "udp and dst port 53";
	}
	bool Callback(PDU& pdu) {
		// The packet probably looks like this:
		//
		// EthernetII / IP / UDP / RawPDU
		DisplayPacket(pdu);


		return isSniffing;
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

	void StopSniffing() {
		isSniffing = false;
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
	thread snifferThread(&NetworkAnalyzer::StartSniffing, &analyzer);
	thread eventListenerThread(&EventHandler::EventListener, &handler);

	snifferThread.join();
	//handler.EventListener();
	eventListenerThread.join();
}