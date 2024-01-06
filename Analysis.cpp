#include "Analysis.h"


int Analysis::totalIPV4 = 0;
int Analysis::totalIPV6 = 0;
int Analysis::totalUDP = 0;
int Analysis::totalTCP = 0;

void Analysis::GatherStatistics(PDU& pdu)
{
    if (pdu.find_pdu<IP>()) {
        IP ip = pdu.rfind_pdu<IP>();

        // Checking IP version
        if (ip.version() == 4) {
            totalIPV4++;
        }
        else if (ip.version() == 6) {
            totalIPV6++;
        }

        /*cout << "Src IP: " << ip.src_addr() << ",";
        cout << "Dst IP: " << ip.dst_addr() << endl;*/
        if (pdu.find_pdu<UDP>()) {
            UDP udp = pdu.rfind_pdu<UDP>();
            totalUDP++;
        }

        // Check If TCP PDU exists, if it does then display corresponding info
        if (pdu.find_pdu<TCP>()) {
            TCP tcp = pdu.rfind_pdu<TCP>();
            totalTCP++;
        }

    }
}

Analysis::Analysis()
{
}



void Analysis::Print() {
	cout << "---------------- Analysis of Last Session ----------------" << endl;
	cout << "Total IPV4: " << totalIPV4 << endl
		<< "Total IPV5: " << totalIPV6 << endl
		<< "Total UDP: " << totalUDP << endl
		<< "Total TCP: " << totalTCP << endl;
}