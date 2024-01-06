#include "Analysis.h"

int Analysis::totalIPV4 = 0;
int Analysis::totalIPV6 = 0;
int Analysis::totalUDP = 0;
int Analysis::totalTCP = 0;
int Analysis::totalBytes = 0;
string Analysis::mostCommonDstIp;
string Analysis::mostCommonSrcIp;

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
        //Checking Most Common Destination Ip:
        Analysis::DstHeap.insert(ip.dst_addr().to_string());
        Analysis::mostCommonDstIp = Analysis::DstHeap.GetLargest();

        //Checking Most Common Source Ip:
        Analysis::SrcHeap.insert(ip.src_addr().to_string());
        Analysis::mostCommonSrcIp = Analysis::SrcHeap.GetLargest();
    }

    // Check If UDP PDU exists
    if (pdu.find_pdu<UDP>()) {
        totalUDP++;
        UDP udp = pdu.rfind_pdu<UDP>();
        int bytes = udp.size();
        totalBytes += bytes;
    }


    // Check If TCP PDU exists
    if (pdu.find_pdu<TCP>()) {
        TCP tcp = pdu.rfind_pdu<TCP>();
        totalTCP++;
        int bytes = tcp.size();
        totalBytes += bytes;
    }
}

Analysis::Analysis()
{
}

void Analysis::Print() {
	cout << "---------------- Analysis of Last Session ----------------" << endl;
    cout << "Total IPV4: " << totalIPV4 << endl
        << "Total IPV6: " << totalIPV6 << endl
        << "Total UDP: " << totalUDP << endl
        << "Total TCP: " << totalTCP << endl
        << "Total Bytes Transferred: " << totalBytes << " Bytes" << endl
        << "Most Common Destination IP: " << Analysis::mostCommonDstIp << endl
        << "Most Common Source IP: " << Analysis::mostCommonSrcIp << endl;
}