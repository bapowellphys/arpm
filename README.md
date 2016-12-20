# arpm
ARP spoofing monitor

 * DESCRIPTION: arpm.c is an ARP monitoring program written with libpcap in C 
 * that tries to detect ARP and MAC spoofing using a variety of methods.  At 
 * its core, arpm.c is a sniffer that collects ARP packets and dynamically 
 * builds a table of IP-MAC pairings: these hosts are stored in the file 
 * arp_associates.log and considered trusted (though arpm.c offers a way to 
 * verify authenticity that I'll mention shortly.) As ARP packets are collected,
 * the IP and MAC addresses appearing in the ARP header are compared against 
 * this list of associates; if a change in either the IP or MAC is detected, 
 * arpm.c writes an alert to a log file (and outputs to stdout). arpm.c also 
 * examines the Ethernet frame headers of all ARP packets, and alerts if the 
 * MAC address found there differs from that found in the ARP header: this 
 * could signify sloppy MAC spoofing. The program can be configured to alert 
 * on unicast ARP requests (via the ALERT UNICAST macro); this is an option 
 * because some networks have a legitimate use for unicast ARP requests.  The 
 * program can also be configured to do host checking (via the HOST_CHECKING 
 * macro) as a simple way of verifying host authenticity: when a new host is 
 * discovered on the network, arpm.c issues an ARP request for the new IP.  If 
 * the host is legit, it will reply with the same MAC address recorded from the
 * initial packet; if, however, this is a poisoned entry, the legit host will 
 * reply with a MAC address different from that recorded from the initial 
 * (evidently spoofed) packet.  Host checking makes use of nping, and so it 
 * must be installed and accessible to the program.  
 *
 * USAGE: arpm <interface> or arpm list, where <interface> is the network 
 * interface to sniff on (e.g. eth0) and arpm list will output the contents of 
 * arp_associates.log (the file is binary and so not human readable).
 * 
 * OUTPUT: arpm creates two files: arp_associates.log, a binary file that 
 * stores IP-MAC associates in one long contiguous list: <IP><MAC><IP><MAC>... 
 * and arp_alerts.log, a text file describing each alert along with a timestamp.
 *
 * COMPILING: gcc arpm.c -o arpm -lpcap
