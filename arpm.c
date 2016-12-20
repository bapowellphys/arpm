/*
 *
 * NAME: arpm.c
 *
 * AUTHOR: Brian Powell
 *
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
 *
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>

#define MAX_HOSTS 256	/* Number of hosts to keep track of */
#define PCAP_BUF_SIZE 2048 
#define ALERT_UNICAST 0   /* Should we alert on unicast ARP requests? (default is 0: no) */
#define HOST_CHECKING 0   /* Should we trust new hosts?  If no, send ARP request to verify 
                             MAC address.  (default is 0: no).  Requires nping. */

void format_addr(u_char *, u_char *, int);
void print_associates(FILE * );

/* Ethernet Header */

typedef struct ethhdr{
    u_char ether_dstMAC[6];
    u_char ether_srcMAC[6];
    u_short ether_type;  	/* IP, ARP, RARP  */
} ethhdr_t;

/* ARP Header, IPv4 */ 

typedef struct arphdr { 
    u_int16_t htype;    	/* Ethernet, etc */           
    u_int16_t ptype;    	/* IPv4, IPv6 */           
    u_char hlen;        	/* MAC Address  Length */ 
    u_char plen;        	/* IP Address Length */ 
    u_int16_t oper;     	/* ARP Request, ARP Reply */       
    u_char arp_srcMAC[6];      	/* Source MAC Address */ 
    u_char srcIP[4];      	/* Source IP Address */       
    u_char arp_dstMAC[6];      	/* Destination MAC Address */ 
    u_char dstIP[4];      	/* Destination IP Address */    
} arphdr_t; 


typedef struct files {
    FILE * arp_associates; /* File of IPs and MACs of associates (legit hosts) on the subnet */
    FILE * arp_alerts;     /* Log file of all alerts */
} files_t;


  /* This is our libpcap "callback" function; it gets called every time we 
     receive a packet matching our filter (to be defined below).  This 
     function analyzes each packet and performs all the logic.  It's the 
     guts of the code. We pass our log files in via the u_char * args argument. */ 
 
void proc_packet(u_char * args,const struct pcap_pkthdr * pkthdr,const u_char * packet)
{

 files_t * Files = (files_t *) args; // Cast u_char * args to files_t struct
 static int file_open = 0;
 static int iter, hosts;
 static u_char data[MAX_HOSTS*10]; /* Amount of data for each packet: 4 byres for
                                     the IP, 6 for the MAC */
 int j, ipmatch, macmatch; 
  
 char time_buff[20]; 
 time_t now = time(NULL);
 
 u_char form_addr1[18];  /* Big enough to hold 1 formated MAC address. We'll need several of these. */
 u_char form_addr2[18];  
 u_char form_addr3[18]; 
 u_char form_addr4[18]; 

 u_char * form_addrp[4];

 form_addrp[0] = form_addr1;  /* Need a pointer for each of the formated addresses */
 form_addrp[1] = form_addr2;  
 form_addrp[2] = form_addr3;
 form_addrp[3] = form_addr4;  

 u_char command[50];
	
  /* When sniffer is launched, load associates from file into buffer */

 if (file_open == 0)
 {
   /* Allocate and load buffer. */
   
   fprintf(stderr,"Reading ARP associates file...");
  
   iter = fread(data,1,MAX_HOSTS*10,Files->arp_associates);
   
   hosts = iter/10;
   fprintf(stderr,"found %d known hosts.\n",hosts);
   file_open = 1;
 }
  
 ethhdr_t * ethheader = NULL;       /* Pointer to the Ethernet header */ 
 arphdr_t * arpheader = NULL;       /* Pointer to the ARP header */ 

 ethheader = (ethhdr_t *)(packet); /* Find Ethernet header in packet */
 arpheader = (arphdr_t *)(packet+14); /* Next, find ARP header in packet */ 

  /* If packet is Ethernet and IPv4, let's analyze it */ 

 if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800)
 { 
    /* Grab the source IP and MAC from the packet. */
    
   format_addr(form_addrp[0],&(arpheader->srcIP[0]),1);
   format_addr(form_addrp[1],&(ethheader->ether_srcMAC[0]),0);
   format_addr(form_addrp[2],&(arpheader->arp_srcMAC[0]),0);

  /* Sloppy MAC spoofing? Low hanging fruit, but it might pay off: check to see 
     if the source MAC in the Ethernet frame matches the source MAC in the ARP header */

   if (strcmp(form_addr2,form_addr3)) /* If Ethernet and ARP MACs differ, Alert! */
   {
     strftime(time_buff, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));
     fprintf(Files->arp_alerts, "%s: MAC spoofing alert: host %s has mismatched ethernet MAC: %s and ARP MAC: %s via %s\n",time_buff, form_addr1,form_addr2,form_addr3,(ntohs(arpheader->oper) == 1)? "ARP Request" : "ARP Reply");
     fflush(Files->arp_alerts);
     fprintf(stderr, "%s: MAC spoofing alert: host %s has mismatched ethernet MAC: %s and ARP MAC: %s via %s\n",time_buff, form_addr1,form_addr2,form_addr3,(ntohs(arpheader->oper) == 1)? "ARP Request" : "ARP Reply");
  }  
  
   /* Some ARP spoofing is in the form of unicast ARP requests, which seldom have a legit role on the network */ 
  
   if ((ALERT_UNICAST && (ntohs(arpheader->oper) == 1))&&(strcmp(form_addr3,"0:0:0:0:0:0")))  /* Alert on unicast ARP requests */
   {   
     /* ARP Broadcast requests have MAC 0:0:0:0:0:0 in the ARP header */
  
     strftime(time_buff, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));
     fprintf(Files->arp_alerts, "%s: Unicast ARP request from host %s\n",time_buff,form_addr1);
     fflush(Files->arp_alerts);
     fprintf(stderr, "%s: Unicast ARP request from host %s\n",time_buff,form_addr1);
   } 

    /* IF hosts > 0, then we've got some stored associates.  Compare ARP packet against these records */

   for(j=0;j < hosts;j++)
   {
     format_addr(form_addrp[1],&data[10*j],1);
     format_addr(form_addrp[3],&data[10*j+4],0);
     
     ipmatch = strcmp(form_addr1,form_addr2);
     macmatch = strcmp(form_addr3,form_addr4);
    
     if ((ipmatch&&!macmatch)||(!ipmatch&&macmatch))  /* IP or MAC is different, Alert! */
     {
       strftime(time_buff, 20, "%Y-%m-%d %H:%M:%S", localtime(&now));
       if ((ipmatch&&(strcmp(form_addr1,"0.0.0.0")))||(ipmatch&&(strcmp(form_addr1,"255.255.255.255"))))
       {
         fprintf(Files->arp_alerts, "%s: IP change Alert: IP %s associated with MAC %s was changed via %s to %s\n", time_buff,form_addr2,form_addr4,(ntohs(arpheader->oper) == 1)? "ARP Request" : "ARP Reply",form_addr1);	
         fflush(Files->arp_alerts);
         fprintf(stderr, "%s: IP change Alert: IP %s associated with MAC %s was changed via %s to %s\n", time_buff,form_addr2,form_addr4,(ntohs(arpheader->oper) == 1)? "ARP Request" : "ARP Reply",form_addr1);	
       } 
       else
       {
         fprintf(Files->arp_alerts, "%s: MAC change Alert: MAC %s associated with IP %s was changed via %s to %s\n", time_buff,form_addr4,form_addr2,(ntohs(arpheader->oper) == 1)? "ARP Request" : "ARP Reply",form_addr3);	
         fflush(Files->arp_alerts);
         fprintf(stderr, "%s: MAC change Alert: MAC %s associated with IP %s was changed via %s to %s\n", time_buff,form_addr4,form_addr2,(ntohs(arpheader->oper) == 1)? "ARP Request" : "ARP Reply",form_addr3);	
       }       
       break;
     }
            
     if (!ipmatch&&!macmatch)  /* We've got a match.  Break. */
     {
       break;
     }
   }  

   if ((ipmatch&&macmatch)||!hosts) /* Either new host or first host. Add it! */
   {
     if (hosts < MAX_HOSTS)
     { 
       fwrite(&(arpheader->srcIP[0]),4,1,Files->arp_associates);   
       fwrite(&(arpheader->arp_srcMAC[0]),6,1,Files->arp_associates);   
       fflush(Files->arp_associates);
       
       memcpy(&data[10*hosts],&(arpheader->srcIP[0]),4);
       memcpy(&data[10*hosts+4],&(arpheader->arp_srcMAC[0]),6);
       hosts++;
  //     hosts += 1;
       fprintf(stderr,"\n> New host %s at %s discovered via %s\n",form_addr3,form_addr1,(ntohs(arpheader->oper) == 1)? "ARP Request" : "ARP Reply");
    
       if (HOST_CHECKING)
       {
         sprintf(command,"nping --arp-type arp %s",form_addr1);
         system(command);
       }
     }
     else
     {
       fprintf(stderr,"Maximum number of hosts exceeded.");
     } 
   }  
 }
} 

int main(int argc, char *argv[])
{

 u_int32_t ip = 0, mask = 0;  	  /* Network Address and Netmask   */ 
 struct bpf_program filter;      	  /* Place to store the BPF filter program  */ 
 struct files Files;			  /* Log files we'll be creating */
 char errbuf[PCAP_ERRBUF_SIZE]; 	  /* Error buffer  */ 
 pcap_t * handle = NULL;         	  /* Network interface handle  */ 
 struct pcap_pkthdr pkthdr; 		  /* Packet information (inc. timestamp, size, ...) */ 
 const u_char *packet = NULL; 		  /* Raw packet data   */ 
 char * dev = argv[1];  		  /* User-supplied network interface */
 //int i,k=0; 
 
 memset(errbuf,0,PCAP_ERRBUF_SIZE);   /* Zero out the error buffer */

 Files.arp_associates = fopen("arp_associates.log", "a+");
 Files.arp_alerts = fopen("arp_alerts.log", "a");

 if (argc != 2)
 { 
   printf("USAGE: arpm <interface> or arpm list\n"); 
   return 1; 
 }
 

 if (!strcmp(argv[1],"list"))
 {
   print_associates(Files.arp_associates);
   return 0;
 } 
 /* Open network device for packet capture, and don't wait any time to process
    packets (the arg -1 in pcap_open_live). */
 
 handle = pcap_open_live(dev, PCAP_BUF_SIZE, 0, -1 , errbuf);

 if (handle == NULL)
 {
   fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
   return 2;
 }
 
 /* Get network settings */
 
 if (pcap_lookupnet(dev , &ip, &mask, errbuf) == -1)
 {
   fprintf(stderr, "Couldn't get network settings on %s: %s\n", dev, errbuf);
   return 2;
 }
 
 /* Compile the filter expression into a BPF filter program. Filter expressions are 
    BPF-style, same as tcpdump.  We are only interested in ARP packets. */
 
 if (pcap_compile(handle, &filter, "arp", 1, mask) == -1)
 {
   fprintf(stderr, "Couldn't compile filter: %s\n", pcap_geterr(handle));
   return 2;
 }

 /* Load the filter program into the packet capture device. */ 

 if (pcap_setfilter(handle, &filter) == -1)
 {
   fprintf(stderr, "Couldn't load filter: %s\n", pcap_geterr(handle));
   return 2; 
 }

 /* OK! Now we're ready to sniff some ARP packets.  pcap_loop listens indefinitely 
    for packets matching the applied filter; in our case, it grabs all ARP packets
    off the wire and sends them to our "callback" function, proc_packet. */
 
 fprintf(stderr,"Sniffing for ARP packets....\n");
 
 pcap_loop(handle, -1, proc_packet, (u_char *)&Files); 

 return 0; 

}

void format_addr(u_char * f_addrp, u_char * addr,int type)
{
  /* Convert binary IP/MAC addresses into readable x.x.x.x and y:y:y:y:y:y format */ 
 
  int i;
  if(type)
  {
    for(i=0;i<3;i++)
    {
      f_addrp += sprintf(f_addrp,"%d.",(int)addr[i]);
    }    
    if(i==3)
    {
      f_addrp += sprintf(f_addrp,"%d",(int)addr[i]);
    }
  } 
  else
  {    
    for(i=0;i<5;i++)
    {
      f_addrp += sprintf(f_addrp,"%02X:",(int)addr[i]);
    }    
    if(i==5)
    {    
      f_addrp += sprintf(f_addrp,"%02X",(int)addr[i]);
    } 
  }
} 
  
void print_associates(FILE * file)
{
  u_char file_contents[MAX_HOSTS*10]; 
  int i,k = 0;
 
  fprintf(stdout,"Known associates:\n");
  k = fread(file_contents,1,MAX_HOSTS*10,file);
  
  for( i=0; i<k; i++)
  {
    if(i%10< 3)
    {
      fprintf(stdout,"%d.",file_contents[i]);
    } 
    if(i%10==3)
    {
      fprintf(stdout,"%d ",file_contents[i]);
    } 
    if((3 < i%10)&&(i%10<9))
    {
      fprintf(stdout,"%02X:",file_contents[i]);
    } 
    if(i%10==9)
    {
      fprintf(stdout,"%02X\n",file_contents[i]);
    } 
  }
}

