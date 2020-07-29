#pragma once

#include <stdint.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

extern char local_ip[16];
extern u_char local_mac[6];

void GetLocalAddr(char *dev, const char *hw);

void packet_setting(EthArpPacket &packet, uint8_t *dmac, uint16_t op, char *sip, uint8_t *tmac, char *sender_ip);

void send_packet(EthArpPacket packet, pcap_t* handle);

int check_reply_packet(EthArpPacket attack_packet , EthArpPacket request_packet);
