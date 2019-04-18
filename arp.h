#include <stdint.h>
#pragma once
#pragma pack(push,1)

#define REQUEST 1
#define REPLY 2

struct Ethernet_header{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t type;
};

struct ARP_header{
    uint16_t htype;
    uint16_t ptype;
    uint8_t hsize;
    uint8_t psize;
    uint16_t opcode;
    uint8_t smac_addr[6];
    uint32_t sip_addr;
    uint8_t tmac_addr[6];
    uint32_t tip_addr;
};

#pragma pack(pop)

