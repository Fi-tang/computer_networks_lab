#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");
	struct ether_header *arp_ether_header;
	struct ether_arp *arp_ether_arp;
	char *arp_packet;
	arp_packet = (char *)malloc(sizeof(struct ether_header) +sizeof(struct ether_arp));
	arp_ether_header = (struct ether_header *)arp_packet;
	arp_ether_arp = (struct ether_arp*)(arp_packet + sizeof(struct ether_header));
	for(int i = 0; i < ETH_ALEN; i++){
		arp_ether_header -> ether_dhost[i] = 0xff;
		arp_ether_header -> ether_shost[i] = iface->mac[i];
	}
	arp_ether_header -> ether_type = htons(ETH_P_ARP);

	arp_ether_arp -> arp_hrd = htons(0X01);
	arp_ether_arp->arp_op = htons(0x01);
	arp_ether_arp -> arp_pro = htons(0x0800);
	arp_ether_arp -> arp_hln = 6;
	arp_ether_arp -> arp_pln = 4;
	for(int i = 0; i < ETH_ALEN; i++){
		arp_ether_arp -> arp_sha[i] = iface->mac[i];
		arp_ether_arp -> arp_tha[i] = 0x0;
	}
	arp_ether_arp -> arp_spa = htonl(iface->ip);
	arp_ether_arp -> arp_tpa = htonl(dst_ip);
	iface_send_packet(iface,  arp_packet , sizeof(struct ether_header) + sizeof(struct ether_arp));
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	fprintf(stderr, "TODO: send arp reply when receiving arp request.\n");
	if(iface->ip == ntohl(req_hdr-> arp_tpa)){
		struct ether_header *arp_ether_header;
		struct ether_arp *arp_ether_arp;
		char *arp_packet;
		arp_packet = (char *)malloc(sizeof(struct ether_header) + sizeof(struct ether_arp));
		arp_ether_header = (struct ether_header *)arp_packet;
		arp_ether_arp = (struct ether_arp *)(arp_packet + sizeof(struct ether_header));
		for(int i = 0; i < ETH_ALEN; i++){
			arp_ether_header -> ether_dhost[i] = req_hdr-> arp_sha[i];
			arp_ether_header -> ether_shost[i] = iface-> mac[i];
		}
		arp_ether_header -> ether_type = htons(ETH_P_ARP);

		arp_ether_arp -> arp_hrd = htons(0x01);
		arp_ether_arp -> arp_op = htons(0x02);
		arp_ether_arp -> arp_pro = htons(0x0800);
		arp_ether_arp -> arp_hln = 6;
		arp_ether_arp -> arp_pln = 4;
		for(int i = 0; i < ETH_ALEN; i++){
			arp_ether_arp -> arp_sha[i] = iface-> mac[i];
			arp_ether_arp -> arp_tha[i] = req_hdr-> arp_sha[i];
		}
		arp_ether_arp -> arp_spa = htonl(iface->ip);
		arp_ether_arp -> arp_tpa = req_hdr -> arp_spa;
		iface_send_packet(iface, arp_packet, sizeof(struct ether_header) + sizeof(struct ether_arp));
	}
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	fprintf(stderr, "TODO: process arp packet: arp request & arp reply.\n");
	struct ether_arp *arp_ether_arp;
	arp_ether_arp = (struct ether_arp *)(packet + sizeof(struct ether_header));
	if(arp_ether_arp -> arp_op == htons(0x01)){
		printf("111\n");
		arp_send_reply(iface, arp_ether_arp);
	}
	else if(arp_ether_arp -> arp_op == htons(0x02)){
		printf("1\n");
		arpcache_insert(ntohl(arp_ether_arp->arp_spa),arp_ether_arp->arp_sha);
	}
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		// log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		// log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
