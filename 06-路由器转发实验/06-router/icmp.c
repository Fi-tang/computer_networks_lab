#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <stdio.h>
#include <stdlib.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	fprintf(stderr, "TODO: malloc and send icmp packet.\n");
	const struct ether_header *icmp_ether_header0;
	icmp_ether_header0 = (const struct ether_header *)in_pkt;
	const struct iphdr *icmp_iphdr0;
	icmp_iphdr0 = (const struct iphdr*)(in_pkt + sizeof(struct ether_header));

	char *icmp_packet;

	if(type == ICMP_ECHOREPLY){
		icmp_packet = (char *)malloc(len);
		memcpy(icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr), in_pkt + sizeof(struct ether_header) + IP_HDR_SIZE(icmp_iphdr0), len - sizeof(struct ether_header) - IP_HDR_SIZE(icmp_iphdr0));
	}
	else{
		icmp_packet = (char *)malloc(sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) +  IP_HDR_SIZE(icmp_iphdr0) + 8);
	}
	struct ether_header *icmp_ether_header;
	icmp_ether_header = (struct ether_header *)icmp_packet;
	struct iphdr *icmp_iphdr;
	icmp_iphdr = (struct iphdr *)(icmp_packet + sizeof(struct ether_header));
	struct icmphdr *icmp_icmphdr;
	icmp_icmphdr = (struct icmphdr *)(icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	for(int i = 0; i < ETH_ALEN; i++){
		icmp_ether_header -> ether_dhost[i] = icmp_ether_header0 -> ether_shost[i];
		icmp_ether_header -> ether_shost[i] = icmp_ether_header0 -> ether_dhost[i];
	}
	icmp_ether_header-> ether_type = icmp_ether_header0 -> ether_type;

	if(type == ICMP_ECHOREPLY){
		ip_init_hdr(icmp_iphdr, ntohl(icmp_iphdr0 -> daddr),ntohl(icmp_iphdr0 -> saddr),len - sizeof(struct ether_header),IPPROTO_ICMP);
	}
	else{
		rt_entry_t *icmp_rtable = longest_prefix_match(ntohl(icmp_iphdr0 -> saddr));
		iface_info_t *icmp_iface = icmp_rtable -> iface;
		ip_init_hdr(icmp_iphdr, (icmp_iface->ip),ntohl(icmp_iphdr0 -> saddr),sizeof(struct iphdr) + sizeof(struct icmphdr) + IP_HDR_SIZE(icmp_iphdr0) + 8,IPPROTO_ICMP);
	}
	icmp_icmphdr -> type = type;
	icmp_icmphdr -> code = code;

	if(type == ICMP_ECHOREPLY){
		icmp_icmphdr -> checksum = icmp_checksum(icmp_icmphdr, len - sizeof(struct ether_header) - IP_HDR_SIZE(icmp_iphdr0));
		ip_send_packet(icmp_packet, len);
	}
	else{
		icmp_icmphdr -> u.um.unused = 0;
		icmp_icmphdr -> icmp_mtu = 0;
		memcpy( (icmp_icmphdr + 1), icmp_iphdr0 , IP_HDR_SIZE(icmp_iphdr0) + 8 );
		icmp_icmphdr -> checksum = icmp_checksum(icmp_icmphdr, sizeof(struct icmphdr) + IP_HDR_SIZE(icmp_iphdr0) + 8 );
		ip_send_packet(icmp_packet, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + IP_HDR_SIZE(icmp_iphdr0) + 8);
	}
}