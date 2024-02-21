#include "ip.h"
#include "icmp.h"

#include <stdio.h>
#include <stdlib.h>

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	fprintf(stderr, "TODO: handle ip packet.\n");
	struct iphdr *ip_iphdr;
	ip_iphdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	struct icmphdr *ip_icmphdr;
	ip_icmphdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + IP_HDR_SIZE(ip_iphdr));

	if(ip_iphdr -> protocol == IPPROTO_ICMP && ip_icmphdr -> type == ICMP_ECHOREQUEST){
		if(ip_iphdr-> daddr == htonl(iface-> ip)){
			icmp_send_packet(packet,len,ICMP_ECHOREPLY,ICMP_ECHOREPLY);
		}
		else{
			ip_send_packet(packet,len);
		}
	}
	else{
		ip_send_packet(packet,len);
	}
}
