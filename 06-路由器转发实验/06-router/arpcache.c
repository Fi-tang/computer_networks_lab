#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "icmp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// lookup the IP->mac mapping
//
// traverse the table to find whether there is an entry with the same IP
// and mac address with the given arguments
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	fprintf(stderr, "TODO: lookup ip address in arp cache.\n");
	for(int i = 0; i < MAX_ARP_SIZE; i++){
		if(arpcache.entries[i].ip4 == ip4 && arpcache.entries[i].valid){
			for(int j = 0; j < ETH_ALEN; j++){
				mac[j] = arpcache.entries[i].mac[j];
			}
			return 1;
		}
	}
	return 0;
}

// append the packet to arpcache
//
// Lookup in the list which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	fprintf(stderr, "TODO: append the ip address if lookup failed, and send arp request if necessary. %x\n", ip4);
	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list){
		if(req_entry->ip4 == ip4){
			struct cached_pkt *temp;
			temp = (struct cached_pkt *)malloc(sizeof(struct cached_pkt));
			temp->packet = packet;
			temp->len = len;
			list_add_tail(&(temp->list),&(req_entry->cached_packets));
			return;
		}
	}

	struct arp_req *target;
	target = (struct arp_req *)malloc(sizeof(struct arp_req));
	list_add_tail(&(target -> list), &(arpcache.req_list));
	target->iface = iface;
	target->ip4 = ip4;
	target->sent =  time(NULL);
	target -> retries = 0;
	struct cached_pkt *temp;
	temp = (struct cached_pkt *)malloc(sizeof(struct cached_pkt));
	temp->packet = packet;
	temp->len = len;
	init_list_head(&(target->cached_packets));
	list_add_tail(&(temp->list),&(target->cached_packets));

	arp_send_request(iface,ip4);
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, and send
// them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	fprintf(stderr, "TODO: insert ip->mac entry, and send all the pending packets. %x\n", ip4);
	int i;
	for(i = 0; i < MAX_ARP_SIZE; i++){
		if(arpcache.entries[i].valid == 0){
			arpcache.entries[i].ip4 = ip4;
			for(int j = 0; j < ETH_ALEN; j++){
				arpcache.entries[i].mac[j] = mac[j];
			}
			arpcache.entries[i].added = time(NULL);
			arpcache.entries[i].valid = 1;
			break;
		}
	}
	if(i == MAX_ARP_SIZE){
		arpcache.entries[0].ip4 = ip4;
		for(int j = 0; j < ETH_ALEN; j++){
			arpcache.entries[0].mac[j] = mac[j];
		}
		arpcache.entries[0].added = time(NULL);
		arpcache.entries[0].valid = 1;
	}

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list){
		if(req_entry->ip4 == ip4){
			printf("send\n");
			struct cached_pkt *pkt_entry = NULL, *pkt_q;
			list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
				struct ether_header *arp_ether_header;
				arp_ether_header = (struct ether_header *)(pkt_entry->packet);
				for(int j = 0; j < ETH_ALEN; j++){
					arp_ether_header->ether_dhost[j] = mac[j];
				}
				iface_send_packet(req_entry->iface,pkt_entry->packet,pkt_entry->len);
			}
			list_delete_entry(&(req_entry->list));
			free(req_entry);
		}
	}
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while 
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg) 
{
	while (1) {
		sleep(1);
		fprintf(stderr, "TODO: sweep arpcache periodically: remove old entries, resend arp requests .\n");
		for(int i = 0; i < MAX_ARP_SIZE; i++){
			if(arpcache.entries[i].valid == 1 && time(NULL) - arpcache.entries[i].added > 15){
				arpcache.entries[i].valid = 0;
			}
		}
		struct arp_req *req_entry = NULL, *req_q;
		list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list){
			if(time(NULL) - req_entry->sent > 1 && req_entry->retries < 5){
				arp_send_request(req_entry->iface,req_entry->ip4);
				req_entry->retries++;
			}
			else if(req_entry-> retries == 5){
				struct cached_pkt *pkt_entry = NULL, *pkt_q;
				list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
					icmp_send_packet(pkt_entry->packet, pkt_entry->len,ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
					list_delete_entry(&(pkt_entry->list));
					free(pkt_entry->packet);
					free(pkt_entry);
				}
				list_delete_entry(&(req_entry->list));
				free(req_entry);
			}
		}
	}
	return NULL;
}
