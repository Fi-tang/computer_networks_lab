#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static struct nat_table nat;

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
	fprintf(stdout, "TODO: determine the direction of this packet.\n");
	struct iphdr *packet_iphdr;
	packet_iphdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	u32 ip1,ip2;
	ip1 = htonl(packet_iphdr-> saddr);
	ip2 = htonl(packet_iphdr -> daddr);

	rt_entry_t *packet_rtable1 = longest_prefix_match(ip1);
	rt_entry_t *packet_rtable2 = longest_prefix_match(ip2);

	iface_info_t *packet_iface1 = packet_rtable1 -> iface;
	iface_info_t *packet_iface2 = packet_rtable2 -> iface;

	if(nat.internal_iface == packet_iface1 && nat.external_iface == packet_iface2 ){
		return DIR_OUT;
	}
	else if(nat.external_iface -> ip == ip2 && nat.external_iface == packet_iface1){
		return DIR_IN;
	}
	return DIR_INVALID;
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	fprintf(stdout, "TODO: do translation for this packet.\n");
	struct iphdr *packet_iphdr;
	packet_iphdr = (struct iphdr *)(packet + sizeof(struct ether_header));
	struct tcphdr *packet_tcphdr;
	packet_tcphdr = (struct tcphdr *)(packet + sizeof(struct ether_header) + IP_HDR_SIZE(packet_iphdr));
	u32 ips,ipd;
	ips = htonl(packet_iphdr-> saddr);
	ipd = htonl(packet_iphdr -> daddr);
	u16 ports,portd;
	ports = htons(packet_tcphdr -> sport);
	portd = htons(packet_tcphdr -> dport);

	rt_entry_t *packet_rtables = longest_prefix_match(ips);
	rt_entry_t *packet_rtabled = longest_prefix_match(ipd);

	iface_info_t *packet_ifaces = packet_rtables -> iface;
	iface_info_t *packet_ifaced = packet_rtabled -> iface;

	if(dir == DIR_IN){
		u32 packet_remote_ip;
		u16 packet_remote_port;

		packet_remote_ip = ips;
		packet_remote_port = ports;

		u32 packet_external_ip;
		u16 packet_external_port;

		packet_external_ip = ipd;
		packet_external_port = portd;

		u8 hash_code = hash8(&packet_remote_ip, 4) ^ hash8(&packet_remote_port,2);
		struct list_head *packet_list_head;
		packet_list_head = &nat.nat_mapping_list[hash_code];
		struct nat_mapping *req_entry,*req_q;
		list_for_each_entry(req_entry,packet_list_head,list){
			if(req_entry -> remote_ip == packet_remote_ip && req_entry -> remote_port == packet_remote_port \
			&& req_entry -> external_ip == packet_external_ip && req_entry -> external_port == packet_external_port){
				packet_iphdr->daddr = htonl(req_entry -> internal_ip);
				packet_tcphdr->dport = htons(req_entry -> internal_port);
				packet_tcphdr -> checksum = tcp_checksum(packet_iphdr,packet_tcphdr);
				packet_iphdr -> checksum = ip_checksum(packet_iphdr);
				ip_send_packet(packet,len);
				return;
			}
		}

		struct dnat_rule *req_temp, *req_p;
		list_for_each_entry(req_temp,&(nat.rules),list){
			if(req_temp->external_ip == packet_external_ip && req_temp->external_port == packet_external_port){
				struct nat_mapping *target;
				target = (struct nat_mapping *)malloc(sizeof(struct nat_mapping));
				target -> remote_ip = packet_remote_ip;
				target -> remote_port = packet_remote_port;
				target -> internal_ip = req_temp -> internal_ip;
				target -> internal_port = req_temp -> internal_port;
				target -> external_ip = packet_external_ip;
				target -> external_port = packet_external_port;

				target -> update_time = time(NULL);
				list_add_tail(&(target->list), &(nat.nat_mapping_list[hash_code]));

				packet_iphdr->daddr = htonl(req_temp -> internal_ip);
				packet_tcphdr->dport = htons(req_temp -> internal_port);
				packet_tcphdr -> checksum = tcp_checksum(packet_iphdr,packet_tcphdr);
				packet_iphdr -> checksum = ip_checksum(packet_iphdr);
				ip_send_packet(packet,len);
				return;
			}
		}		
	}
	else if(dir == DIR_OUT){
		u32 packet_remote_ip;
		u16 packet_remote_port;

		packet_remote_ip = ipd;
		packet_remote_port = portd;

		u32 packet_internal_ip;
		u16 packet_internal_port;

		packet_internal_ip = ips;
		packet_internal_port = ports;

		u8 hash_code = hash8(&packet_remote_ip, 4) ^ hash8(&packet_remote_port,2);
		struct list_head *packet_list_head;
		packet_list_head = &nat.nat_mapping_list[hash_code];
		struct nat_mapping *req_entry,*req_q;
		list_for_each_entry(req_entry,packet_list_head,list){
			if(req_entry -> remote_ip == packet_remote_ip && req_entry -> remote_port == packet_remote_port \
			&& req_entry -> internal_ip == packet_internal_ip && req_entry -> internal_port == packet_internal_port){
				packet_iphdr->saddr = htonl(req_entry-> external_ip);
				packet_tcphdr -> sport = htons(req_entry -> external_port);
				packet_tcphdr -> checksum = tcp_checksum(packet_iphdr,packet_tcphdr);
				packet_iphdr -> checksum = ip_checksum(packet_iphdr);
				ip_send_packet(packet,len);
				return;
			}
		}

		for(int i = NAT_PORT_MIN; i < NAT_PORT_MAX; i++){
			if(nat.assigned_ports[i] == 0){
				nat.assigned_ports[i] = 1;
				struct nat_mapping *target;
				target = (struct nat_mapping *)malloc(sizeof(struct nat_mapping));
				target -> remote_ip = packet_remote_ip;
				target -> remote_port = packet_remote_port;
				target -> internal_ip = packet_internal_ip;
				target -> internal_port = packet_internal_port;
				target -> external_ip = nat.external_iface-> ip;
				target -> external_port = i;

				target -> update_time = time(NULL);
				list_add_tail(&(target->list), &(nat.nat_mapping_list[hash_code]));
				packet_iphdr->saddr = htonl(target -> external_ip);
				packet_tcphdr -> sport = htons(target  -> external_port);
				packet_tcphdr -> checksum = tcp_checksum(packet_iphdr,packet_tcphdr);
				packet_iphdr -> checksum = ip_checksum(packet_iphdr);
				ip_send_packet(packet,len);
				return;
			}
		}
	}
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	int dir = get_packet_direction(packet);
	if (dir == DIR_INVALID) {
		log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP) {
		log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return ;
	}

	do_translation(iface, packet, len, dir);
}

// check whether the flow is finished according to FIN bit and sequence number
// XXX: seq_end is calculated by `tcp_seq_end` in tcp.h
static int is_flow_finished(struct nat_connection *conn)
{
    return (conn->internal_fin && conn->external_fin) && \
            (conn->internal_ack >= conn->external_seq_end) && \
            (conn->external_ack >= conn->internal_seq_end);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
	while (1) {
		fprintf(stdout, "TODO: sweep finished flows periodically.\n");
		sleep(1);
		for(int i = 0; i < HASH_8BITS; i++){
			struct nat_mapping *req_entry,*req_q;
			list_for_each_entry_safe(req_entry,req_q,&nat.nat_mapping_list[i],list){
				if(time(NULL) - req_entry-> update_time > TCP_ESTABLISHED_TIMEOUT || is_flow_finished( &(req_entry -> conn) )){
					u16 return_port = req_entry -> external_port;
					int flag = 0;
					struct dnat_rule *req_temp, *req_p;
					list_for_each_entry(req_temp,&(nat.rules),list){
						if(req_temp->external_port == req_entry->external_port &&  req_temp->external_ip == req_entry->external_ip && \
							req_temp -> internal_port == req_entry -> internal_port && req_temp -> internal_ip == req_entry-> internal_ip){
							flag = 1;
							break;
						}
					}
					if(flag == 0) nat.assigned_ports[return_port] = 0;
					list_delete_entry(req_entry);
					free(req_entry);
				} 
			}
		}
	}

	return NULL;
}

int parse_config(const char *filename)
{
	fprintf(stdout, "TODO: parse config file, including i-iface, e-iface (and dnat-rules if existing).\n");
	FILE *fd;
	fd = fopen(filename,"r");
	char *buffer1;
	buffer1 = (char *)malloc(1024);
	fscanf(fd,"internal-iface: %s\n",buffer1);
	nat.internal_iface = if_name_to_iface(buffer1);
	char *buffer2;
	buffer2 = (char *)malloc(1024);
	fscanf(fd,"external-iface: %s\n",buffer2);
	nat.external_iface = if_name_to_iface(buffer2);
	fprintf(stdout,"%s\n%s\n", buffer1, buffer2);
	int n1,n2,n3,n4,n5;
	int d1,d2,d3,d4,d5;
	int c;
	while((c = fscanf(fd,"dnat-rules: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",&n1,&n2,&n3,&n4,&n5, \
	&d1,&d2,&d3,&d4,&d5))!=-1){
		struct dnat_rule *temp;
		temp = (struct dnat_rule *)malloc(sizeof(struct dnat_rule));
		temp -> external_ip = (n1 << 24) + (n2 << 16) + (n3 << 8) + n4;
		temp -> external_port = n5;
		temp -> internal_ip = (d1 << 24) + (d2 << 16) + (d3 << 8) + d4;
		temp -> internal_port = d5;
		list_add_tail(temp,&(nat.rules));
		fprintf(stdout,"%d %x %d %x %d\n", c, temp -> external_ip, temp -> external_port, temp -> internal_ip, temp -> internal_port);
	}

	return 0;
}

// initialize
void nat_init(const char *config_file)
{
	memset(&nat, 0, sizeof(nat));

	for (int i = 0; i < HASH_8BITS; i++)
		init_list_head(&nat.nat_mapping_list[i]);

	init_list_head(&nat.rules);

	// seems unnecessary
	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

	parse_config(config_file);

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

void nat_exit()
{
	fprintf(stdout, "TODO: release all resources allocated.\n");
	for(int i = 0; i < HASH_8BITS; i++){
		struct nat_mapping *req_entry,*req_q;
		list_for_each_entry_safe(req_entry,req_q,&nat.nat_mapping_list[i],list){
			list_delete_entry(req_entry);
			free(req_entry);
		}
		struct dnat_rule *req_temp, *req_p;
		list_for_each_entry_safe(req_temp,req_p,&(nat.rules),list){
			list_delete_entry(req_temp);
			free(req_temp);
		} 
	} 
	nat.internal_iface = NULL;
	nat.external_iface = NULL;
}
