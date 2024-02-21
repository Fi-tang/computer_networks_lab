#include "base.h"
#include <stdio.h>

// XXX ifaces are stored in instace->iface_list
extern ustack_t *instance;

extern void iface_send_packet(iface_info_t *iface, const char *packet, int len);

void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	// TODO: broadcast packet 
	iface_info_t *current = iface;  //ustack_t 是每一个主机记录的，存放头结点指针，iface_info_t里面是该主机的端口a,b,c的序列号
	list_for_each_entry(iface,&instance->iface_list,list){
		if(iface !=current){
			iface_send_packet(iface,packet,len);
		}
	}
}