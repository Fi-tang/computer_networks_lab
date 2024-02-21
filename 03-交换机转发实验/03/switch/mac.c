#include "mac.h"
#include "log.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

mac_port_map_t mac_port_map;

// initialize mac_port table
void init_mac_port_table()
{
	bzero(&mac_port_map, sizeof(mac_port_map_t));

	for (int i = 0; i < HASH_8BITS; i++) {
		init_list_head(&mac_port_map.hash_table[i]);
	}

	pthread_mutex_init(&mac_port_map.lock, NULL);

	pthread_create(&mac_port_map.thread, NULL, sweeping_mac_port_thread, NULL);
}

// destroy mac_port table
void destory_mac_port_table()
{
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *entry, *q;
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry_safe(entry, q, &mac_port_map.hash_table[i], list) {
			list_delete_entry(&entry->list);
			free(entry);
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

// lookup the mac address in mac_port table
iface_info_t *lookup_port(u8 mac[ETH_ALEN])
{
	// TODO: implement the lookup process here
	fprintf(stdout, "TODO: implement the lookup process here.\n");
	pthread_mutex_lock(&mac_port_map.lock);
	int position = 0;
	position = hash8(mac,ETH_ALEN);

	struct mac_port_entry *port = NULL;
	list_for_each_entry(port,&mac_port_map.hash_table[position],list){
		if(port ->mac[0] == mac[0] && port->mac[1] == mac[1] && port->mac[2] == mac[2] && port->mac[3] == mac[3] && port->mac[4] == mac[4] && port->mac[5]==mac[5]){
			pthread_mutex_unlock(&mac_port_map.lock);
			return port->iface;
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
	dump_mac_port_table();
	return NULL;
}

int count = 0;
// insert the mac -> iface mapping into mac_port table
void insert_mac_port(u8 mac[ETH_ALEN], iface_info_t *iface)
{
	// TODO: implement the insertion process here
	fprintf(stdout, "TODO: implement the insertion process here.\n");
	iface_info_t *look_port = lookup_port(mac);
	pthread_mutex_lock(&mac_port_map.lock);

	int position = 0;
	position = hash8(mac,ETH_ALEN);

	if(look_port == NULL){
		struct mac_port_entry *new=NULL;
		new = (struct mac_port_entry *)malloc(sizeof(struct mac_port_entry));
		int i = 0;
		for(i = 0; i < ETH_ALEN; i++){
			new -> mac[i]=mac[i];
		}
		new ->iface = iface;
		new ->visited = time(NULL);

		list_add_tail(new, &mac_port_map.hash_table[position]);
	}
	else{
		struct mac_port_entry *port = NULL;
		list_for_each_entry(port,&mac_port_map.hash_table[position],list){
			if(port ->mac[0] == mac[0] && port->mac[1] == mac[1] && port->mac[2] == mac[2] && port->mac[3] == mac[3] && port->mac[4] == mac[4] && port->mac[5]==mac[5]){
				port -> iface = iface;
				port -> visited = time(NULL);
			}
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
	dump_mac_port_table();
	fprintf(stdout,"count============================:%d\n",count);
	count++;

}

// dumping mac_port table
void dump_mac_port_table()
{
	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);

	fprintf(stdout, "dumping the mac_port table:\n");
	fflush(stdout);
	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry(entry, &mac_port_map.hash_table[i], list) {
			fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(entry->mac), \
					entry->iface->name, (int)(now - entry->visited));
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);
}

// sweeping mac_port table, remove the entry which has not been visited in the
// last 30 seconds.
int sweep_aged_mac_port_entry()
{
	// TODO: implement the sweeping process here
	printf("TODO: implement the sweeping process here.\n");
	//fflush(stdout);
	pthread_mutex_lock(&mac_port_map.lock);
	int i = 0;
	for(i = 0; i < HASH_8BITS;i++){
		if(list_empty(mac_port_map.hash_table[i].next)){
			continue;
		}
		printf("dead%d\n",i);
		struct mac_port_entry *find_port;
		struct mac_port_entry *q;
		list_for_each_entry_safe(find_port,q,&mac_port_map.hash_table[i],list){
			printf("2dead%d\n",i);
			if(time(NULL)- find_port -> visited >= MAC_PORT_TIMEOUT){
				list_delete_entry(&find_port->list);
				printf("dead2\n");
				free(find_port);
				printf("dead3\n");
			}
		}
	}
	printf("deadttttt\n");
	pthread_mutex_unlock(&mac_port_map.lock);
	return 0;
}

// sweeping mac_port table periodically, by calling sweep_aged_mac_port_entry
void *sweeping_mac_port_thread(void *nil)
{
	while (1) {
		sleep(1);
		int n = sweep_aged_mac_port_entry();

		if (n > 0)
			log(DEBUG, "%d aged entries in mac_port table are removed.", n);
	}

	return NULL;
}