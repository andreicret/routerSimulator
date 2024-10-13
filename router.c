#include "queue.h"
#include "lib.h"
#include "protocols.h"

struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len;

uint8_t mac_addr[MAC_SIZE];
struct in_addr ip_addr;

/*Comparator for sorting the routing table*/
int route_comparator(const void* p1, const void* p2)
{
    struct route_table_entry aux1 = *(struct route_table_entry*)p1;
    struct route_table_entry aux2 = *(struct route_table_entry*)p2;

    if (ntohl(aux1.prefix) > ntohl(aux2.prefix)) {
        return -1;
    }

    if (ntohl(aux1.prefix) ==  ntohl(aux2.prefix)) {
        if (ntohl(aux1.mask) > ntohl(aux2.mask)) {
            return -1;
        } else if (ntohl(aux1.mask) == ntohl(aux2.mask))
            return 0;
    }

    return 1;
}

/*Linear search to match the given ip with its MAC*/
struct arp_table_entry *get_mac_entry(uint32_t given_ip) {
	
	for (size_t i = 0; i < arp_table_len; i++) {
		if (given_ip == arp_table[i].ip)
			return &arp_table[i];
	}

	return NULL;
}

/*Binary search to find the best route*/
struct route_table_entry *get_best_route(uint32_t ip_dest) {

	size_t right = rtable_len - 1, left = 0;
	size_t mid;

	struct route_table_entry *current_choice = NULL;
	uint32_t network_add;

	while (left <= right) {

		mid = left + (right - left) / 2;
		network_add = ip_dest & rtable[mid].mask;
		
		if (network_add == rtable[mid].prefix && !current_choice)
			current_choice = &rtable[mid];
		
		/*If second criteria is better - mask*/
		if (network_add == rtable[mid].prefix && current_choice &&
			ntohl(rtable[mid].mask) > ntohl(current_choice->mask))
				current_choice = &rtable[mid];

		if (ntohl(rtable[mid].prefix) < ntohl(ip_dest)) {
			right = mid - 1;
		} else {
			left = mid + 1;
		}
			
	}
	return current_choice;
}

/*Modify packet structure for ICMP types*/
void icmp_message(int type, struct iphdr* ip_hdr, size_t* len)
{	
	struct icmphdr* icmp_hdr = (struct icmphdr*) ((char*)ip_hdr +sizeof(struct iphdr));
	
	/*Copy the first 64 bits from the original payload*/
	memcpy((char*)(ip_hdr + sizeof(struct iphdr) + sizeof(struct icmphdr)),
				 (char*)(ip_hdr + sizeof(struct iphdr)), 64);
	
	/*Set the ICMP parameters*/
	icmp_hdr = (struct icmphdr*) ((char*)ip_hdr + sizeof(struct iphdr));
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	ip_hdr->protocol = 1;

	/*Send the packet back*/	
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = ip_addr.s_addr;

	/*Changes necessary to send the packet back to sender*/
	ip_hdr->ttl = MAX_TTL;
	*len += sizeof(struct icmphdr);
	ip_hdr->tot_len = htons(sizeof(struct icmphdr));
}

/*Allocation and table parsing*/
void init_control_plane(char* rtable_name)
{
	/*Routing table allocation and parsing*/
	rtable = malloc(MAX_TABLE_ENTRIES * sizeof (struct route_table_entry));
	DIE(!rtable, "malloc");

	
	rtable_len = read_rtable(rtable_name, rtable);
	qsort(rtable, rtable_len, sizeof(rtable[0]), route_comparator);

	/*ARP table*/
	arp_table = malloc(MAX_TABLE_ENTRIES * sizeof(struct arp_table_entry));
	DIE(!arp_table, "malloc");

	arp_table_len = parse_arp_table("arp_table.txt", arp_table);
}

/*Check the validity of IPv4 packet*/
int ipv4_checksum_check(struct iphdr* ip_hdr)
{
	uint16_t current_checksum = ntohs(ip_hdr->check);
	ip_hdr->check = 0;

	if (current_checksum != checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)))
		return 0;

	ip_hdr->check = htons(current_checksum);

	return 1;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	/*Get the broadcast address*/
	uint8_t *broadcast_address = malloc(MAC_SIZE * sizeof(uint8_t));
	DIE(!broadcast_address, "malloc");
	hwaddr_aton(BROADCAST_ADDRESS, (uint8_t*) broadcast_address);

	init(argc - 2, argv + 2);
	init_control_plane(argv[1]);

	while (1) {

		int interface;
		size_t len;

		/*Read the packet from the network*/
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		/*Declare pointers to buf for better visibility*/
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr*) (buf + sizeof(struct ether_header));
		struct icmphdr *icmp_hdr;

		/*Get router's IP and MAC*/
		get_interface_mac(interface, (uint8_t*)(&mac_addr));	
		inet_aton(get_interface_ip(interface), &ip_addr);

		/*Check if the Ethernet destination is the router or broadcast*/
		if (!(!memcmp(mac_addr, eth_hdr->ether_dhost, MAC_SIZE) ||
			!memcmp(mac_addr, broadcast_address, MAC_SIZE)))
				continue;

		/*Check packet's ethertype*/
		if (eth_hdr->ether_type == htons(IPv4_ETHER_TYPE)) { //ipv4 parsing
			
			/*Checksum*/
			if (!ipv4_checksum_check(ip_hdr))
				continue;

			/*If packet is ICMP*/
			if (ip_hdr->protocol == IPPROTO_ICMP) {
				
				icmp_hdr = (struct icmphdr*) ((char*)ip_hdr + sizeof(struct iphdr));

				/*If an echo request was sent and router is the receiver*/
				if (icmp_hdr->type == ECHO_REQUEST && ip_addr.s_addr == ip_hdr->daddr) {

					icmp_hdr->type = ECHO_REPLY;
					ip_hdr->daddr = ip_hdr->saddr;
					ip_hdr->saddr = ip_addr.s_addr;
				}

			} else {
				icmp_hdr = NULL;
			}

			
			/*TTL check*/
			int old_ttl = ip_hdr->ttl;
			int old_check = ip_hdr->check;
			
			if (ip_hdr->ttl <= TIMEOUT) {
				/*Send the packet back to source*/
				icmp_message(TIME_EXCEEDED, ip_hdr, &len);

			} else
				ip_hdr->ttl--;

			/*Recompute the checksum*/
			ip_hdr->check = ~(~old_check +  ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

		} else {
			continue;
		}

		int new_interface;

		/*Routing*/
		struct route_table_entry *entry = get_best_route(ip_hdr->daddr);
		
		if (!entry) {
			
			/*Destination unreachable: send ICMP packet on the same interface*/
			icmp_message(DESTINATION_UNREACHABLE, ip_hdr, &len);
			
			/*change destination MAC with source*/
			memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_SIZE);

			new_interface = interface;

		}else {
			new_interface = entry->interface;

			/*Get the next hop's address and set is as destination MAC*/
			struct arp_table_entry* arp_next_mac = get_mac_entry(entry->next_hop);

			memcpy(eth_hdr->ether_dhost, arp_next_mac->mac, MAC_SIZE);
		}
		
		/*Update source MAC*/
		memcpy(eth_hdr->ether_shost, mac_addr, MAC_SIZE);
		
		/*Send the packet on the new interface*/
		send_to_link(new_interface, buf, len);
	}

	/*Free the data allocated on heap*/
	free(rtable);
	free(arp_table);
	free(broadcast_address);
}
