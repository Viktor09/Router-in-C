#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len;

struct arp_dynamic
{
    uint32_t ip;
    uint8_t mac[6];
    int size;
};
struct pair_buf_and_len{
    char buf[MAX_PACKET_LEN];
    size_t len;

};
int size_pbl;


int comparator(const void *a, const void *b){
    struct route_table_entry *mask1 = (struct route_table_entry *)a;
    struct route_table_entry *mask2 = (struct route_table_entry *)b;

    if(mask2->mask - mask1->mask > 0){
        return 1;
    } else if(mask2->mask - mask1->mask < 0){
        return -1;
    } else{
        return 0;
    }

}

int main(int argc, char *argv[]) {
    char buf[MAX_PACKET_LEN];

    // Do not modify this line
    init(argc - 2, argv + 2);

    rtable = malloc(sizeof(struct route_table_entry) * 100000);
    if (rtable == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    arp_table = malloc(sizeof(struct arp_table_entry) * 100000);
    if (arp_table == NULL) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }

    rtable_len = read_rtable(argv[1], rtable);
    //arp_table_len = parse_arp_table("arp_table.txt", arp_table);

    struct arp_dynamic *arp_dyn = calloc(1000, sizeof(struct arp_dynamic));
    arp_dyn->size = 0;

    struct pair_buf_and_len **pbl = calloc(100000, sizeof(struct pair_buf_and_len *));
    queue q = queue_create();
    qsort(rtable, rtable_len, sizeof(struct route_table_entry), comparator);

    while (1) {
        int interface;
        size_t len;

        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");
        struct ether_header *eth_hdr = (struct ether_header *)buf;



        if(ntohs(eth_hdr->ether_type) == 0x0800){
            struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

	   	    if(inet_addr(get_interface_ip(interface)) == ip_hdr->daddr){
                struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

                icmp_hdr->type = 0;
                icmp_hdr->code = 0;

                icmp_hdr->checksum = 0;
                icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

                u_int8_t copie_shost[6];
                memset(copie_shost, 0, sizeof(copie_shost));
                memcpy(copie_shost, eth_hdr->ether_shost, 6 * sizeof(uint8_t));

                u_int8_t copie_dhost[6];
                memset(copie_dhost, 0, sizeof(copie_dhost));
                memcpy(copie_dhost, eth_hdr->ether_dhost, 6 * sizeof(uint8_t));

                memcpy(eth_hdr->ether_shost, copie_dhost, 6 *sizeof(uint8_t));
                memcpy(eth_hdr->ether_dhost, copie_shost, 6 *sizeof(uint8_t));

                uint32_t aux = ip_hdr->saddr;
                ip_hdr->saddr = ip_hdr->daddr;
                ip_hdr->daddr = aux;
                send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
                continue;
            }

			uint16_t old_sum = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			ip_hdr->check = checksum((uint16_t *)ip_hdr, ntohs(ip_hdr->tot_len));

			if (ip_hdr->check != old_sum) {
            	continue;
        	} else{
        		if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1) {
            		char new_buf[MAX_PACKET_LEN];
                    int offset = 0;


                    struct ether_header *eth_new = (struct ether_header *)calloc(1,sizeof(struct ether_header));
		            u_int8_t copie_shost[6];
                    memset(copie_shost, 0, sizeof(copie_shost));
                    memcpy(copie_shost, eth_hdr->ether_shost, 6 * sizeof(uint8_t));

                    u_int8_t copie_dhost[6];
                    memset(copie_dhost, 0, sizeof(copie_dhost));
                    memcpy(copie_dhost, eth_hdr->ether_dhost, 6 * sizeof(uint8_t));

                    memcpy(eth_new->ether_shost, copie_dhost, 6 *sizeof(uint8_t));
                    memcpy(eth_new->ether_dhost, copie_shost, 6 *sizeof(uint8_t));
		            eth_new->ether_type = htons(0x0800);

                    memcpy(new_buf, eth_new, sizeof(struct ether_header));
                    offset = offset + sizeof(struct ether_header);

                    struct iphdr *ip_new = (struct iphdr *)calloc(1,sizeof(struct iphdr));

                    ip_new->saddr = ip_hdr->saddr;
                    ip_new->daddr = ip_hdr->daddr;
		            uint32_t aux = ip_new->saddr;
                    ip_new->saddr = ip_new->daddr;
                    ip_new->daddr = aux;
		            ip_new->protocol = 0x1;
		            ip_new->ttl = 255;
                    ip_new->version = 4;
                    ip_new->ihl = 5;
                    ip_new->id = 1;
		            ip_new->tot_len = htons(sizeof(struct icmphdr) + 2*sizeof(struct iphdr) + 8);
                    ip_new->check = 0;
        		    ip_new->check = htons(checksum((uint16_t *)ip_new, sizeof(struct iphdr)));

                    memcpy(new_buf + offset, ip_new, sizeof(struct iphdr));
                    offset = offset + sizeof(struct iphdr);

		            struct icmphdr *icmp_hdr = (struct icmphdr *)calloc(1,sizeof(struct icmphdr));
		            icmp_hdr->type = 11;
		            icmp_hdr->code = 0;
		            icmp_hdr->checksum = 0;
		            icmp_hdr->checksum =htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8)) ;

		            memcpy(new_buf + offset, icmp_hdr, sizeof(struct icmphdr));
		            offset = offset + sizeof(struct icmphdr);

                    memcpy(new_buf + offset, ip_hdr , sizeof(struct iphdr));
                    offset = offset + sizeof(struct iphdr);

                    memcpy(new_buf + offset, buf - sizeof(struct icmphdr), 8);
                    offset = offset + 8;

                    printf("AM INTRATT\n");
		            send_to_link(interface, new_buf, offset);
                    continue;

        		}else{
                    ip_hdr->ttl--;

                    struct route_table_entry *rtable_best = NULL;
                    for (int i = 0; i < rtable_len; i++) {
                        if ((ip_hdr->daddr & rtable[i].mask) == rtable[i].prefix) {
                            rtable_best = &rtable[i];
                            break;
                        }
                    }

                    if(rtable_best == NULL){

                    char new_buf[MAX_PACKET_LEN];
                    int offset = 0;


                    struct ether_header *eth_new = (struct ether_header *)calloc(1,sizeof(struct ether_header));
		            u_int8_t copie_shost[6];
                    memset(copie_shost, 0, sizeof(copie_shost));
                    memcpy(copie_shost, eth_hdr->ether_shost, 6 * sizeof(uint8_t));

                    u_int8_t copie_dhost[6];
                    memset(copie_dhost, 0, sizeof(copie_dhost));
                    memcpy(copie_dhost, eth_hdr->ether_dhost, 6 * sizeof(uint8_t));

                    memcpy(eth_new->ether_shost, copie_dhost, 6 *sizeof(uint8_t));
                    memcpy(eth_new->ether_dhost, copie_shost, 6 *sizeof(uint8_t));
		            eth_new->ether_type = htons(0x0800);

                    memcpy(new_buf, eth_new, sizeof(struct ether_header));
                    offset = offset + sizeof(struct ether_header);

                    struct iphdr *ip_new = (struct iphdr *)calloc(1,sizeof(struct iphdr));

                    ip_new->saddr = ip_hdr->saddr;
                    ip_new->daddr = ip_hdr->daddr;
		            uint32_t aux = ip_new->saddr;
                    ip_new->saddr = ip_new->daddr;
                    ip_new->daddr = aux;
		            ip_new->protocol = 0x1;
		            ip_new->ttl = 255;
                    ip_new->version = 4;
                    ip_new->ihl = 5;
                    ip_new->id = 1;
		            ip_new->tot_len = htons(sizeof(struct icmphdr) + 2*sizeof(struct iphdr) + 8);
                    ip_new->check = 0;
        		    ip_new->check = htons(checksum((uint16_t *)ip_new, sizeof(struct iphdr)));

                    memcpy(new_buf + offset, ip_new, sizeof(struct iphdr));
                    offset = offset + sizeof(struct iphdr);

		            struct icmphdr *icmp_hdr = (struct icmphdr *)calloc(1,sizeof(struct icmphdr));
		            icmp_hdr->type = 3;
		            icmp_hdr->code = 0;
		            icmp_hdr->checksum = 0;
		            icmp_hdr->checksum =htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8)) ;

		            memcpy(new_buf + offset, icmp_hdr, sizeof(struct icmphdr));
		            offset = offset + sizeof(struct icmphdr);

                    memcpy(new_buf + offset, ip_hdr , sizeof(struct iphdr));
                    offset = offset + sizeof(struct iphdr);

                    memcpy(new_buf + offset, buf - sizeof(struct icmphdr), 8);
                    offset = offset + 8;

                    printf("AM INTRATT\n");
		            send_to_link(interface, new_buf, offset);
                    continue;


                    }else{
                        ip_hdr->check = 0;
        		        ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
                    }



                    uint8_t ip_mac[6];
		            memset(ip_mac, 0, sizeof(ip_mac));
		    	    get_interface_mac(rtable_best->interface, ip_mac);
                    for(int i = 0; i < 6; i++){
                        eth_hdr->ether_shost[i] = ip_mac[i];
                    }

                    uint8_t ip_mac_dest[6];
                    memset(ip_mac_dest, 0, sizeof(ip_mac_dest));

                    for(int i = 0; i < arp_dyn->size; i++){
                        if(arp_dyn[i].ip == rtable_best->next_hop){
                            for(int j = 0; j < 6; j++){
                                ip_mac_dest[j] = arp_dyn[i].mac[j];
                            }
                        }
                    }

                    int ok = 0;
                    for(int i = 0; i < 6; i++){
                        if(ip_mac_dest[i] != 0){
                            ok = 1;
                        }
                    }

                    if(ok == 1){
                        for(int i = 0; i < 6; i++){
                            eth_hdr->ether_dhost[i] = ip_mac_dest[i];
                        }
                         send_to_link(rtable_best->interface, buf, len);
                    } else{
                        pbl[size_pbl] = calloc(1, sizeof(struct pair_buf_and_len));
                        memcpy(pbl[size_pbl]->buf, buf, len);
                        pbl[size_pbl]->len = len;
                        queue_enq(q, pbl[size_pbl]);
                        size_pbl++;

                        char arp_buf[MAX_PACKET_LEN];
                        int offset_arp = 0;

                        struct ether_header *eth = calloc(1, sizeof(struct ether_header));
                        memset(eth->ether_dhost, 0xFF, 6 * sizeof(u_int8_t));
                        uint8_t mac_source[6];
                        get_interface_mac(rtable_best->interface, mac_source);
                        memcpy(eth->ether_shost, mac_source, 6 * sizeof(uint8_t));
                        eth->ether_type = htons(0x0806);

                        struct arp_header *arp_hdr = calloc(1, sizeof(struct arp_header));
                        arp_hdr->ptype = htons(0x0800);
                        arp_hdr->hlen = 6;
                        arp_hdr->plen = 4;
                        arp_hdr->op = htons(1);
                        arp_hdr->htype = htons(1);
                        memcpy(arp_hdr->sha,  mac_source, 6 * sizeof(uint8_t));
                        arp_hdr->spa = inet_addr(get_interface_ip(rtable_best->interface));
                        uint8_t mac_dest[6];
                        memset(mac_dest, 0, 6 * sizeof(uint8_t));
                        memcpy(arp_hdr->tha, mac_dest, 6 * sizeof(uint8_t));
                        arp_hdr->tpa = rtable_best->next_hop;

                        memcpy(arp_buf, eth, sizeof(struct ether_header));
                        offset_arp += sizeof(struct ether_header);

                        memcpy(arp_buf + offset_arp, arp_hdr, sizeof(struct arp_header));
                        offset_arp += sizeof(struct arp_header);

                        send_to_link(rtable_best->interface, arp_buf, offset_arp); 

                        continue;
                    }

                }

			}
        }else if(ntohs(eth_hdr->ether_type) == 0x0806){
            struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
            uint8_t mac_sursa[8];
            get_interface_mac(interface, mac_sursa);
            memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6 * sizeof(uint8_t));
            memcpy(eth_hdr->ether_shost, mac_sursa, 6 * sizeof(uint8_t));


            if(ntohs(arp_hdr->op) == 1){

                arp_hdr->op = htons(2);
                uint32_t aux = arp_hdr->spa;
                arp_hdr->spa = arp_hdr->tpa;
                arp_hdr->tpa = aux;

                memcpy(arp_hdr->tha, arp_hdr->sha, 6 * sizeof(uint8_t));
                memcpy(arp_hdr->sha, mac_sursa, 6 * sizeof(uint8_t));

                send_to_link(interface, buf, len);

            }else if(ntohs(arp_hdr->op) == 2){
                
                int ok = 0;
                for(int i = 0; i < arp_dyn->size; i++){
                    if(arp_dyn[i].ip == arp_hdr->spa){
                        ok = 1;
                    }
                }
                if(ok == 0){
                    arp_dyn[arp_dyn->size].ip = arp_hdr->spa;
                    memcpy(arp_dyn[arp_dyn->size].mac, arp_hdr->sha, 6 * sizeof(uint8_t));
                    arp_dyn->size++;
                }

                while(!queue_empty(q)){
                    struct pair_buf_and_len *pbl = queue_deq(q);
                    struct iphdr *ip = (struct iphdr *)(pbl->buf + sizeof(struct ether_header));
                    struct route_table_entry *rtable_best = NULL;
                    for (int i = 0; i < rtable_len; i++) {
                        if ((ip->daddr & rtable[i].mask) == rtable[i].prefix) {
                            rtable_best = &rtable[i];
                            break;
                        }
                    }
                    if(rtable_best == NULL){

                        break;
                    }
                    else{
                        uint8_t ip_mac_dest[6];
                        memset(ip_mac_dest, 0, sizeof(ip_mac_dest));
                        struct ether_header *eth = (struct ether_header *)(pbl->buf);
                        int ok = 0;

                        for(int i = 0; i < arp_dyn->size; i++){
                            if(arp_dyn[i].ip == rtable_best->next_hop){
                                for(int j = 0; j < 6; j++){
                                    ip_mac_dest[j] = arp_dyn[i].mac[j];
                                }
                                break;
                            }
                        }
                        for(int i = 0; i < 6; i++){
                            if(ip_mac_dest[i] != 0){
                                ok = 1;
                            }
                        }

                        if(ok == 1){
                            for(int i = 0; i < 6; i++){
                                eth->ether_dhost[i] = ip_mac_dest[i];
                            }

                            send_to_link(rtable_best->interface, pbl->buf, pbl->len);
                        }else{

                        }
                    }

                }
            }
        }



    }

    // Free allocated memory
    free(rtable);
    free(arp_table);

    return 0;
}