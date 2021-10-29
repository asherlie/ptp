#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "mac_log.h"

void init_probe_history(struct probe_history* ph){
    for(int i = 0; i < (0xff*6)+1; ++i){
        ph->buckets[i] = NULL;
    }
}

int sum_mac_addr(uint8_t mac_addr[6]){
    int ret = 0;
    for(int i = 0; i < 6; ++i){
        ret += mac_addr[i];
    }
    return ret;
}

void init_probe_storage(struct probe_storage* ps){
    ps->next = NULL;
    ps->n_probes = 0;
    ps->probe_cap = 10000;
    ps->probe_times = malloc(sizeof(uint32_t)*ps->probe_cap);
}

struct mac_addr* alloc_mac_addr_bucket(uint8_t mac_addr[6]){
    struct mac_addr* new_entry = malloc(sizeof(struct mac_addr));
 
    memcpy(new_entry->addr, mac_addr, 6);
    new_entry->next = NULL;
    new_entry->notes = NULL;
    new_entry->probes = malloc(sizeof(struct probe_storage));
    init_probe_storage(new_entry->probes);

    return new_entry;
}

void insert_probe(struct probe_storage* ps){
    if(ps->n_probes == ps->probe_cap){
        ps->probe_cap *= 2;
        uint32_t* tmp = malloc(sizeof(uint32_t)*ps->probe_cap);
        memcpy(tmp, ps->probe_times, sizeof(uint32_t)*ps->n_probes);
        free(ps->probe_times);
        ps->probe_times = tmp;
    }
    ps->probe_times[ps->n_probes++] = time(NULL);
}




void insert_probe_request(struct probe_history* ph, uint8_t mac_addr[6], char ssid[32]){
    int idx = sum_mac_addr(mac_addr);
    struct mac_addr** bucket;// * new_entry = malloc(sizeof(struct mac_addr));
    struct probe_storage* ps;
    _Bool found_bucket = 0;

    bucket = &ph->buckets[idx];

    /* initialize bucket if not found */
    if(!*bucket)*bucket = alloc_mac_addr_bucket(mac_addr);

#if 0
lookup bucket, if not found, allocate with new specific mac
go through all buckets looking for mac
if not found, alloc bucket
#endif

    for(; (*bucket)->next; *bucket = (*bucket)->next){
        printf("bucket next: %p\n", (void*)(*bucket)->next);
        if(!memcmp((*bucket)->addr, mac_addr, 6)){
            found_bucket = 1;
            break;
        }
    }

    /* add to linked list if this exact mac address has not yet been seen
     * but the bucket is already occupied by mac addresses with the same sum
     */
    if(!found_bucket)*bucket = ((*bucket)->next = alloc_mac_addr_bucket(mac_addr));

    /* at this point, *bucket will contain a struct mac_addr ready for insertion
     * now all we need to do is find the appropriate ssid field and insert a new
     * probe request timestamp
     */

    found_bucket = 0;
    for(ps = (*bucket)->probes; ps->next; ps = ps->next){
        if(!memcmp(ps->ssid, ssid, 32)){
            found_bucket = 1;
            break;
        }
    }

    /* if we don't have an entry matching ssid for a given mac address,
     * it's time to insert a new one into the front of our mac address'
     * probe linked list
     *
     * TODO: if this isn't working, just add to the end using ps
     * when this was originally writte, ps was defined in the for loop
     */
    if(!found_bucket){
        struct probe_storage* tmp = malloc(sizeof(struct probe_storage));
        init_probe_storage(tmp);
        tmp->next = (*bucket)->probes;
        ps = (*bucket)->probes = tmp;
        memcpy(ps->ssid, ssid, 32);
    }

    /* at this point, ps will contain the appropriate probe list */

    insert_probe(ps);
}

void p_probes(struct probe_history* ph){
    struct mac_addr* ma;
    for(int i = 0; i < (0xff*6)+1; ++i){
        if((ma = ph->buckets[i])){
            for(; ma; ma = ma->next){
                printf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx's requests:\n", ma->addr[0], ma->addr[1], ma->addr[2], ma->addr[3],
                       ma->addr[4], ma->addr[5]);
                for(struct probe_storage* ps = ma->probes; ps; ps = ps->next){
                    printf("  %i probes to \"%s\"\n", ps->n_probes, ps->ssid);
                }
            }
        }
    }
}

int main(){
    struct probe_history ph;
    uint8_t addr[] = {0x1f, 0x99, 0x84, 0xa4, 0x19, 0x23};
    char ssid[32] = "asher's network";

    init_probe_history(&ph);
    insert_probe_request(&ph, addr, ssid);

    p_probes(&ph);

    return 0;
}
