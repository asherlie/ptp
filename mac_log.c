#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "mac_log.h"

void init_probe_history(struct probe_history* ph){
    memset(ph->buckets, 0, sizeof(struct mac_addr*)*(0xff*6));
}

int sum_mac_addr(uint8_t mac_addr[6]){
    int ret = 0;
    for(int i = 0; i < 6; ++i){
        ret += mac_addr[i];
    }
    return ret;
}

struct mac_addr* alloc_mac_addr_bucket(uint8_t mac_addr[6]){
    struct mac_addr* new_entry = malloc(sizeof(struct mac_addr));
 
    memcpy(new_entry->addr, mac_addr, 6);
    new_entry->next = NULL;
    new_entry->notes = NULL;
    new_entry->probes.n_probes = 0;
    new_entry->probes.probe_cap = 10000;
    new_entry->probes.probe_times = malloc(sizeof(uint32_t)*new_entry->probes.probe_cap);

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
        if(!memcmp((*bucket)->addr, mac_addr, 6)){
            found_bucket = 1;
            break;
        }
    }

    /* add to linked list if this exact mac address has not yet been seen
     * but the bucket is already occupied by mac addresses with the same sum
     */
    if(!found_bucket)*bucket = ((*bucket)->next = alloc_mac_addr_bucket(mac_addr));

    /* at this point, *bucket will contain a struct mac_addr ready for insertion */

}

int main(){
    return 0;
}
