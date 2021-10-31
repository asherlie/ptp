#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "mac_log.h"

void init_probe_history(struct probe_history* ph){
    ph->unique_addresses = 0;
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

void init_probe_storage(struct probe_storage* ps, char ssid[32]){
    ps->next = NULL;
    ps->n_probes = 0;
    ps->probe_cap = 10000;
    ps->probe_times = malloc(sizeof(time_t)*ps->probe_cap);
    memcpy(ps->ssid, ssid, 32);
}

struct mac_addr* alloc_mac_addr_bucket(uint8_t mac_addr[6]){
    struct mac_addr* new_entry = malloc(sizeof(struct mac_addr));
 
    memcpy(new_entry->addr, mac_addr, 6);
    new_entry->next = NULL;
    new_entry->notes = NULL;
    new_entry->probes = NULL;
    /*new_entry->probes = malloc(sizeof(struct probe_storage));*/
    /*init_probe_storage(new_entry->probes);*/

    return new_entry;
}

void insert_probe(struct probe_storage* ps){
    time_t t = time(NULL);

    /* we ignore probes that occur in the same second
     * as the next most recently received probe
     */
    if(ps->n_probes && t == ps->probe_times[ps->n_probes-1])return;

    if(ps->n_probes == ps->probe_cap){
        ps->probe_cap *= 2;
        time_t* tmp = malloc(sizeof(time_t)*ps->probe_cap);
        memcpy(tmp, ps->probe_times, sizeof(time_t)*ps->n_probes);
        free(ps->probe_times);
        ps->probe_times = tmp;
    }
    ps->probe_times[ps->n_probes++] = t;
}


void insert_probe_request(struct probe_history* ph, uint8_t mac_addr[6], char ssid[32]){
    int idx = sum_mac_addr(mac_addr);
    struct mac_addr** bucket, * prev_bucket, * ready_bucket;
    struct probe_storage* ps;
    _Bool found_bucket = 0;

    bucket = &ph->buckets[idx];

    /* initialize bucket if not found */
    if(!*bucket){
        /*printf("no bucket found at idx %i, creating!\n", idx);*/
        ++ph->unique_addresses;
        *bucket = alloc_mac_addr_bucket(mac_addr);
    }

    #if 0
    lookup bucket, if not found, allocate with new specific mac
    go through all buckets looking for mac
    if not found, alloc bucket
    #endif

    for(ready_bucket = *bucket; ready_bucket; ready_bucket = ready_bucket->next){
        if(!memcmp(ready_bucket->addr, mac_addr, 6)){
            found_bucket = 1;
            break;
        }
        prev_bucket = ready_bucket;
    }

    /* add to linked list if this exact mac address has not yet been seen
     * but the bucket is already occupied by mac addresses with the same sum
     */
    if(!found_bucket){
        ++ph->unique_addresses;
        ready_bucket = (prev_bucket->next = alloc_mac_addr_bucket(mac_addr));
    }

    /* at this point, ready_bucket will contain a struct mac_addr ready for insertion
     * now all we need to do is find the appropriate ssid field/create one if none exists
     * and insert a new probe request timestamp
     */

    if(!ready_bucket->probes){
        ready_bucket->probes = malloc(sizeof(struct probe_storage));
        init_probe_storage(ready_bucket->probes, ssid);
    }

    found_bucket = 0;
    for(ps = ready_bucket->probes; ps; ps = ps->next){
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
        init_probe_storage(tmp, ssid);
        tmp->next = ready_bucket->probes;
        ps = ready_bucket->probes = tmp;
        memcpy(ps->ssid, ssid, 32);
    }

    /* at this point, ps will contain the appropriate probe list */

    insert_probe(ps);
}

void add_note(struct probe_history* ph, uint8_t addr[6], char* note){
    struct mac_addr* ma = ph->buckets[sum_mac_addr(addr)];
    for(; ma; ma = ma->next){
        if(!memcmp(ma->addr, addr, 6)){
            ma->notes = note;
            return;
        }
    }
}

/*
TODO - add note insertion command for suspected identity
TODO - make this threadsafe but fast by having a separate mutex lock at each bucket index
*/
/*
 * i'll split this up into different layers so that i can have functions that print requests of a given mac address
 * this will be helpful in the repl, where i can issue commands to print the number of unique mac addresses, which is now tracked
 *
 * as well as a mac address lookup command, that lets the user print mac addr nots and all requests by a given mac
 *
 * TODO: write this:
 *   as well as an ssid command that prints all users that have attempted to connect to a given ssid
 *   this will be very slow, but is going to be called rarely
 *
 * as well as a mac address and ssid lookup command that will print time and date of each probe from a given mac to a given ssid
 *   to achieve this, the lowest level print function will optionally print all probe times
*/

void p_probe_storage(struct probe_storage* ps, _Bool verbose, char* prepend){
    char date_str[40];
    struct tm lt;

    if(prepend)fputs(prepend, stdout);
    
    printf("%i probes to \"%s\"\n", ps->n_probes, ps->ssid);

    if(!verbose)return;

    for(int i = 0; i < ps->n_probes; ++i){
        localtime_r((time_t*)&ps->probe_times[i], &lt);
        strftime(date_str, 40, "%A %B %d %Y @ %I:%M:%S %p", &lt);
        if(prepend){
            fputs(prepend, stdout);
            fputs(prepend, stdout);
        }
        puts(date_str);
    }
}

void p_mac_addr_probe(struct mac_addr* ma, _Bool p_timestamps){
    printf("%.2hhX:%.2hhX:%.2hhX:%.2hhX:%.2hhX:%.2hhX:\n", ma->addr[0], ma->addr[1],
           ma->addr[2], ma->addr[3], ma->addr[4], ma->addr[5]);
    if(ma->notes)printf("  notes: %s\n", ma->notes);

    for(struct probe_storage* ps = ma->probes; ps; ps = ps->next){
        p_probe_storage(ps, p_timestamps, "  ");
    }
}

/*fixed p_probes, but now notes are being applied to too many elements*/
void p_probes(struct probe_history* ph, _Bool verbose){
    struct mac_addr* ma;
    for(int i = 0; i < (0xff*6)+1; ++i){
        if((ma = ph->buckets[i])){
            for(; ma; ma = ma->next){
                p_mac_addr_probe(ma, verbose);
            }
        }
    }
}

void free_probe_storage_lst(struct probe_storage* ps){
    struct probe_storage* prev = NULL;
    for(struct probe_storage* psp = ps; psp; psp = psp->next){
        if(prev)free(prev);
        free(psp->probe_times);
        prev = psp;
    }
    free(prev);
}

void free_mac_addr_lst(struct mac_addr* ma){
    struct mac_addr* prev = NULL;
    for(struct mac_addr* map = ma; map; map = map->next){
        if(prev)free(prev);
        free_probe_storage_lst(map->probes);
        prev = map;
    }
    free(prev);
}

void free_probe_history(struct probe_history* ph){
    for(int i = 0; i < (0xff*6)+1; ++i){
        if(ph->buckets[i]){
            free_mac_addr_lst(ph->buckets[i]);
        }
    }
}
