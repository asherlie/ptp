#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "csv.h"
#include "mac_log.h"

void insert_al(struct addr_ll* al, uint8_t* addr){
    /* new node, prev == NULL, next == al, al->prev == tmp */
    struct addr_entry* tmp = calloc(sizeof(struct addr_entry), 1);

    tmp->addr = addr;

    if(al->first){
        al->first->prev = tmp;
        tmp->next = al->first;
    }
    al->first = tmp;
}

_Bool al_contains(struct addr_ll* al, uint8_t* addr){
    for(struct addr_entry* ae = al->first; ae; ae = ae->next){
        if(!memcmp(ae->addr, addr, 6))return 1;
    }
    return 0;
}

void init_soh(struct ssid_overview_hash* soh, int n_buckets, int second_interval){
    soh->n_buckets = n_buckets;
    soh->second_interval = second_interval;
    soh->se = calloc(sizeof(struct soh_entry*), STR_HASH_MAX);
    /*memset(soh->se, 0, sizeof(struct soh_entry*)*STR_HASH_MAX);*/
}

void free_soh(struct ssid_overview_hash* soh){
    struct addr_entry* prev_ae;
    for(int i = 0; i < STR_HASH_MAX; ++i){
        if(soh->se[i]){
            free(soh->se[i]->buckets);
            for(int j = 0; j < soh->n_buckets; ++j){
                prev_ae = soh->se[i]->addresses[j].first;
                if(!prev_ae)continue;
                for(struct addr_entry* ae = prev_ae->next; ae; ae = ae->next){
                    free(prev_ae);
                    prev_ae = ae;
                }
                free(prev_ae);
            }
            free(soh->se[i]->addresses);
            free(soh->se[i]);
        }
    }
}

int str_hash(char str[32]){
    int ret = 0,
    primes[32] = {2, 3, 5, 7, 11, 13, 17, 19, 23,
                  29, 31, 37, 41, 43, 47, 53, 59,
                  61, 67, 71, 73, 79, 83, 89, 97,
                  101, 103, 107, 109, 113, 127, 131};
    for(int i = 0; i < 32; ++i){
        ret += str[i]*primes[i];
    }

    return ret;
}


/*void insert_soh(struct ssid_overview_hash* soh, char ssid[32], struct probe_storage* ps){*/
void insert_soh(struct ssid_overview_hash* soh, struct probe_storage* ps, uint8_t* addr, time_t oldest){
    int idx, bucket;
    if(!soh->se[(idx = str_hash(ps->ssid))]){
        soh->se[idx] = calloc(sizeof(struct soh_entry), 1);
        soh->se[idx]->buckets = calloc(sizeof(int), soh->n_buckets);
        soh->se[idx]->n_probes = 0;
        soh->se[idx]->ssid = ps->ssid;

        soh->se[idx]->addresses = calloc(sizeof(struct addr_ll), soh->n_buckets);
    }
    for(int i = 0; i < ps->n_probes; ++i){
        bucket = (ps->probe_times[i]-oldest)/soh->second_interval;
        /* need option to only insert in case of first occurence in bucket by mac address */
        /* al will contain addr if we just created our linked list and bucket */
        if(addr){
            if(al_contains(&soh->se[idx]->addresses[bucket], addr))continue;
            insert_al(&soh->se[idx]->addresses[bucket], addr);
        }
        /*++soh->se[idx]->buckets[(ps->probe_times[i]-oldest)/soh->second_interval];*/
        ++soh->se[idx]->n_probes;
        ++soh->se[idx]->buckets[bucket];
    }
}

struct ssid_overview_hash* gen_ssid_overview(struct probe_history* ph, int second_interval, _Bool unique_macs){
    struct ssid_overview_hash* ret = calloc(1, sizeof(struct ssid_overview_hash));
    time_t oldest = oldest_probe(ph);

    init_soh(ret, ((time(NULL)-oldest)/second_interval)+1, second_interval);

    pthread_mutex_lock(&ph->lock);
    for(int i = 0; i < (0xff*6)+1; ++i){
        if(!ph->buckets[i])continue;
        for(struct mac_addr* ma = ph->buckets[i]; ma; ma = ma->next){
            for(struct probe_storage* ps = ma->probes; ps; ps = ps->next){
                insert_soh(ret, ps, (unique_macs) ? ma->addr : NULL, oldest);
            }
        }
    }
    pthread_mutex_unlock(&ph->lock);

    return ret;
}

/* returns whether str matches any of filters */
_Bool strmatch(char* str, char** filters){
    for(char** i = filters; *i; ++i){
        if(strstr(str, *i))return 1;
    }
    return 0;
}
/* TODO: should this be build in to gen_ssid_overview()? */
void filter_soh(struct ssid_overview_hash* soh, char** filters, int occurence_floor){
    for(int i = 0; i < STR_HASH_MAX; ++i){
        if(!soh->se[i])continue;
        /*printf("%s - n p: %i\n", soh->se[i]->ssid, soh->se[i]->n_probes);*/
        if(soh->se[i]->n_probes < occurence_floor || (*filters && !strmatch(soh->se[i]->ssid, filters))){
            /*printf("removing!\n");*/
            free(soh->se[i]->buckets);
            free(soh->se[i]);
            soh->se[i] = NULL;
        }
    }
}
