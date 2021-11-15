#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "csv.h"
#include "mac_log.h"

void init_soh(struct ssid_overview_hash* soh, int n_buckets, int second_interval){
    soh->n_buckets = n_buckets;
    soh->second_interval = second_interval;
    soh->se = calloc(sizeof(struct soh_entry*), STR_HASH_MAX);
    /*memset(soh->se, 0, sizeof(struct soh_entry*)*STR_HASH_MAX);*/
}

void free_soh(struct ssid_overview_hash* soh){
    for(int i = 0; i < STR_HASH_MAX; ++i){
        if(soh->se[i]){
            free(soh->se[i]->buckets);
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
void insert_soh(struct ssid_overview_hash* soh, struct probe_storage* ps, time_t oldest){
    int idx;
    if(!soh->se[(idx = str_hash(ps->ssid))]){
        soh->se[idx] = calloc(sizeof(struct soh_entry), 1);
        soh->se[idx]->buckets = calloc(sizeof(int), soh->n_buckets);
        soh->se[idx]->ssid = ps->ssid;
    }
    for(int i = 0; i < ps->n_probes; ++i){
        ++soh->se[idx]->buckets[(ps->probe_times[i]-oldest)/soh->second_interval];
    }
}

struct ssid_overview_hash* gen_ssid_overview(struct probe_history* ph, int second_interval){
    struct ssid_overview_hash* ret = calloc(1, sizeof(struct ssid_overview_hash));
    time_t oldest = oldest_probe(ph);

    init_soh(ret, ((time(NULL)-oldest)/second_interval)+1, second_interval);

    pthread_mutex_lock(&ph->lock);
    for(int i = 0; i < (0xff*6)+1; ++i){
        if(!ph->buckets[i])continue;
        for(struct mac_addr* ma = ph->buckets[i]; ma; ma = ma->next){
            for(struct probe_storage* ps = ma->probes; ps; ps = ps->next){
                insert_soh(ret, ps, oldest);
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
void filter_soh(struct ssid_overview_hash* soh, char** filters){
    if(!*filters)return;
    for(int i = 0; i < STR_HASH_MAX; ++i){
        if(!soh->se[i])continue;
        if(!strmatch(soh->se[i]->ssid, filters)){
            free(soh->se[i]->buckets);
            free(soh->se[i]);
            soh->se[i] = NULL;
        }
    }
}
