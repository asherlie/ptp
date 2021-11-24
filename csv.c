#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "csv.h"
#include "mac_log.h"

#define STR_HASH_MAX 233226

/* TODO:
 * should i rename this file and have this generated and added to throughout regular usage?
 * would allow a command to print unique ssids, n_uniqe, which we could keep track of easily
 * and very fast csv generation
*/

struct addr_entry{
    uint8_t* addr;
    struct addr_entry* next, * prev;
};

struct addr_ll{
    struct addr_entry* first;
};

struct soh_entry{
    /* each ssid has an associated set of time interval buckets */
    /* should int* buckets be replaced with a struct that contains both a 
     * counter, as well as a list of addresses in case of deduplication
     * being enabled?
     */
    int n_probes;
    int* buckets;
    struct addr_ll* addresses;
    char* ssid;
};

struct ssid_overview_hash{
    int second_interval, n_buckets;
    struct soh_entry** se;
};


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
}

void free_se(struct soh_entry* se, int n_buckets){
    struct addr_entry* prev_ae;
    free(se->buckets);
    for(int i = 0; i < n_buckets; ++i){
        prev_ae = se->addresses[i].first;
        if(!prev_ae)continue;
        for(struct addr_entry* ae = prev_ae->next; ae; ae = ae->next){
            free(prev_ae);
            prev_ae = ae;
        }
        free(prev_ae);
    }
    free(se->addresses);
    free(se);
}

void free_soh(struct ssid_overview_hash* soh){
    for(int i = 0; i < STR_HASH_MAX; ++i){
        if(soh->se[i]){
            free_se(soh->se[i], soh->n_buckets);
        }
    }
    free(soh->se);
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
/* TODO: should this be built in to gen_ssid_overview()? */
void filter_soh(struct ssid_overview_hash* soh, char** filters, int occurence_floor){
    for(int i = 0; i < STR_HASH_MAX; ++i){
        if(!soh->se[i])continue;
        if(soh->se[i]->n_probes < occurence_floor || (*filters && !strmatch(soh->se[i]->ssid, filters))){
            free_se(soh->se[i], soh->n_buckets);
            soh->se[i] = NULL;
        }
    }
}

void export_csv(struct probe_history* ph, FILE* fp, int second_interval, _Bool unique_macs, char** filters, int occurence_floor){
    char date_str[30];
    time_t tt = oldest_probe(ph);
    struct tm lt;
    struct ssid_overview_hash* soh = gen_ssid_overview(ph, second_interval, unique_macs);
    filter_soh(soh, filters, occurence_floor);

    fprintf(fp, "%i second period", second_interval);
    for(int i = 0; i < STR_HASH_MAX; ++i){
        if(soh->se[i]){
            fprintf(fp, ",%s", soh->se[i]->ssid);
        }
    }
    fputc('\n', fp);
    for(int i = 0; i < soh->n_buckets; ++i){
        localtime_r((time_t*)&tt, &lt);
        memset(date_str, 0, sizeof(date_str));
        strftime(date_str, 50, "%B %d %Y %I:%M:%S %p", &lt);

        fprintf(fp, "%s", date_str);
        for(int j = 0; j < STR_HASH_MAX; ++j){
            if(!soh->se[j])continue;
            fprintf(fp, ",%i", soh->se[j]->buckets[i]);
        }
        fputc('\n', fp);
        tt += second_interval;
    }

    free_soh(soh);
    free(soh);
}
