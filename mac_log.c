#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <ctype.h>

#include "mac_log.h"
#include "persist.h"

void init_mac_stack(struct mac_stack* ms, int n_most_recent){
    assert(n_most_recent > 1);
    pthread_mutex_init(&ms->lock, NULL);
    ms->n_most_recent = n_most_recent;

    ms->ins_idx = 0;
    ms->addrs = calloc(sizeof(struct mac_addr*), n_most_recent);
}

void free_mac_stack(struct mac_stack* ms){
    pthread_mutex_lock(&ms->lock);
    free(ms->addrs);
    pthread_mutex_unlock(&ms->lock);
    pthread_mutex_destroy(&ms->lock);
}

void insert_mac_stack(struct mac_stack* ms, struct mac_addr* ma, enum mac_stack_indices which){
    pthread_mutex_lock(&ms[which].lock);
    /* first handle pre-existing ma */
    if(ma->mac_stack_idx[which] != -1){
        /* if it's already at the top of the stack */
        if(ma->mac_stack_idx[which] == ms[which].ins_idx-1)goto EXIT;
        
        for(int i = ma->mac_stack_idx[which]; i < ms[which].ins_idx-1; ++i){
            ms[which].addrs[i] = ms[which].addrs[i+1];
            --ms[which].addrs[i]->mac_stack_idx[which];
        }
        ms[which].addrs[ms[which].ins_idx-1] = ma;
        ma->mac_stack_idx[which] = ms[which].ins_idx-1;
        goto EXIT;
    }
    
    /* if we have no space, move everything over  */
    if(ms[which].ins_idx == ms[which].n_most_recent){
        for(int i = 0; i < ms[which].ins_idx-1; ++i){
            ms[which].addrs[i] = ms[which].addrs[i+1];
            --ms[which].addrs[i]->mac_stack_idx[which];
        }
        ms[which].addrs[ms[which].ins_idx-1] = ma;
        ma->mac_stack_idx[which] = ms[which].ins_idx-1;
    }
    else ms[which].addrs[(ma->mac_stack_idx[which] = ms[which].ins_idx++)] = ma;

    EXIT:
    pthread_mutex_unlock(&ms[which].lock);
}

void init_probe_history(struct probe_history* ph, char* fn){
    pthread_mutex_init(&ph->lock, NULL);
    pthread_mutex_init(&ph->file_storage_lock, NULL);
    ph->unique_addresses = 0;
    ph->total_probes = 0;
    for(int i = 0; i < (0xff*6)+1; ++i){
        ph->buckets[i] = NULL;
    }
    init_mac_stack(ph->ms, 100);
    init_mac_stack(ph->ms+1, 100);

    ph->offload_fn = fn;
    if(fn){
        ph->offload_after = 1;
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
    ps->probe_times = malloc(sizeof(int64_t)*ps->probe_cap);
    memcpy(ps->ssid, ssid, 32);
}

struct mac_addr* alloc_mac_addr_bucket(uint8_t mac_addr[6]){
    struct mac_addr* new_entry = malloc(sizeof(struct mac_addr));
 
    memcpy(new_entry->addr, mac_addr, 6);
    new_entry->mac_stack_idx[0] = -1;
    new_entry->mac_stack_idx[1] = -1;
    new_entry->next = NULL;
    new_entry->notes = NULL;
    new_entry->probes = NULL;

    return new_entry;
}

/* returns success */
_Bool insert_probe(struct probe_storage* ps, int64_t timestamp){
    /* we ignore probes that occur in the same second
     * as the next most recently received probe
     */
    if(ps->n_probes && timestamp == ps->probe_times[ps->n_probes-1])return 0;

    if(ps->n_probes == ps->probe_cap){
        ps->probe_cap *= 2;
        int64_t* tmp = malloc(sizeof(int64_t)*ps->probe_cap);
        memcpy(tmp, ps->probe_times, sizeof(int64_t)*ps->n_probes);
        free(ps->probe_times);
        ps->probe_times = tmp;
    }
    ps->probe_times[ps->n_probes++] = timestamp;
    return 1;
}

/* returns whether a new bucket had to be created */
_Bool  _insert_probe_request(struct probe_history* ph, uint8_t mac_addr[6], char ssid[32],
                             int64_t timestamp, _Bool from_reload, _Bool lock, struct mac_addr** ret_ma,
                             struct probe_storage** ret_ps){

    int idx = sum_mac_addr(mac_addr);
    struct mac_addr** bucket, * prev_bucket, * ready_bucket;
    struct probe_storage* ps;
    _Bool found_bucket = 0, attempt_offload, ret = 0;

    if(lock)pthread_mutex_lock(&ph->lock);

    bucket = &ph->buckets[idx];

    /* initialize bucket if not found */
    if(!*bucket){
        ret = 1;
        ++ph->unique_addresses;
        *bucket = alloc_mac_addr_bucket(mac_addr);
    }

    /*
     * lookup bucket, if not found, allocate with new specific mac
     * go through all buckets looking for mac
     * if not found, alloc bucket
    */

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
        /* return whether or not we had to alloc a mac addr bucket */
        ret = 1;
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

    ph->total_probes += insert_probe(ps, timestamp);

    /* would be very bad form to offload during a [l]oad command
     * ESPECIALLY if -o and -i values are identical
     * this would immediately corrupt our files
     *
     * checking while lock still acquired
     */
    attempt_offload = !from_reload && ph->offload_fn && 
                      !(ph->total_probes % ph->offload_after);

    if(lock)pthread_mutex_unlock(&ph->lock);

    if(!from_reload){
        // TODO: add another mac stack to keep track of new addrs AND new ssids
        // TOTALLY new probes
        insert_mac_stack(ph->ms, ready_bucket, RECENTLY_RECVD);
        if(ret)insert_mac_stack(ph->ms, ready_bucket, NEW_ADDRS);
    }

    if(attempt_offload)dump_probe_history(ph, ph->offload_fn);

    if(ret_ma)*ret_ma = ready_bucket;
    if(ret_ps)*ret_ps = ps;

    return ret;
}

_Bool  insert_probe_request_nolock(struct probe_history* ph, uint8_t mac_addr[6], char ssid[32],
                             int64_t timestamp, _Bool from_reload, struct mac_addr** ret_ma,
                             struct probe_storage** ret_ps){
    return _insert_probe_request(ph, mac_addr, ssid, timestamp, from_reload, 0, ret_ma, ret_ps);
}

_Bool  insert_probe_request(struct probe_history* ph, uint8_t mac_addr[6], char ssid[32],
                             int64_t timestamp, _Bool from_reload, struct mac_addr** ret_ma,
                             struct probe_storage** ret_ps){
    return _insert_probe_request(ph, mac_addr, ssid, timestamp, from_reload, 1, ret_ma, ret_ps);
}

_Bool _add_note(struct probe_history* ph, uint8_t addr[6], char* note, _Bool lock){
    struct mac_addr* ma;

    if(note){
        for(char* i = note; *i; ++i)
            *i = toupper(*i);
    }

    if(lock)pthread_mutex_lock(&ph->lock);

    ma = ph->buckets[sum_mac_addr(addr)];
    for(; ma; ma = ma->next){
        if(!memcmp(ma->addr, addr, 6)){
            ma->notes = note;
            pthread_mutex_unlock(&ph->lock);
            return 1;
        }
    }
    if(lock)pthread_mutex_unlock(&ph->lock);
    return 0;
}

_Bool add_note(struct probe_history* ph, uint8_t addr[6], char* note){
    return _add_note(ph, addr, note, 1);
}

_Bool add_note_nolock(struct probe_history* ph, uint8_t addr[6], char* note){
    return _add_note(ph, addr, note, 0);
}

/*
TODO - make this threadsafe but fast by having a separate mutex lock at each bucket index
       another option, the simpler one, would be to simply have a receiving thread which
       we'll need regardless, which just reads in packets and a separate storage thread
       which takes its time to process packets in the queue

       there may be no need to have many processing threads

TODO - users should be able to connect to issue commands/request info about mac addresses

*/

/*
 * TODO: fix issues exposed by valgrind
 * TODO: add client that can remote connect
 * TODO: add [r]ange command to print entries within a range, enable filtering
 *
 * TODO: add mac address alerts - alert when mac sends a probe
 *
 * TODO: there should be a command to export addr's probes as csv - THIS IS HIGH PRIORITY
 *       it can then easily be graphed, which would be enlightening
 *
 *       the export command should be able to be filtered both by ssid and mac address or EITHER
 *       i can possibly bake this into the existing print functions
 *
 * TODO: print new to me command
 *
 * TODO: INTERESTING - add field in each probe for proximity - distance from router
 *       i can base this off of power, WOW
 *
 * TODO: add more verbosity settings - summarize option
 *       mac:
 *          ssid, most recent
 *
 *          OR have non-verbose print most recent
 *
 * most important missing features:
 *
 *   there might need to be two separate csv formats
 *      one focused on ssid
 *      one focused on mac address
 *
 *      ssid traffic over time
 *      mac address requests over time
 */

/*
 * TODO: HAVE BOOLEAN ARG THAT DETERMINES WHETHER TO USE RELATIVE TIME MODE - SUBTRACT FROM CURRENT TIME
 * this as well as the mac stack should be finished today
 * mac stack can be simplified greatly
*/
void p_probe_storage(struct probe_storage* ps, _Bool verbose, char* ssid, char* prepend){
    char date_str[50];
    time_t tmp_time;
    struct tm lt;

    if(ssid && !strstr(ps->ssid, ssid))return;

    if(prepend)fputs(prepend, stdout);
    
    printf("%s%i%s probes to \"%s%s%s\"\n", ANSI_BLUE, ps->n_probes, ANSI_RESET, ANSI_RED, ps->ssid, ANSI_RESET);

    if(!verbose){
        if(prepend)fputs(prepend, stdout);
        puts("most recent probe:");
    }

    for(int i = (verbose) ? 0 : ps->n_probes-1; i < ps->n_probes; ++i){
        tmp_time = ps->probe_times[i];
        localtime_r(&tmp_time, &lt);
        strftime(date_str, 50, "%A %B %d %Y @ %I:%M:%S %p", &lt);
        if(prepend){
            fputs(prepend, stdout);
            fputs(prepend, stdout);
        }
        puts(date_str);
    }
}

void p_mac_addr_probe(struct mac_addr* ma, _Bool p_timestamps, char* ssid, uint8_t* mac){
    _Bool ssid_match = !ssid;

    /* if we have an ssid search term, we unfortunately need to check if there will be
     * any matches in the probe storage before print our addresses
     */
    if(ssid){
        for(struct probe_storage* ps = ma->probes; ps; ps = ps->next){
            if(strstr(ps->ssid, ssid)){
                ssid_match = 1;
                break;
            }
        }
    }

    if(!ssid_match || (mac && memcmp(ma->addr, mac, 6)))return;
    /* how do i not print this in case of non-matching ssid? */
    printf("%s%.2hhX:%.2hhX:%.2hhX:%.2hhX:%.2hhX:%.2hhX%s:\n", ANSI_GREEN, ma->addr[0], ma->addr[1],
           ma->addr[2], ma->addr[3], ma->addr[4], ma->addr[5], ANSI_RESET);
    if(ma->notes)printf("  notes: %s%s%s\n", ANSI_MAGENTA, ma->notes, ANSI_RESET);

    for(struct probe_storage* ps = ma->probes; ps; ps = ps->next){
        p_probe_storage(ps, p_timestamps, ssid, "  ");
    }
}

/*this doesn't work with probes that were loaded from a dump, hmm*/
void p_mac_stack(struct probe_history* ph, enum mac_stack_indices which, int n){
    int c = 0;
    
    pthread_mutex_lock(&ph->lock);
    pthread_mutex_lock(&ph->ms[which].lock);

    for(int i = ph->ms[which].ins_idx-1; i >= 0 && c != n; --i){
        printf("%sSEQUENTIAL ENTRY #%i%s\n", ANSI_YELLOW, ph->ms[which].ins_idx-i, ANSI_RESET);
        p_mac_addr_probe(ph->ms[which].addrs[i], 0, NULL, NULL);
        ++c;
    }

    pthread_mutex_unlock(&ph->ms[which].lock);
    pthread_mutex_unlock(&ph->lock);
}

void p_probes(struct probe_history* ph, _Bool verbose, char* note, char* ssid, uint8_t* mac){
    struct mac_addr* ma;

    pthread_mutex_lock(&ph->lock);

    for(int i = 0; i < (0xff*6)+1; ++i){
        if((ma = ph->buckets[i])){
            for(; ma; ma = ma->next){
                if(!note || (ma->notes && strstr(ma->notes, note)))
                p_mac_addr_probe(ma, verbose, ssid, mac);
            }
        }
    }
    pthread_mutex_unlock(&ph->lock);
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
        free(map->notes);
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
    pthread_mutex_destroy(&ph->lock);
    pthread_mutex_destroy(&ph->file_storage_lock);
    free_mac_stack(ph->ms);
    free_mac_stack(ph->ms+1);
}

struct mac_addr* lookup_mac(struct probe_history* ph, uint8_t* mac){
    struct mac_addr* ma;
    ma = ph->buckets[sum_mac_addr(mac)];
    if(ma){
        for(; ma; ma = ma->next){
            if(!memcmp(ma->addr, mac, 6)){
                break;
            }
        }
    }
    return ma;
}

int64_t oldest_probe(struct probe_history* ph){
    int64_t oldest = time(NULL);
    pthread_mutex_lock(&ph->lock);

    for(int i = 0; i < (0xff*6)+1; ++i){
        if(!ph->buckets[i])continue;
        for(struct mac_addr* ma = ph->buckets[i]; ma; ma = ma->next){
            for(struct probe_storage* ps = ma->probes; ps; ps = ps->next){
                if(*ps->probe_times < oldest)oldest = *ps->probe_times;
            }
        }
    }
    pthread_mutex_unlock(&ph->lock);

    return oldest;
}
