#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kmq.h"
#include "persist.h"
#include "mac_log.h"

int ma_comparator(const void* x, const void* y){
    const struct mac_addr* mx = x, * my = y;
    /*printf("accessing %p and %p\n", (void*)mx->probes->probe_times, (void*)my->probes->probe_times);*/
    return *mx->probes->probe_times > *my->probes->probe_times;
}

/* only necessary at startup/loading
 * this operation sorts all probes by time and inserts them
 * into a spoofed ph in sequential order - the generated mac stacks
 * from the spoofed ph then have their info copied over to ph
 * all mac index references are reset to -1
 * in case this is called by the user
 */
void normalize_mac_stacks(struct probe_history* ph){
    struct mac_addr* addrs = malloc(sizeof(struct mac_addr)*ph->/*unique_addresses*/total_probes), * ma;
    struct probe_history spoof_ph;
    int idx = 0;
    init_probe_history(&spoof_ph, NULL);

    pthread_mutex_lock(&ph->lock);
    /* creating flattened mac stack array */
    for(int i = 0; i < (0xff*6)+1; ++i){
        if(!(ma = ph->buckets[i]))continue;
        for(; ma; ma = ma->next){
            for(struct probe_storage* ps = ma->probes; ps; ps = ps->next){
                for(int j = 0; j < ps->n_probes; ++j){
                    memcpy(addrs[idx].addr, ma->addr, 6);
                    addrs[idx].probes = malloc(sizeof(struct probe_storage));
                    addrs[idx].probes->probe_times = malloc(sizeof(int64_t));
                    addrs[idx].probes->n_probes = 1;
                    addrs[idx].probes->probe_cap = 1;
                    addrs[idx].probes->next = NULL;
                    memcpy(addrs[idx].probes->ssid, ps->ssid, 32);
                    *addrs[idx].probes->probe_times = ps->probe_times[j];
                    ++idx;
                }
            }
        }
    }

    /* sorting, inserting */
    qsort(addrs, ph->total_probes, sizeof(struct mac_addr), ma_comparator);
    for(int i = 0; i < ph->total_probes; ++i){
        insert_probe_request_nolock(&spoof_ph, addrs[i].addr, addrs[i].probes->ssid, *addrs[i].probes->probe_times, 0, NULL, NULL);
        free(addrs[i].probes->probe_times);
        free(addrs[i].probes);
    }

    free(addrs);

    /* updating mac_stack_idx for original ph by looking up addr in ph,
     * copying over data from spoofed mac stacks, removing now irrelevant
     * old indices
     *
     */
    for(int ms_i = 0; ms_i < 2; ++ms_i){
        ph->ms[ms_i].ins_idx = spoof_ph.ms[ms_i].ins_idx;
        for(int i = 0; i < spoof_ph.ms[ms_i].n_most_recent; ++i){
            if(ph->ms[ms_i].addrs[i])ph->ms[ms_i].addrs[i]->mac_stack_idx[ms_i] = -1;
            if(!spoof_ph.ms[ms_i].addrs[i]){
                ph->ms[ms_i].addrs[i] = NULL;
                continue;
            }
            ma = lookup_mac(ph, spoof_ph.ms[ms_i].addrs[i]->addr);
            ma->mac_stack_idx[ms_i] = spoof_ph.ms[ms_i].addrs[i]->mac_stack_idx[ms_i];

            ph->ms[ms_i].addrs[i] = ma;
        }
    }

    free_probe_history(&spoof_ph);

    pthread_mutex_unlock(&ph->lock);
}


_Bool dump_probe_history(struct probe_history* ph, char* fn){
    FILE* fp;
    struct mac_addr* ma;
    int notelen;
    int ps_len;
    /* TODO: phase out fingerprinting altogether */
    int fingerprint = -1;

    pthread_mutex_lock(&ph->lock);
    pthread_mutex_lock(&ph->file_storage_lock);
    if(!(fp = fopen(fn, "w")))goto EXIT;
    fwrite(&fingerprint, sizeof(int), 1, fp);
    for(int i = 0; i < (0xff*6)+1; ++i){
        if((ma = ph->buckets[i])){
            for(; ma; ma = ma->next){
                notelen = ma->notes ? strlen(ma->notes) : 0;
                /* deal with struct mac_addr */
                fwrite(ma->addr, 1, 6, fp);
                fwrite(&notelen, sizeof(int), 1, fp);
                if(ma->notes){
                    fwrite(ma->notes, 1, notelen, fp);
                    fwrite(&ma->alert_threshold, sizeof(int), 1, fp);
                }
                /* deal with probes */
                ps_len = 0;
                for(struct probe_storage* ps = ma->probes; ps; ps = ps->next){
                    ++ps_len;
                }
                fwrite(&ps_len, sizeof(int), 1, fp);
                for(struct probe_storage* ps = ma->probes;
                    ps; ps = ps->next){
                    
                    fwrite(ps->ssid, 1, 32, fp);
                    fwrite(&ps->n_probes, sizeof(int), 1, fp);
                    fwrite(ps->probe_times, sizeof(int64_t), ps->n_probes, fp);
                }
            }
        }
    }
    fclose(fp);

    EXIT:
    pthread_mutex_unlock(&ph->lock);
    pthread_mutex_unlock(&ph->file_storage_lock);

    return fp;
}

int probe_comparator(const void* x, const void* y){
    return *((int64_t*)x) > *((int64_t*)y);
}

/* we should be able to detect invalid files */
/* hmm - files are sometimes corrupted - the time_ts are sometimes
 * large negative numbers
 */

int _load_probe_history(struct probe_history* ph, char* fn){
    FILE* fp;
    uint8_t addr[6];
    char ssid[32], * note;
    int notelen, alert_thresh, ps_len, n_probes, probes_removed = 0;
    int64_t probe_time, current = time(NULL);
    struct probe_storage* ps;
    struct mac_addr* ma;
    int n_inserted = 0;
    int fingerprint = 0;
    int n_corrupted = 0;
    _Bool failure = 0, alerts_enabled = 0;

    pthread_mutex_lock(&ph->lock);
    pthread_mutex_lock(&ph->file_storage_lock);

    if(!(fp = fopen(fn, "r"))){
        failure = 1;
        goto EXIT;
    }

    /* if file can't be read from we might be getting
     * spammed with signals
     * give it some time and attempt to load again
     */
    if(fread(&fingerprint, sizeof(int), 1, fp) != 1){
        failure = 1;
        goto EXIT;
    }
    while(fread(addr, 1, 6, fp) == 6){
        if(fread(&notelen, sizeof(int), 1, fp) != 1)
            goto EXIT;
        if(notelen){
            note = malloc(notelen+1);
            note[notelen] = 0;
            if((int)fread(note, 1, notelen, fp) != notelen)
                goto EXIT;
            if(fread(&alert_thresh, sizeof(int), 1, fp) != 1)
                goto EXIT;
        }
        if(fread(&ps_len, sizeof(int), 1, fp) != 1)
            goto EXIT;
        while(ps_len--){
            if(fread(ssid, 1, 32, fp) != 32)
                goto EXIT;
            if(fread(&n_probes, sizeof(int), 1, fp) != 1)
                goto EXIT;
            while(n_probes--){
                if(fread(&probe_time, sizeof(int64_t), 1, fp) != 1)
                    goto EXIT;
                /* 1635379200 is the date of the first commit to ptp
                 * any backups that are older are a bit suspicious
                 * TODO: find out why/how dumps get corrupted
                 */
                if(probe_time > current || (probe_time < 1635379200)){
                    /* if this probe is bad, ignore and print about it later */
                    ++n_corrupted;
                    continue;
                }

                /* ps is used for sorting after all probes have been inserted
                 * ps pointer should be identical with each iteration
                 */
                insert_probe_request_nolock(ph, addr, ssid, probe_time, 1, &ma, &ps);
                ++n_inserted;
            }
            /* after reading all probes for a given mac/ssid pair,
             * it's time to sort/remove duplicates
             * logs will grow incomprehensible otherwise
             */
            /* it's good to have our probe times sorted even without duplicates */
            qsort(ps->probe_times, ps->n_probes, sizeof(int64_t), probe_comparator);
            /* duplicates should only ever occur when two different backup have overlapping times
             * OR when one backup is applied more than once
             * so this expensive section is acceptable
             */
            /*would it be more efficient to just swap last and first and then re-sort? */
            for(int i = 0; i < ps->n_probes-1; ++i){
                if(ps->probe_times[i] == ps->probe_times[i+1]){
                    memmove(ps->probe_times+i, ps->probe_times+i+1, (ps->n_probes-(i+1))*sizeof(int64_t));
                    --ps->n_probes;
                    --i;
                    ++probes_removed;
                }
            }
        }
        /* done after our iteration to ensure that fields exist */
        if(notelen){
            add_note_nolock(ph, addr, note);
            alerts_enabled |= ((ma->alert_threshold = alert_thresh) >= 0);
        }
    }
    EXIT:
    if(fp)fclose(fp);
    /* subtract probes_removed to keep ph->total_probes accurate */
    ph->total_probes -= probes_removed;

    /* if >= 1 alert is found to be enabled, ensure that our queue
     * is created if it needs to be
     */
    if(alerts_enabled)set_alert_thresholds(ph, NULL, -1, 0);

    pthread_mutex_unlock(&ph->lock);
    pthread_mutex_unlock(&ph->file_storage_lock);

    if(n_corrupted){
        printf("%sdump contains %i ~probably~ corrupted probes%s\n", ANSI_RED, n_corrupted, ANSI_RESET);
    }

    /* return -1 if we couldn't read the first handful of bytes or open the fp */
    if(failure)return -1;
    return n_inserted-probes_removed;
}

int load_probe_history(struct probe_history* ph, char* fn){
    int n_attempts = 1, ret = _load_probe_history(ph, fn);
    for(int i = 0; (i < n_attempts-1) && (ret == -1); ++i){
        usleep(10000);
        ret = _load_probe_history(ph, fn);
    }
    normalize_mac_stacks(ph);
    return ret;
}
