#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "persist.h"
#include "mac_log.h"

_Bool dump_probe_history(struct probe_history* ph, char* fn){
    FILE* fp;
    struct mac_addr* ma;
    int notelen;
    int ps_len;
    int fingerprint = sizeof(struct mac_addr) + sizeof(struct probe_storage) + sizeof(time_t);

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
                if(ma->notes)fwrite(ma->notes, 1, notelen, fp);
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
                    fwrite(ps->probe_times, sizeof(time_t), ps->n_probes, fp);
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

int time_t_comparator(const void* x, const void* y){
    return *((time_t*)x) > *((time_t*)y);
}

/* we should be able to detect invalid files */
/* hmm - files are sometimes corrupted - the time_ts are sometimes
 * large negative numbers
 */

int _load_probe_history(struct probe_history* ph, char* fn){
    FILE* fp;
    uint8_t addr[6];
    char ssid[32], * note;
    int notelen, ps_len, n_probes, probes_removed = 0;
    time_t probe_time, current = time(NULL);
    struct probe_storage* ps;
    int n_inserted = 0;
    int fingerprint = 0;
    int n_corrupted = 0;
    _Bool failure = 0;

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
    if(fingerprint != (sizeof(struct mac_addr) + sizeof(struct probe_storage) + sizeof(time_t)))
        goto EXIT;

    while(fread(addr, 1, 6, fp) == 6){
        if(fread(&notelen, sizeof(int), 1, fp) != 1)
            goto EXIT;
        if(notelen){
            note = malloc(notelen+1);
            note[notelen] = 0;
            if((int)fread(note, 1, notelen, fp) != notelen)
                goto EXIT;
        }
        fread(&ps_len, sizeof(int), 1, fp);
        for(int i = 0; i < ps_len; ++i){
            if(fread(ssid, 1, 32, fp) != 32)
                goto EXIT;
            if(fread(&n_probes, sizeof(int), 1, fp) != 1)
                goto EXIT;
            for(int j = 0; j < n_probes; ++j){
                if(fread(&probe_time, sizeof(time_t), 1, fp) != 1)
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
                /* this pointer is used for sorting after all probes have been inserted
                 * this pointer should be identical with each iteration
                 */
                ps = insert_probe_request_nolock(ph, addr, ssid, probe_time, 1);
                ++n_inserted;
            }
            /* after reading all probes for a given mac/ssid pair,
             * it's time to sort/remove duplicates
             * logs will grow incomprehensible otherwise
             */
            /* it's good to have our probe times sorted even without duplicates */
            qsort(ps->probe_times, ps->n_probes, sizeof(time_t), time_t_comparator);
            /* duplicates should only ever occur when two different backup have overlapping times
             * OR when one backup is applied more than once
             * so this expensive section is acceptable
             */
            /*would it be more efficient to just swap last and first and then re-sort? */
            for(int i = 0; i < ps->n_probes-1; ++i){
                if(ps->probe_times[i] == ps->probe_times[i+1]){
                    memmove(ps->probe_times+i, ps->probe_times+i+1, (ps->n_probes-(i+1))*sizeof(time_t));
                    --ps->n_probes;
                    --i;
                    ++probes_removed;
                }
            }
        }
        /* done after our iteration to ensure that fields exist */
        if(notelen)add_note_nolock(ph, addr, note);
    }
    EXIT:
    if(fp)fclose(fp);
    /* subtract probes_removed to keep ph->total_probes accurate */
    ph->total_probes -= probes_removed;

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
    return ret;
}
