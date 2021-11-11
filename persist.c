#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "persist.h"
#include "mac_log.h"

void dump_probe_history(struct probe_history* ph, FILE* fp){
    struct mac_addr* ma;
    int notelen;
    int ps_len;
    int fingerprint = sizeof(struct mac_addr) + sizeof(struct probe_storage) + sizeof(time_t);

    pthread_mutex_lock(&ph->lock);
    pthread_mutex_lock(&ph->file_storage_lock);
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
    pthread_mutex_unlock(&ph->lock);
    pthread_mutex_unlock(&ph->file_storage_lock);
}

int time_t_comparator(const void* x, const void* y){
    return *((time_t*)x) > *((time_t*)y);
}

/* we should be able to detect invalid files */
int load_probe_history(struct probe_history* ph, FILE* fp){
    uint8_t addr[6];
    char ssid[32], * note;
    int notelen, ps_len, n_probes, probes_removed = 0;
    time_t probe_time;
    struct probe_storage* ps;
    int n_inserted = 0;
    int fingerprint;

    pthread_mutex_lock(&ph->file_storage_lock);

    if(fread(&fingerprint, sizeof(int), 1, fp) != 1 || 
        fingerprint != (sizeof(struct mac_addr) + sizeof(struct probe_storage) + sizeof(time_t)))goto EXIT;
    while(fread(addr, 1, 6, fp) == 6){
        if(fread(&notelen, sizeof(int), 1, fp) != 1)goto EXIT;
        if(notelen){
            note = malloc(notelen);
            if((int)fread(note, 1, notelen, fp) != notelen)goto EXIT;
        }
        fread(&ps_len, sizeof(int), 1, fp);
        for(int i = 0; i < ps_len; ++i){
            if(fread(ssid, 1, 32, fp) != 32)goto EXIT;
            if(fread(&n_probes, sizeof(int), 1, fp) != 1)goto EXIT;
            for(int j = 0; j < n_probes; ++j){
                if(fread(&probe_time, sizeof(time_t), 1, fp) != 1)goto EXIT;
                /* this pointer is used for sorting after all probes have been inserted
                 * this pointer should be identical with each iteration
                 */
                ps = insert_probe_request(ph, addr, ssid, probe_time);
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
        if(notelen)add_note(ph, addr, note);
    }
    EXIT:

    pthread_mutex_unlock(&ph->file_storage_lock);

    /* subtract probes_removed to keep ph->total_probes accurate */
    pthread_mutex_lock(&ph->lock);
    ph->total_probes -= probes_removed;
    pthread_mutex_unlock(&ph->lock);

    return n_inserted-probes_removed;
}

#if 0
void gen_rand_mac_addr(uint8_t dest[6], int unique_bytes){
    int x = random(), y = random();

    memcpy(dest, &x, sizeof(int));
    memcpy(dest+sizeof(int), &y, 6-sizeof(int));
    for(int i = 0; i < 6-unique_bytes; ++i){
        dest[i] = 0xff;
    }
}

void test(char* fn){
    FILE* fp = fopen(fn, "w");
    struct probe_history ph, loaded_ph;
    uint8_t addr[6];
    char ssid[32] = "one_direction", * note = malloc(20);
    strcpy(note, "this is a network");
    srand(time(NULL));
    init_probe_history(&ph);
    init_probe_history(&loaded_ph);
    for(int i = 0; i < 1000; ++i){
        /* the last 600 insertions will be to the same addr */
        gen_rand_mac_addr(addr, 6);
        insert_probe_request(&ph, addr, ssid, time(NULL));
        add_note(&ph, addr, note);
    }
    for(int i = 0; i < 10000; ++i){
        insert_probe_request(&ph, addr, ssid, time(NULL));
    }
    dump_probe_history(&ph, fp);
    fclose(fp);

    fp = fopen(fn, "r");
    load_probe_history(&loaded_ph, fp);
    fclose(fp);

    p_probes(&loaded_ph, 1, NULL, NULL);
    puts("----SEPARATOR----");
    p_probes(&ph, 1, NULL, NULL);

    free_probe_history(&ph);
}

int main(int a, char** b){
    (void)a;
    test(b[1]);
    return 0;
}
#endif
