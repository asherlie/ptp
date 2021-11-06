#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "persist.h"
#include "mac_log.h"

#if 0
for each bucket that is populated:

dump mac:
    write addr, notelen, notes, 
    for each gT

can just store a list of ssid, maddr, time

dump mac:
    addr, notelen, notes, time_t

    each mac will have n_probes things

for i in buckets
    if i
        for j in buckets.all
            for k in probes
                write ssid, mac addr, k

void* dump_mac_addr(FILE* fp){
}
#endif

void dump_probe_history(struct probe_history* ph, FILE* fp){
    struct mac_addr* ma;
    int notelen;
    int ps_len;

    pthread_mutex_lock(&ph->lock);
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
}

void load_probe_history(struct probe_history* ph, FILE* fp){
    uint8_t addr[6];
    char ssid[32], * note;
    int notelen, ps_len, n_probes;
    time_t probe_time;

    pthread_mutex_lock(&ph->lock);

    while(fread(addr, 1, 6, fp) == 6){
        fread(&notelen, sizeof(int), 1, fp);
        if(notelen){
            note = malloc(notelen);
            fread(note, 1, notelen, fp);
        }
        fread(&ps_len, sizeof(int), 1, fp);
        for(int i = 0; i < ps_len; ++i){
            fread(ssid, 1, 32, fp);
            fread(&n_probes, sizeof(int), 1, fp);
            for(int j = 0; j < n_probes; ++j){
                fread(&probe_time, sizeof(time_t), 1, fp);
                insert_probe_request(ph, addr, ssid, probe_time);
            }
        }
        /* done after our iteration to ensure that fields exist */
        if(notelen)add_note(ph, addr, note);
    }
    pthread_mutex_unlock(&ph->lock);
}

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
    char ssid[32] = "booboo child";
    srand(time(NULL));
    init_probe_history(&ph);
    init_probe_history(&loaded_ph);
    for(int i = 0; i < 1000; ++i){
        /* the last 600 insertions will be to the same addr */
        gen_rand_mac_addr(addr, 6);
        insert_probe_request(&ph, addr, ssid, time(NULL));
    }
    for(int i = 0; i < 10000; ++i){
        insert_probe_request(&ph, addr, ssid, time(NULL));
    }
    dump_probe_history(&ph, fp);
    fclose(fp);

    fp = fopen(fn, "r");
    load_probe_history(&loaded_ph, fp);
    fclose(fp);


    free_probe_history(&ph);
}

int main(int a, char** b){
    test(b[1]);
    return 0;
}
