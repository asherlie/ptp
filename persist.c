#include <stdio.h>
#include <string.h>

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

    pthread_mutex_lock(&ph->lock);
    for(int i = 0; i < (0xff*6)+1; ++i){
        if((ma = ph->buckets[i])){
            for(; ma; ma = ma->next){
                notelen = strlen(ma->notes);
                /* deal with struct mac_addr */
                fwrite(ma->addr, 1, 6, fp);
                fwrite(&notelen, sizeof(int), 1, fp);
                fwrite(ma->notes, 1, notelen, fp);
                /* deal with probes */
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
