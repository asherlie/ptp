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
                fwrite(ma->addr, 1, 6, fp);
                fwrite(&notelen, sizeof(int), 1, fp);
            }
        }
    }
    pthread_mutex_unlock(&ph->lock);
}
