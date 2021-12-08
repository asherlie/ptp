#include <sys/msg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kmq.h"
#include "mac_log.h"

#define KQ_MAX 1000

struct msgbuf{
    long mtype;
    char mdata[KQ_MAX];
};

/* not threadsafe by default because they are meant to be used inside calls to _insert_probe_request() */
/*
 * there's no need to check if ph->mq_key != -1 because this is guaranteed not to occur since it will be either set
 * at startup with the -key flag OR generated at the first [t] or [k] command being issued
*/
_Bool alert_eligible(struct probe_history* ph, struct mac_addr* ma){
    return ph->alerts_enabled && ma->alert_threshold >= 0 && 
           /* ma->probes->n_probes should never be 1, n_probes will be >= 1 already when set_alert_thresholds() is called
            * because it can only set the relevant flag for mac_addr structs that have notes
            * notes can only be added to entries that exist
            */
           (ma->probes->probe_times[ma->probes->n_probes-1] - ma->probes->probe_times[ma->probes->n_probes-2] > ma->alert_threshold);
}

int set_alert_thresholds(struct probe_history* ph, char* filter, int threshold){
    struct mac_addr* ma;
    int ret = 0;

    pthread_mutex_lock(&ph->lock);
    if(ph->mq_key == -1){
        srand(time(NULL));
        ph->mq_key = random();
        msgget(ph->mq_key, 0777 | IPC_CREAT);
    }
    if(filter){
        for(int i = 0; i < (0xff*6)+1; ++i){
            if((ma = ph->buckets[i])){
                for(; ma; ma = ma->next){
                    if(!ma->notes || (*filter != '*' && !strstr(ma->notes, filter)))continue;
                    ++ret;
                    printf("%i -> %i: %s\n", ma->alert_threshold, threshold, ma->notes);
                    ma->alert_threshold = threshold;
                }
            }
        }
    }
    pthread_mutex_unlock(&ph->lock);
    return ret;
}

int p_alert_thresholds(struct probe_history* ph, char* filter, _Bool show_unset){
    int cnt = 0;
    struct mac_addr* ma;
    pthread_mutex_lock(&ph->lock);
    for(int i = 0; i < (0xff*6)+1; ++i){
        if((ma = ph->buckets[i])){
            for(; ma; ma = ma->next){
                if(!ma->notes || (filter && *filter != '*' &&
                   !strstr(ma->notes, filter)) || 
                   (!show_unset && ma->alert_threshold < 0))continue;
                ++cnt;
                printf("  %i: %s\n", ma->alert_threshold, ma->notes);
            }
        }
    }
    pthread_mutex_unlock(&ph->lock);

    return cnt;
}

/* set_alert_thresholds() must have been called at least once before this is called */
_Bool add_alert(struct probe_history* ph, struct mac_addr* ma){
    struct msgbuf mb = {0};
    int msgid = msgget(ph->mq_key, 0777), msglen;
    if(msgid == -1)return 0;
    msglen = snprintf(mb.mdata, KQ_MAX, "ARRIVAL ALERT FOR %s", ma->notes);
    mb.mtype = 1;
    return !msgsnd(msgid, &mb, msglen, 0);
}
