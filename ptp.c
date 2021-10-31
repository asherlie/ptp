#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "mac_log.h"
#include "mq.h"

/*
 * repl, thread to collect packets and add them to queue
 * thread to pop from queue and process
*/

void gen_rand_mac_addr(uint8_t dest[6], int unique_bytes){
    int x = random(), y = random();

    memcpy(dest, &x, sizeof(int));
    memcpy(dest+sizeof(int), &y, 6-sizeof(int));
    for(int i = 0; i < 6-unique_bytes; ++i){
        dest[i] = 0xff;
    }
}

/* generates a spoofed packet */
uint8_t* gen_packet(int* len){
    uint8_t* pkt = calloc(1, 64);
    if(len)*len = 64;
    gen_rand_mac_addr(pkt, 1);
    strcpy((char*)pkt+6, "asher's network");
    
    return pkt;
}

void collect_packets(struct mqueue* mq){
    int pktlen;

    while(1){
        insert_mq(mq, gen_packet(&pktlen), pktlen);
        usleep((random() + 100000) % 1000000);
    }
}

/* returns two pointers within pkt - the first is addr[6], second is ssid[32] */
uint8_t** parse_raw_packet(uint8_t* pkt, int len){
    uint8_t** ret = malloc(sizeof(uint8_t*)*2);
    /* as of now, we know that the generated packets
     * have mac address at first byte
     */
    (void)len;

    ret[0] = pkt;
    ret[1] = pkt+6;

    return ret;
}

void process_packets(struct mqueue* mq, struct probe_history* ph){
    struct mq_entry* mqe;
    uint8_t** fields; 

    while(1){
        mqe = pop_mq(mq);
        fields = parse_raw_packet(mqe->buf, mqe->len);
        insert_probe_request(ph, fields[0], (char*)fields[1], mqe->timestamp);

        free(mqe->buf);
        free(mqe);
        free(fields);
    }
}

#if 0
have a packet that splits uint8_t to addr, 
i need to mq needs to store timestamp too
so that timestamp reflects the time of reception

update the probe insertion to take a time_t argument
#endif


void* collector_thread(void* arg){
    collect_packets((struct mqueue*)arg);
    return NULL;
}

struct mq_ph_pair{
    struct mqueue* mq;
    struct probe_history* ph;
};

void* processor_thread(void* arg){
    struct mq_ph_pair* mqph = arg;
    process_packets(mqph->mq, mqph->ph);
    return NULL;
}

/*
 * void* repl_thread(){
 * }
*/

int main(){
    struct mqueue mq;
    struct probe_history ph;
    struct mq_ph_pair mqph = {.mq = &mq, .ph = &ph};

    init_mq(&mq);
    init_probe_history(&ph);

    pthread_t pth[3];
    pthread_create(pth, NULL, collector_thread, &mq);
    pthread_create(pth+1, NULL, processor_thread, &mqph);

    while(1){
        usleep(1000000);
        printf("\r%i", ph.unique_addresses);
        p_probes(&ph, 1);
        fflush(stdout);
    }
    pthread_join(pth[0], NULL);
}
