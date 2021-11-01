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
    gen_rand_mac_addr(pkt, 6);
    strcpy((char*)pkt+6, "asher's network");
    pkt[6] += random() % 26;
    
    return pkt;
}

void collect_packets(struct mqueue* mq){
    int pktlen;

    while(1){
        insert_mq(mq, gen_packet(&pktlen), pktlen);
        /*usleep((random() + 100000) % 1000000);*/
        usleep(5000000);
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

_Bool parse_maddr(char* mstr, uint8_t mac[6]){
    if(!mstr)return 0 ;
    sscanf(mstr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           mac, mac+1, mac+2, mac+3, mac+4, mac+5);
    return 1;
}

void handle_command(char* cmd, struct probe_history* ph){
    char* args[100] = {0};
    char* sp = cmd, * prev = cmd;
    int n_args = 0;
    (void)ph;

    while((sp = strchr(sp, ' '))){
        *sp = 0;
        args[n_args++] = prev;
        prev = ++sp;
    }
    args[n_args++] = prev;

    switch(*cmd){
        #if 0
        the most important commands to implement for interacting with the data are:
            note
            note search
            ssid

            ssid search and mac search should be two separate commands
            each print function should take an optional search term arg
            the outermost has both options

            ssid x y
                and
            mac y x
            
            will yield the same results

            possibly add a feature for changing directory in order to navigate
        #endif
        /* [c]lear */
        case 'c':
            puts("\n\n========================================\n");
            break;
        /* [m]ac / [a]ddr lookup */
        case 'm':
        case 'a':{
            uint8_t mac[6] = {0};
            parse_maddr(args[1], mac);
            p_probes(ph, 1, args[2], mac);
            break;
        }
        /*ssid command - addr (ssid)?*/
        case 's':{
            uint8_t mac[6] = {0};
            parse_maddr(args[2], mac);
            p_probes(ph, 1, args[1], parse_maddr(args[2], mac) ? mac : NULL);
            break;
        }
        /* [n]ote */
        case 'n':{
            uint8_t mac[6] = {0};
            parse_maddr(args[1], mac);
            if(add_note(ph, mac, args[2] ? strdup(args[2]) : NULL))
                printf("added note to %s\n", args[1]);
            else puts("failed to find matching MAC address");
            break;
        }
        /* [p]rint */
        case 'p':
            p_probes(ph, args[1], NULL, NULL);
            break;
        /* [d]istinct */
        case 'd':
            pthread_mutex_lock(&ph->lock);
            printf("%i distinct MAC addresses collected\n", ph->unique_addresses);
            pthread_mutex_unlock(&ph->lock);
            break;
    }
}

void repl(struct probe_history* ph){
    char* ln = NULL;
    size_t sz = 0;
    int len;

    while(1){
        len = getline(&ln, &sz, stdin);
        ln[--len] = 0;

        handle_command(ln, ph);
    }
    (void)ph;
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

    repl(&ph);
    while(1){
        usleep(1000000);
        printf("\r%i", ph.unique_addresses);
        p_probes(&ph, 1, NULL, NULL);
        fflush(stdout);
    }
    pthread_join(pth[0], NULL);
}
