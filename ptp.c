#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include <pcap.h>

#ifdef READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "mac_log.h"
#include "persist.h"
#include "mq.h"

/*
 * repl, thread to collect packets and add them to queue
 * thread to pop from queue and process
*/

pcap_t* _pcap_init(){
    pcap_t* pcap_data;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf;

    if(!(pcap_data = pcap_create("wlp3s0", errbuf))){
        puts("pcap_create() failed");
        return NULL;
    }

    if(pcap_set_immediate_mode(pcap_data, 1)){
        puts("pcap_set_immediate_mode() failed");
        return NULL;
    }

    if(!pcap_can_set_rfmon(pcap_data)){
        puts("pcap_can_set_rfmon() failed");
        return NULL;
    }
    
    if(pcap_set_rfmon(pcap_data, 1)){
        puts("pcap_set_rfmon() failed");
        return NULL;
    }

    if(pcap_activate(pcap_data) < 0){
        puts("pcap_activate() failed");
        return NULL;
    }

    if(pcap_compile(pcap_data, &bpf, "type mgt subtype probe-req", 0, PCAP_NETMASK_UNKNOWN) == -1){
        puts("pcap_compile() failed");
        return NULL;
    }

    if(pcap_setfilter(pcap_data, &bpf) == -1){
        puts("pcap_setfilter failed");
        return NULL;
    }

    pcap_freecode(&bpf);

    return pcap_data;
}

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

struct rtap_hdr{
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__((__packed__));

void collect_packets(struct mqueue* mq){
    int pktlen;
    struct pcap_pkthdr hdr;
    const uint8_t* packet;

    pcap_t* pc = _pcap_init();

    char ssid[32];
    uint8_t* packet_copy;

    while(1){
        packet = pcap_next(pc, &hdr);
        packet_copy = malloc(hdr.len);
        memcpy(packet_copy, packet, hdr.len);
        insert_mq(mq, packet_copy, hdr.len);
        continue;
        #if 0
        for(int i = 0; i < (int)hdr.len; ++i){
            if((packet[i] > 'a' && packet[i] < 'z') || (packet[i] > 'A' && packet[i] < 'Z'))
            44, 44-16
                printf("%i: %s\n", i, (char*)packet+i);
        }
        #endif
        /*printf("%s\n", (char*)packet+51-20);*/
        struct rtap_hdr* rhdr = (struct rtap_hdr*)packet;
        /*radiotag + length + x == ssidlen*/
        /* packet+rhdr->it_len + 10 should be sender address */
        /*printf("zero: %i, rtap length: %i\n", rhdr->it_version, rhdr->it_len);*/
        /*printf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx probed %s\n", packet[28], packet[29], packet[30], packet[31], packet[32], packet[33], packet+44);*/
        /* 6 bytes before sa should be 0xff */
        /*if(memcmp(packet+rhdr->it_len+10-6-6, 6))*/
        _Bool valid = 1;
        /*printf("%hhx should be 4\n", packet[rhdr->it_len]);*/
        valid = ((int)packet[rhdr->it_len+10+15]) && packet[rhdr->it_len] == 0x40;
        for(int i = 0; i < 6; ++i){
            if(packet[rhdr->it_len+10-6+i] != 0xff){
                  valid = 0;
                  break;
            }
        }
        if(!valid)continue;
        /*printf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx probed %s\n", packet[rhdr->it_len+10], packet[rhdr->it_len+11], packet[rhdr->it_len+12], packet[rhdr->it_len+13], packet[rhdr->it_len+14], packet[rhdr->it_len+15], NULL);*/

        /*printf("ssid len: %hhx\n", packet + rhdr->it_len + 10+15);*/
        /*this seems to be working!*/
        /*
         *printf("ssid len: %hhx %i\n", packet [ rhdr->it_len + 10+15], packet [ rhdr->it_len + 10+15]);
         *for(int i = 0; i < (int)packet[rhdr->it_len+10+15]; ++i){
         *    printf("%c", packet[rhdr->it_len+10+15+1+i]);
         *}
         *puts("");
         */

        /*printf("len: %i\n", (int)packet[rhdr->it_len+10+15]);*/
        memset(ssid, 0, 32);
        memcpy(ssid, packet+rhdr->it_len+10+15+1, (int)packet[rhdr->it_len+10+15]);
        /*puts(ssid);*/

        /* sa +15 is the length of the ssid */
        /*printf("");*/
        /*insert_mq(mq, packet);*/
        insert_mq(mq, gen_packet(&pktlen), pktlen);
        /*usleep((random() + 100000) % 1000000);*/
        /*usleep(5000000);*/
    }
}

/* returns two pointers within pkt - the first is addr[6], second is ssid[32] */
uint8_t** parse_raw_packet(uint8_t* packet, int len){
    uint8_t** ret = malloc(sizeof(uint8_t*)*2);
    struct rtap_hdr* rhdr = (struct rtap_hdr*)packet;
    uint8_t* ssid = calloc(1, 32);
    uint8_t* addr = calloc(1, 6);
    _Bool valid = 1;
    (void)len;
    /*printf("%hhx should be 4\n", packet[rhdr->it_len]);*/
    valid = ((int)packet[rhdr->it_len+10+15]) && packet[rhdr->it_len] == 0x40;
    memcpy(addr, packet+rhdr->it_len+10, 6);
    for(int i = 0; i < 6; ++i){
        if(packet[rhdr->it_len+10-6+i] != 0xff){
            valid = 0;
            break;
        }
    }
    if(!valid){
        free(ret);
        free(packet);
        return NULL;
    }
    memcpy(ssid, packet+rhdr->it_len+10+15+1, (int)packet[rhdr->it_len+10+15]);

    ret[0] = addr;
    ret[1] = ssid;

    /*free(packet);*/
    return ret;
}

void process_packets(struct mqueue* mq, struct probe_history* ph){
    struct mq_entry* mqe;
    uint8_t** fields; 

    while(1){
        mqe = pop_mq(mq);
        fields = parse_raw_packet(mqe->buf, mqe->len);
        if(!fields)continue;
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
        /* [b]ackup */
        case 'b':{
            FILE* fp;
            if(!args[1] || !(fp = fopen(args[1], "w"))){
                puts("please provide a valid filename");
                break;
            }
            dump_probe_history(ph, fp);
            fclose(fp);

            printf("all probe data has been written to \"%s\"\n", args[1]);
            break;
        }
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
    #ifndef READLINE
    size_t sz = 0;
    int len;
    #endif

    while(1){
        #ifdef READLINE
        if(ln)free(ln);
        ln = readline("**PTP>** ");
        if(!ln || !*ln){
            for(int i = 0; i < 3; ++i){
                printf(". ");
                fflush(stdout);
                usleep(50000);
            }
            printf("\r");
            for(int i = 0; i < 3; ++i)printf("  ");
            printf("\r");
            continue;
        }
        add_history(ln);
        #else
        len = getline(&ln, &sz, stdin);
        ln[--len] = 0;
        #endif

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
