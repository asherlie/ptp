#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <pcap.h>

#ifdef READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "mac_log.h"
#include "persist.h"
#include "mq.h"

/* these are set to ph lock and file storage lock
 * and are used to ensure a safe exit so that
 * offload files aren't corrupted
 */
pthread_mutex_t* exit_locks[2];

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

    char ssid[32];
    uint8_t* packet_copy;

    pcap_t* pc = _pcap_init();

    if(!pc)exit(0);

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
        /* [l]oad_backup */
        case 'l':{
            FILE* fp;
            if(!args[1] || !(fp = fopen(args[1], "r"))){
                puts("please provide a valid filename");
                break;
            }
            /* hmm - this is sometimes appending n probes to a mac/ssid pair - TODO: look into this */
            load_probe_history(ph, fp);
            fclose(fp);
            printf("all entries backed up in \"%s\" have been merged/loaded into current storage\n", args[1]);
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
            p_probes(ph, 1, NULL, args[2], mac);
            break;
        }
        /*ssid command - addr (ssid)?*/
        case 's':{
            uint8_t mac[6] = {0};
            parse_maddr(args[2], mac);
            p_probes(ph, 1, NULL, args[1], parse_maddr(args[2], mac) ? mac : NULL);
            break;
        }
        /* [n]ote */
        case 'n':{
            uint8_t mac[6] = {0};
            FILE* fp = NULL;
            parse_maddr(args[1], mac);
            if(add_note(ph, mac, args[2] ? strdup(args[2]) : NULL)){
                /* TODO: what if this occurs during a routine offload
                 * can i have two file pointers open at once
                 * should be totally fine because of file_storage_lock
                 * we don't do any ACTUAL writing unless this is acquired
                 */
                printf("added note to %s\n", args[1]);
                if(ph->offload_fn && (fp = fopen(ph->offload_fn, "w"))){
                    dump_probe_history(ph, fp);
                }
            }
            else puts("failed to find matching MAC address");
            break;
        }
        /* [p]rint */
        case 'p':
            p_probes(ph, args[1], NULL, NULL, NULL);
            break;
        /* [d]istinct */
        /* [d]ata */
        case 'd':
            pthread_mutex_lock(&ph->lock);
            printf("%i probes collected accross %i distinct MAC addresses\n", ph->total_probes, ph->unique_addresses);
            pthread_mutex_unlock(&ph->lock);
            break;
        /* [r]ecent - prints the n mots recent probes */
        case 'r':
            p_most_recent(ph, args[1] ? atoi(args[1]) : 1);
            break;
        /* [f]ind - search by note */
        case 'f':
            /* TODO: should p_probes assume that note arg can be altered
             * if so, we can do the uppercase conversion at the beginning
             * of p_probes()
             */
            if(args[1]){
                for(char* i = args[1]; *i; ++i)
                    *i = toupper(*i);
            }
            p_probes(ph, args[2], args[1], NULL, NULL);
            break;
        /* [o]ldest */
        case 'o':
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

void wait_to_exit(int sig){
    (void)sig;
    
    printf("waiting to acquire locks in case of dump_probe_history()...");

    fflush(stdout);

    pthread_mutex_lock(exit_locks[0]);
    pthread_mutex_lock(exit_locks[1]);

    puts("exiting");

    exit(0);
}

/* if started with one arg - that filepath will be used to provide
 * startup state to ptp AS WELL AS shutdown storage
 *
 * TODO: add SIGTERM signal handler to dump_probe_history()
 */
void parse_args(int a, char** b, char** in_fn, char** out_fn){
    _Bool set_in = 0, set_out = 0;

    for(int i = 1; i < a; ++i){
        if(set_in){
            *in_fn = b[i];
            set_in = 0;
        }
        if(set_out){
            *out_fn = b[i];
            set_out = 0;
        }
        else if(*b[i] == '-'){
            switch(b[i][1]){
                case 'I':
                case 'i':
                    set_in = 1;
                    break;
                case 'O':
                case 'o':
                    set_out = 1;
                    break;
            }
        }
    }
}

int main(int a, char** b){
    struct mqueue mq;
    struct probe_history ph;
    struct mq_ph_pair mqph = {.mq = &mq, .ph = &ph};

    init_mq(&mq);
    init_probe_history(&ph, (a > 2) ? b[2] : NULL);

    exit_locks[0] = &ph.lock;
    exit_locks[1] = &ph.file_storage_lock;

    signal(SIGINT, wait_to_exit);

    if(a > 1){
        FILE* fp = fopen(b[1], "r");
        load_probe_history(&ph, fp);
        fclose(fp);
    }
    ph.restore_complete = 1;

    pthread_t pth[2];
    pthread_create(pth, NULL, collector_thread, &mq);
    pthread_create(pth+1, NULL, processor_thread, &mqph);

    /*
     * two big big issues - 
     *     this is only usable if a startup file is used eek
     *     i need to ensure that ptp doesn't exit during a 
     *     dump_probe_history()
     *     i need to have a signal handler that waits until a
     *     dump is over
     *     okay, i can just signal(sigint)
     *     and pthread_lock() ph lock and file storage lock
     *     once acquired, exit(0)
     *     we'll call this ~safe~ lol
    */

    repl(&ph);
    while(1){
        usleep(1000000);
        printf("\r%i", ph.unique_addresses);
        p_probes(&ph, 1, NULL, NULL, NULL);
        fflush(stdout);
    }
    pthread_join(pth[0], NULL);
}
