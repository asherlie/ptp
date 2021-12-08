#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>

#include <pcap.h>

#ifdef READLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "kmq.h"
#include "mac_log.h"
#include "persist.h"
#include "mq.h"
#include "csv.h"

#define PTP_VER_STR "0.9.3"

/* used to ensure a safe exit so that
 * offload files aren't corrupted
 */
struct probe_history* __ph;

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

struct rtap_hdr{
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
} __attribute__((__packed__));

void collect_packets(struct mqueue* mq){
    struct pcap_pkthdr hdr;
    const uint8_t* packet;

    uint8_t* packet_copy;

    pcap_t* pc = _pcap_init();

    if(!pc)exit(0);

    while(1){
        if(!(packet = pcap_next(pc, &hdr)))
            continue;
        packet_copy = malloc(hdr.len);
        memcpy(packet_copy, packet, hdr.len);
        insert_mq(mq, packet_copy, hdr.len);
    }
}

/* returns two pointers within pkt - the first is addr[6], second is ssid[32] */
uint8_t** parse_raw_packet(uint8_t* packet, int len){
    struct rtap_hdr* rhdr = (struct rtap_hdr*)packet;
    uint8_t** ret;
    uint8_t* ssid;
    uint8_t* addr;

    if(!((len > (int)sizeof(struct rtap_hdr)) && (len >= rhdr->it_len+10+15+1) &&
       ((int)packet[rhdr->it_len+10+15]) && packet[rhdr->it_len] == 0x40)){
        return NULL;
    }

    for(int i = 0; i < 6; ++i){
        if(packet[rhdr->it_len+10-6+i] != 0xff){
            return NULL;
        }
    }

    ret = malloc(sizeof(uint8_t*)*2);
    ssid = calloc(1, 32);
    addr = calloc(1, 6);

    memcpy(addr, packet+rhdr->it_len+10, 6);
    memcpy(ssid, packet+rhdr->it_len+10+15+1, (int)packet[rhdr->it_len+10+15]);

    ret[0] = addr;
    ret[1] = ssid;

    return ret;
}

void process_packets(struct mqueue* mq, struct probe_history* ph){
    struct mq_entry* mqe;
    uint8_t** fields; 

    while(1){
        mqe = pop_mq(mq);
        fields = parse_raw_packet(mqe->buf, mqe->len);
        if(!fields){
            free(mqe->buf);
            free(mqe);
            continue;
        }
        insert_probe_request(ph, fields[0], (char*)fields[1], mqe->timestamp, 0, NULL, NULL);

        free(mqe->buf);
        free(mqe);
        free(fields[0]);
        free(fields[1]);
        free(fields);
    }
}

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
    return mstr && sscanf(mstr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   mac, mac+1, mac+2, mac+3, mac+4, mac+5) == 6;
}

_Bool parse_seconds(char* str, int* ret){
	char* endptr = NULL, lowend;
	double conv = strtod(str, &endptr);

	int map[10] = {86400, 1, 1, 1, 3600, 1, 1, 1, 1, 60};

	if(endptr == str)return 0;

	lowend = tolower(*endptr);
	if(lowend >= 'd' && lowend <= 'm')conv *= (map[lowend-'d']);
	
	if(ret){
        conv += (conv >= 0) ? .5 : -.5;
        *ret = (int)conv;
    }
	return 1;
}

void handle_command(char* cmd, struct probe_history* ph){
    char* args[200] = {0};
    char* sp = cmd, * prev = cmd;
    int n_args = 0;

    while((sp = strchr(sp, ' '))){
        *sp = 0;
        args[n_args++] = prev;
        prev = ++sp;
    }
    args[n_args++] = prev;


    #if 0
    NTD NEWTODO:
    there really should be another csv option to create them based on address
    graph addresses over time

    addygraph <addr0> <addr1> <addr2> <addr...>

    maybe based on buckets also

    this can be done without any additional data structs
    because ph is already indexed using addrs

    create n buckets each sized according to time per bucket
    there will be n_uniqe_macs buckets

    go through each mac addr`s probes, adding each probe to the relevant bucket index

    labels with be mac addresses unless a note exists, in which case it will be a note

    also need a command for arrival time - prints all the times a device has sent a probe
    after threshold seconds of inactivity
    [arrival] [addr/note] <threshold>

    ALSO important!!! a command to export csv for networks instead of users
    will graph different users pings to a network over time
    this will make it easy to group them together and reason about who is represented by what MAC

    another option to give a list of days that someone is known to have been here
    this returns a list of addresses, optionally with none that have notes included
    #endif

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
            if(!args[1] || !dump_probe_history(ph, args[1])){
                puts("please provide a valid filename");
                break;
            }
            printf("all probe data has been written to \"%s\"\n", args[1]);
            break;
        }
        /* network over time command */
        /* csv of a specific network
         * this command should group probes into 10 or configurable n minute buckets
         * and make a csv with number of distinct mac addresses that made probe requests
         * in that window
         * n_minute_period | one_direction
         * -----------------------------
         *  0              | 20
         *  1              | 20
         *  2              | 20
         *  3              | 11
         *  4              | 2
         *  5              | 2
         *
         * first group all of the same ssid together
         * total time = newest probe - oldest
         * then make (total time)/(10*1000000) buckets - 10 second buckets
         *
         *   OR
         * it should keep track of gaps
         * possibly try different methods of quantifying number of 
         * addresses per ssid
         */
        /* [l]oad_backup */
        case 'l':{
            if(!args[1] || load_probe_history(ph, args[1]) < 0){
                puts("please provide a valid filename");
                break;
            }
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
        #if 0
        NTD NEWTODO:
        need a new in the last n minutes command
        prints probes received in the last n minutes that have never been seen before
        if second arg is provided
        it could be a date range perhaps
        two options - first time seeing this ssiid
        or first time seeing address

        going through i can spoof a new ph and see when entries are created maybe? hmm
        how do i confirm that they are within our window
        could extend the size of our mac stack and have it be very large
        or could have a separate mac stack that keeps track of only new elements

        maybe this could take the form of a command that prints the most recent NEW elements
        similar to [r]ecent
        it will use a separate mac stack, yeah, i like that idea
        populated with just those entries that were new when added

            this is very easy to make note of - can just have an extra return value somewhere

            ALSO - to replicate behavior upon startup - both for regular mac stack and our new one
            that will keep track of new entries to never before seen addresses

            we can do our mac stack magic IFF the probe time we are adding is the absolute NEWEST yet
            this guarantees the same behavior as our vanilla

            might not be as clever as i thought, the order of insertion still matters
            what if we instert the newest element first? this is very unlikely

        ALSO - all mac stack behavior should be replicated upon startup

        can possibly go thru ph at each level and see when the newest probe is new enough to be included
        and print it

        alos wow i need the option to link two instances together
        they can share their storage/get a fuller picture of an area
        #endif
        /* [n]ote */
        case 'n':{
            uint8_t mac[6] = {0};
            if(!parse_maddr(args[1], mac)){
                puts("please enter a valid mac address");
                break;
            }
            if(add_note(ph, mac, args[2] ? strdup(args[2]) : NULL)){
                printf("added note to %s\n", args[1]);

                if(ph->offload_fn)dump_probe_history(ph, ph->offload_fn);
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
            p_mac_stack(ph, RECENTLY_RECVD, args[1] ? atoi(args[1]) : 1);
            break;
        case 'q':{
            }
            break;
        case 'z':
            p_mac_stack(ph, NEW_ADDRS, args[1] ? atoi(args[1]) : 1);
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
        /* [t]rack */
        // as of now, [t] provides all necessary functionality
        // t * -1 will disable all tracking
        // t * n will re-enable it 
        // the issue is that we can't set each to a specific value and
        // re-enable to that same value unless we use the global alerts_enabled
        case 't':{
            int n_secs, n_updated;
            if(!args[1]){
                puts("current alert thresholds:");
                printf("alerts enabled for %i users\n", p_alert_thresholds(ph, NULL, 0));
                break;
            }

            for(char* i = args[1]; *i; ++i)
                *i = toupper(*i);

            if(!args[2] || !parse_seconds(args[2], &n_secs)){
                p_alert_thresholds(ph, args[1], 1);
                break;
            }

            n_updated = set_alert_thresholds(ph, args[1], n_secs, 1);
            printf("updated alert threshold for %i addresses to %i\n", n_updated, n_secs);
            if(ph->offload_fn && n_updated)dump_probe_history(ph, ph->offload_fn);
            break;
        }
        /*
         * i still need a toggle command to broadly enable and one to disable alerts
         * i need commands to print the list of alerts enabled
         * think about the [t] and [k] commands - how could they be improved?
        */
        /* key_print */
        case 'k':
            /* when called without a filter, set_alert_thresholds()
             * just ensures that a key is set
             */
            set_alert_thresholds(ph, NULL, 0, 1);
            printf("alert tag: %i\n", ph->mq_key);
            break;
        /* [u]nique_xport_csv */
        /* [e]xport_csv */
        case 'u':
        case 'e':{
            int n_secs = 0, min_occurences = 0;
            FILE* fp;

            if(!args[1] || !parse_seconds(args[1], &n_secs) || n_secs <= 0){
                puts("please provide an interval in seconds, minutes, hours, or days");
                break;
            }

            if(args[2]){
                min_occurences = atoi(args[2]);
            }

            fp = args[3] ? fopen(args[3], "w") : stdout;

            if(!fp){
                puts("please provide a valid output file");
                break;
            }

            export_csv(ph, fp, n_secs, *cmd == 'u', args+4, min_occurences);

            if(fp != stdout)fclose(fp);
            break;
        }
        /* [o]ldest */
        case 'o':
            break;
    }
}

void repl(struct probe_history* ph){
    char* ln;
    #ifndef READLINE
    size_t sz = 0;
    int len;
    #endif

    while(1){
        #ifdef READLINE
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
        ln = NULL;
        len = getline(&ln, &sz, stdin);
        ln[--len] = 0;
        #endif

        handle_command(ln, ph);

        free(ln);
    }
}

void* safe_exit_thread(void* arg){
    struct probe_history* ph = arg;

    /* dumping here just in case - it's conceivable that
     * SIGINT is received during an insertion and safe_exit_thread
     * acquires locks before insert() can initiate its dump()
     * this is just being extra careful so as to not lose any data
     */
    if(ph->offload_fn){
        dump_probe_history(ph, ph->offload_fn);
        printf("ph dumped to %s... ", ph->offload_fn);
    }

    puts("waiting to safely exit");
    fflush(stdout);
    pthread_mutex_lock(&ph->lock);
    pthread_mutex_lock(&ph->file_storage_lock);
    printf("ph & fs locks acquired...");
    fflush(stdout);
    free_probe_history(ph);
    printf(" ph free()d...");
    fflush(stdout);
    raise(SIGKILL);

    return NULL;
}

/* when a SIGINT is received, we need to 
 * acquire locks in case anything important
 * is happening - most importantly because we don't want to lose
 * any data from our offloads. we can't acquire locks while in
 * the signal handler because no work is being done
 *
 * as a workaround, we spawn a safe exit thread that dumps one
 * final time before acquiring locks and freeing memory
 */
void wait_to_exit(int sig){
    pthread_t safe_exit_pth;

    (void)sig;
    signal(SIGINT, SIG_IGN);

    pthread_create(&safe_exit_pth, NULL, safe_exit_thread, __ph);

    return;
}

_Bool parse_args(int a, char** b, char** in_fn, char** out_fn, key_t* key){
    _Bool set_in = 0, set_out = 0, set_key = 0, version = 0;

    for(int i = 1; i < a; ++i){
        if(set_in){
            *in_fn = b[i];
            set_in = 0;
        }
        if(set_out){
            *out_fn = b[i];
            set_out = 0;
        }
        if(set_key){
            *key = atoi(b[i]);
            set_key = 0;
        }
        else if(*b[i] == '-'){
            switch(b[i][1]){
                case 'V':
                case 'v':
                    version = 1;
                    break;
                case 'I':
                case 'i':
                    set_in = 1;
                    break;
                case 'O':
                case 'o':
                    set_out = 1;
                    break;
                case 'K':
                case 'k':
                    set_key = 1;
                    break;
            }
        }
    }
    return version;
}

void p_info(){
    printf("PTP version %s "
    #ifdef READLINE
    "compiled with readline support"
    #endif
    "\n", PTP_VER_STR);
}

int main(int a, char** b){
    struct mqueue mq;
    struct probe_history ph;
    struct mq_ph_pair mqph = {.mq = &mq, .ph = &ph};
    key_t startup_key = -1;
    char* init_fn = NULL, * offload_fn = NULL;

    if(parse_args(a, b, &init_fn, &offload_fn, &startup_key)){
        p_info();
        return EXIT_SUCCESS;
    }

    init_mq(&mq);
    init_probe_history(&ph, offload_fn);
    ph.mq_key = startup_key;

    __ph = &ph;

    signal(SIGINT, wait_to_exit);

    if(init_fn)load_probe_history(&ph, init_fn);

    pthread_t pth[2];
    pthread_create(pth, NULL, collector_thread, &mq);
    pthread_create(pth+1, NULL, processor_thread, &mqph);

    repl(&ph);
}
