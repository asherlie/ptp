#pragma once

#include <stdint.h>
#include <pthread.h>

#define ANSI_RED     "\x1b[31m"
#define ANSI_GREEN   "\x1b[32m"
#define ANSI_YELLOW  "\x1b[33m"
#define ANSI_BLUE    "\x1b[34m"
#define ANSI_MAGENTA "\x1b[35m"
#define ANSI_CYAN    "\x1b[36m"
#define ANSI_RESET   "\x1b[0m"

#if 0
TODO: all ints should have a declared size, not a problem for now but important to ensure
broader portability

once these changes are complete, there will be no more need for fingerprinting

time_t should not even be used anywhere but when strftime is called
we can use an int64_t until it is time to interpret


once this is all working i will write a version to read in our file and export it int64_t version
    the load function will remain untouched in this version

    i can make it so that the only difference is the dump() function
    which will create temp variables and cast from time_t to int64_t
    before writing to disk

    this should immediately fix the problem

    i can confirm that all is well by echoing p verbose output to a file
    and by comparing csvs
    if all is not IDENTICAL, something is wrong
    i need to be very careful so as not to lose data


    there is no reason in fact to even have time.h included in any file but mac_log.c where strftime is called
    and mq.c, where timestamp is generated
    stamp can immediately be converted to the appropriate size in mq.c

    int64_t stamp = time(NULL);

    i will also need to update mq.{c,h} to get rid of the time_t

i will then re-dump and restart my rpi collection using the new 64_t version with converted files
#endif

struct probe_storage{
    char ssid[32];
    int n_probes, probe_cap;
    int64_t* probe_times;

    struct probe_storage* next;
};

struct mac_addr{
    uint8_t addr[6];
    char* notes;
    struct probe_storage* probes;

    int mac_stack_idx;

    struct mac_addr* next;
};

struct mac_stack{
    pthread_mutex_t lock;
    int n_most_recent;
    int ins_idx;
    struct mac_addr** addrs;
};

struct probe_history{
    pthread_mutex_t lock, file_storage_lock;
    /* TODO: should we use a separate lock for each bucket?
     * is performance this big of an issue?
     */
    //pthread_mutex_t bucket_locks[(0xff*6)+1];
    struct mac_addr* buckets[(0xff*6)+1];

    struct mac_stack ms;

    int unique_addresses, total_probes;

    int offload_after;
    char* offload_fn;
};

void init_probe_history(struct probe_history* ph, char* fn);

struct probe_storage* insert_probe_request(struct probe_history* ph, uint8_t mac_addr[6],
                                           char ssid[32], int64_t timestamp, _Bool from_reload);

struct probe_storage* insert_probe_request_nolock(struct probe_history* ph, uint8_t mac_addr[6],
                                           char ssid[32], int64_t timestamp, _Bool from_reload);

_Bool add_note(struct probe_history* ph, uint8_t addr[6], char* note);
_Bool add_note_nolock(struct probe_history* ph, uint8_t addr[6], char* note);

void p_probes(struct probe_history* ph, _Bool verbose, char* note, char* ssid, uint8_t* mac);
void p_most_recent(struct probe_history* ph, int n);
void free_probe_history(struct probe_history* ph);

struct mac_addr* lookup_mac(struct probe_history* ph, uint8_t* mac);

/*
 * hashing structure to store mac addresses
 * once we find the specific mac addr, we need to keep track
 * of the recent probes and ssids
*/
void init_mac_stack(struct mac_stack* ms, int n_most_recent);
int64_t oldest_probe(struct probe_history* ph);
