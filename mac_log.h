#pragma once

#include <stdint.h>
#include <pthread.h>
#include <time.h>

struct probe_storage{
    char ssid[32];
    int n_probes, probe_cap;
    time_t* probe_times;

    struct probe_storage* next;
};

struct mac_addr{
    uint8_t addr[6];
    char* notes;
    struct probe_storage* probes;

    #if 0
    /* to avoid iterating through n_most_recent with each insertion */
    this should be an integer for position in line - but damn, this is a linked freaking list
    i could also keep a struct mac_stack_entry*[] with a list of mac stack entries
    ridiculous LOL
    this should be aa
    
    nvm - this is what i should do - scrap the linked list. this should be an array
    arr[20]
    and keep a pointer to the first element
    and the last element
    or first element and its index
    when iterating, start from first, go to last, go from base pointer to first 
    if we have come across a mac address that has the in_mac_stack marked as 1
    in_mac_stack keeps track of the pointer
    i can memcpy
    #endif



    _Bool in_mac_stack;

    struct mac_addr* next;
};

/* used to store n most recently received struct mac_addrs */
struct mac_stack_entry{
    struct mac_addr* m_addr;
    struct mac_stack_entry* next, * prev;
};

struct mac_stack{
    pthread_mutex_t lock;
    int n_most_recent, n_stored;
    struct mac_stack_entry* first, * last;
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
};

void init_probe_history(struct probe_history* ph);
struct probe_storage* insert_probe_request(struct probe_history* ph, uint8_t mac_addr[6], char ssid[32], time_t timestamp);
_Bool add_note(struct probe_history* ph, uint8_t addr[6], char* note);
void p_probes(struct probe_history* ph, _Bool verbose, char* ssid, uint8_t* mac);
void p_most_recent(struct probe_history* ph, int n);
void free_probe_history(struct probe_history* ph);

struct mac_addr* lookup_mac(struct probe_history* ph, uint8_t* mac);

/*
 * hashing structure to store mac addresses
 * once we find the specific mac addr, we needd to keep track
 * of the recent probes and ssids
*/
