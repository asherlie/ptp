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

    /* so that we don't offload after each offload_after insertions before
     * restoring is complete
     */
    _Bool restore_complete;
    int offload_after;
    char* offload_fn;
};

void init_probe_history(struct probe_history* ph, char* fn);
struct probe_storage* insert_probe_request(struct probe_history* ph, uint8_t mac_addr[6], char ssid[32], time_t timestamp);
_Bool add_note(struct probe_history* ph, uint8_t addr[6], char* note);
void p_probes(struct probe_history* ph, _Bool verbose, char* note, char* ssid, uint8_t* mac);
void p_most_recent(struct probe_history* ph, int n);
void free_probe_history(struct probe_history* ph);

struct mac_addr* lookup_mac(struct probe_history* ph, uint8_t* mac);

/*
 * hashing structure to store mac addresses
 * once we find the specific mac addr, we needd to keep track
 * of the recent probes and ssids
*/
void init_mac_stack(struct mac_stack* ms, int n_most_recent);
void insert_mac_stack_(struct mac_stack* ms, struct mac_addr* ma);
