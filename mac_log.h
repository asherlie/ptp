#include <stdint.h>
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

    struct mac_addr* next;
};

struct probe_history{
    pthread_mutex_t lock;
    /* TODO: should we use a separate lock for each bucket?
     * is performance this big of an issue?
     */
    //pthread_mutex_t bucket_locks[(0xff*6)+1];
    struct mac_addr* buckets[(0xff*6)+1];
    int unique_addresses;
};

void init_probe_history(struct probe_history* ph);
struct mac_addr* insert_probe_request(struct probe_history* ph, uint8_t mac_addr[6], char ssid[32], time_t timestamp);
_Bool add_note(struct probe_history* ph, uint8_t addr[6], char* note);
void p_probes(struct probe_history* ph, _Bool verbose);
void free_probe_history(struct probe_history* ph);

struct mac_addr* lookup_mac(struct probe_history* ph, uint8_t* mac);

/*
 * hashing structure to store mac addresses
 * once we find the specific mac addr, we needd to keep track
 * of the recent probes and ssids
*/
