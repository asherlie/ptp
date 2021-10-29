#include <stdint.h>

struct probe_storage{
    char ssid[32];
    int n_probes, probe_cap;
    uint32_t* probe_times;

    struct probe_storage* next;
};

struct mac_addr{
    uint8_t addr[6];
    char* notes;
    struct probe_storage* probes;

    struct mac_addr* next;
};

struct probe_history{
    struct mac_addr* buckets[0xff*6];
};

void init_probe_history(struct probe_history* ph);

/*
 * hashing structure to store mac addresses
 * once we find the specific mac addr, we needd to keep track
 * of the recent probes and ssids
*/
