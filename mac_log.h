#include <stdint.h>

struct probe_history{
    char ssid[32];
    int n_probes, probe_cap;
    uint32_t* probe_times;
};

struct mac_addr{
    uint8_t addr[6];
};

/*
 * hashing structure to store mac addresses
 * once we find the specific mac addr, we needd to keep track
 * of the recent probes and ssids
*/
