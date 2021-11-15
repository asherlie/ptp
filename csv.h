#include "mac_log.h"

#define STR_HASH_MAX 233226


/* TODO:
 * should i rename this file and have this generated and added to throughout regular usage?
 * would allow a command to print unique ssids, n_uniqe, which we could keep track of easily
 * and very fast csv generation
*/
struct soh_entry{
    /* each ssid has an associated time interval bucket */
    int* buckets;
    /*struct mac_addr* ma;*/
    char* ssid;
};

struct ssid_overview_hash{
    int second_interval, n_buckets;
    struct soh_entry** se;
};

//void init_soh(struct ssid_overview_hash* soh, int n_buckets, int second_interval);
//void insert_soh(struct ssid_overview_hash* soh, struct probe_storage* ps, time_t oldest);
struct ssid_overview_hash* gen_ssid_overview(struct probe_history* ph, int second_interval);
void free_soh(struct ssid_overview_hash* soh);
void filter_soh(struct ssid_overview_hash* soh, char** filters);
