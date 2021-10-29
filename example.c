#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "mac_log.h"

void gen_rand_mac_addr(uint8_t dest[6]){
    int x = random();

    dest[0] = 0x0a;
    dest[1] = 0x0a;
    memcpy(dest+2, &x, sizeof(int));
}

int main(){
    struct probe_history ph;
    uint8_t addr[] = {0x1f, 0x99, 0x84, 0xa4, 0x19, 0x23};
    char ssid[32] = "asher's network";

    srand(time(NULL));
    init_probe_history(&ph);

    insert_probe_request(&ph, addr, ssid);
    p_probes(&ph, 1);

    return 0;
    insert_probe_request(&ph, addr, ssid);
    for(int i = 0; i < 1301; ++i)
        insert_probe_request(&ph, addr, ssid);
    ssid[0] = 'b';
    /*addr[3] = 13;*/
    insert_probe_request(&ph, addr, ssid);
    ssid[0] = 'c';

    for(int i = 0; i < 100000; ++i){
        gen_rand_mac_addr(addr);
        insert_probe_request(&ph, addr, ssid);
    }

    p_probes(&ph, 0);
    printf("%i unique addresses\n", ph.unique_addresses);
    free_probe_history(&ph);

    return 0;
}
