#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "mq.h"
#include "mac_log.h"

void gen_rand_mac_addr(uint8_t dest[6]){
    int x = random(), y = random();

    memcpy(dest, &x, sizeof(int));
    memcpy(dest+sizeof(int), &y, 6-sizeof(int));
}

void test_mq(){
    struct mqueue mq;
    uint8_t packet[1000];
    init_mq(&mq);
    insert_mq(&mq, packet, 1000);
    pop_mq(&mq);
}

int main(int a, char** b){
    test_mq();
    return 0;
    (void)b;
    struct probe_history ph;
    uint8_t addr[6];
    char ssid[32] = "one_direction";

    srand(time(NULL));

    init_probe_history(&ph);

    gen_rand_mac_addr(addr);

    insert_probe_request(&ph, addr, ssid, 0);
    add_note(&ph, addr, strdup("hi mannn"));
    insert_probe_request(&ph, addr, ssid, 0);
    insert_probe_request(&ph, addr, ssid, 0);
    uint8_t tmp = addr[4];
    addr[4] = addr[5];
    addr[5] = tmp;
    insert_probe_request(&ph, addr, ssid, 0);
    add_note(&ph, addr, strdup("second note"));

    p_probes(&ph, a > 1);
    printf("there are %i unique addresses\n", ph.unique_addresses);

    free_probe_history(&ph);

    return 0;
}
