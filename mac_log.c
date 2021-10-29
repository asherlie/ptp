#include <string.h>

#include "mac_log.h"

void init_probe_history(struct probe_history* ph){
    memset(ph->buckets, 0, sizeof(struct mac_addr*)*(0xff*6));
}

int main(){
    return 0;
}
