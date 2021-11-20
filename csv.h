#include "mac_log.h"

void export_csv(struct probe_history* ph, FILE* fp, int second_interval, _Bool unique_macs, char** filters, int occurence_floor);
