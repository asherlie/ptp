#include "mac_log.h"

_Bool alert_eligible(struct probe_history* ph, struct mac_addr* ma);
int set_alert_thresholds(struct probe_history* ph, char* filter, int threshold);
int p_alert_thresholds(struct probe_history* ph, char* filter, _Bool show_unset);
_Bool add_alert(struct probe_history* ph, struct mac_addr* ma);
