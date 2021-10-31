#include <stdint.h>
#include <pthread.h>

struct mq_entry{
    uint8_t* buf;
    int len;

    struct mq_entry* next;
};

struct mqueue{
    pthread_mutex_t lock;
    struct mq_entry* first, * last;
};
