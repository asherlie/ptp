#include <stdint.h>
#include <pthread.h>

struct mq_entry{
    int64_t timestamp;
    uint8_t* buf;
    int len;

    struct mq_entry* next;
};

struct mqueue{
    pthread_cond_t cond;
    pthread_mutex_t lock;
    struct mq_entry* first, * last;
};

void init_mq(struct mqueue* mq);
void free_mq(struct mqueue* mq);
void insert_mq(struct mqueue* mq, uint8_t* packet, int len);
struct mq_entry* pop_mq(struct mqueue* mq);
