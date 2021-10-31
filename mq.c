#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#include "mq.h"

void init_mq(struct mqueue* mq){
    mq->first = mq->last = NULL;
    pthread_mutex_init(&mq->lock, NULL);
}

void insert_mq(struct mqueue* mq, uint8_t* packet, int len){
    struct mq_entry* mqe = malloc(sizeof(struct mq_entry));
    mqe->timestamp = time(NULL);
    mqe->buf = packet;
    mqe->len = len;
    mqe->next = NULL;

    pthread_mutex_lock(&mq->lock);
    if(!mq->first){
        mq->first = mq->last = mqe;
    }
    else mq->last->next = mqe;
    pthread_mutex_unlock(&mq->lock);
}

struct mq_entry* pop_mq(struct mqueue* mq){
    struct mq_entry* ret;
    pthread_mutex_lock(&mq->lock);
    ret = mq->first;
    mq->first = mq->first->next;
    if(!ret)mq->last = NULL;
    pthread_mutex_unlock(&mq->lock);
    return ret;
}
