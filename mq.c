#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#include "mq.h"

void init_mq(struct mqueue* mq){
    mq->first = mq->last = NULL;
    pthread_mutex_init(&mq->lock, NULL);
    pthread_cond_init(&mq->cond, NULL);
}

void free_mq(struct mqueue* mq){
    pthread_mutex_destroy(&mq->lock);
    pthread_cond_destroy(&mq->cond);
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

    pthread_cond_signal(&mq->cond);

    pthread_mutex_unlock(&mq->lock);
}

_Bool mq_is_empty(struct mqueue* mq){
    return mq->first;
}

struct mq_entry* pop_mq(struct mqueue* mq){
    struct mq_entry* ret = NULL;
    pthread_mutex_t tmp_lck;
    pthread_mutex_init(&tmp_lck, NULL);

    while(!ret){
        pthread_mutex_lock(&tmp_lck);
        /* mq is non empty no need to sleep
         * even if another thread gets to mq->head first,
         * we'll just iterate
         */
        if(!mq_is_empty(mq))pthread_cond_wait(&mq->cond, &tmp_lck);
        pthread_mutex_unlock(&tmp_lck);
        pthread_mutex_lock(&mq->lock);
        ret = mq->first;
        if(ret)mq->first = mq->first->next;
        else mq->last = NULL;
        pthread_mutex_unlock(&mq->lock);
    }
    return ret;
}
