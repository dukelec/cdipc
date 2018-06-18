/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <duke@dukelec.com>
 */

#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>

#include "cdipc.h"

static void cdipc_get_full_path(char *fpath, const char *rpath)
{
    char *base_path = getenv("CDIPC_BASE_PATH");
    if (base_path == NULL)
        base_path = "/tmp/cdipc/";
    snprintf(fpath, PATH_MAX, "%s%s", base_path, rpath);
}


int cdipc_create(const char *rpath, cdipc_type_t type,
        int pub_amount, int sub_amount,
        int nd_amount, size_t max_dat_len)
{
    int i, r;
    char fpath[PATH_MAX];
    cdipc_ch_t _ch;
    cdipc_ch_t *ch = &_ch;

    if (!pub_amount || !sub_amount || !nd_amount || !max_dat_len) {
        df_error("zero arguments detected\n");
        return -1;
    }
    if (type == CDIPC_SERVICE && sub_amount != 1) {
        df_error("sub_amount must be 1 for service\n");
        return -1;
    }

    memset(ch, 0, sizeof(cdipc_ch_t));
    ch->map_len = sizeof(cdipc_hdr_t) +
            sizeof(cdipc_pub_t) * pub_amount +
            sizeof(cdipc_sub_t) * sub_amount +
            (sizeof(cdipc_nd_t) + max_dat_len) * nd_amount;
    strncpy(ch->rpath, rpath, PATH_MAX);
    cdipc_get_full_path(fpath, rpath);

    ch->fd = shm_open(fpath, O_CREAT | O_EXCL | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG);
    if (ch->fd < 0) {
        df_error("shm_open, ret code: %d\n", ch->fd);
        return ch->fd;
    }

    if (ftruncate(ch->fd, ch->map_len) == -1) {
        df_error("ftruncate to size %ld\n", ch->map_len);
        return -1;
    }

    ch->hdr = (cdipc_hdr_t*) mmap(NULL, ch->map_len,
            PROT_READ | PROT_WRITE, MAP_SHARED, ch->fd, 0);
    if (ch->hdr == MAP_FAILED) {
        df_error("mmap\n");
        return -1;
    }

    memset(ch->hdr, 0, sizeof(cdipc_hdr_t));
    ch->hdr->type = type;
    ch->hdr->pub_amount = pub_amount;
    ch->hdr->sub_amount = sub_amount;
    ch->hdr->nd_amount = nd_amount;
    ch->hdr->max_dat_len = max_dat_len;

    pthread_mutexattr_t mutexattr;
    if ((r = pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED))) {
        df_error("pthread_mutexattr_setpshared\n");
        return -1;
    }
#ifdef HAVE_MUTEX_PRIORITY_INHERIT
    if ((r = pthread_mutexattr_setprotocol(&mutexattr, PTHREAD_PRIO_INHERIT))) {
        df_error("pthread_mutexattr_setprotocol");
        return -1;
    }
#endif
#ifdef HAVE_MUTEX_ROBUST
    if ((r = pthread_mutexattr_setrobust(&mutexattr, PTHREAD_MUTEX_ROBUST))) {
        df_error("pthread_mutexattr_setrobust");
        return -1;
    }
#endif
#if defined (HAVE_MUTEX_ERROR_CHECK) && defined (DEBUG)
    if ((r = pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_ERRORCHECK))) {
        df_error("pthread_mutexattr_settype");
        return -1;
    }
#endif
    if ((r = pthread_mutex_init(&ch->hdr->mutex, &mutexattr))) {
        df_error("pthread_mutex_init\n");
        return -1;
    }
    if ((r = pthread_mutexattr_destroy(&mutexattr))) {
        df_error("pthread_mutexattr_destroy\n");
        return -1;
    }

    pthread_condattr_t condattr;
    if ((r = pthread_condattr_setpshared(&condattr, PTHREAD_PROCESS_SHARED))) {
        df_error("pthread_condattr_setpshared\n");
        return -1;
    }
    if ((r = pthread_cond_init(&ch->hdr->cond, &condattr))) {
        df_error("pthread_cond_init\n");
        return -1;
    }
    if ((r = pthread_condattr_destroy(&condattr))) {
        df_error("pthread_condattr_destroy\n");
        return -1;
    }

    ch->pubs = (void *) ch->hdr + sizeof(cdipc_hdr_t);
    ch->subs = (void *) ch->pubs + sizeof(cdipc_pub_t) * pub_amount;
    cdipc_nd_t *nds = (void *) ch->subs + sizeof(cdipc_sub_t) * sub_amount;

    for (i = 0; i < pub_amount; i++) {
        cdipc_pub_t *pub = ch->pubs + sizeof(cdipc_pub_t) * i;
        memset(pub, 0, sizeof(cdipc_pub_t));
        pub->id = i;
    }
    for (i = 0; i < sub_amount; i++) {
        cdipc_sub_t *sub = ch->subs + sizeof(cdipc_sub_t) * i;
        memset(sub, 0, sizeof(cdipc_sub_t));
        sub->id = i;
    }
    for (i = 0; i < nd_amount; i++) {
        cdipc_nd_t *nd = nds + (sizeof(cdipc_nd_t) + max_dat_len) * i;
        memset(nd, 0, sizeof(cdipc_nd_t));
        nd->id = i;
        list_put(&ch->hdr->free, &nd->node);
    }

    ch->hdr->magic = CDIPC_MAGIC_NUM;
    return cdipc_close(ch);
}

int cdipc_unlink(const char *rpath)
{
    int r;
    char fpath[PATH_MAX];
    cdipc_get_full_path(fpath, rpath);

    if ((r = shm_unlink(fpath))) {
        df_error("shm_unlink\n");
        return -1;
    }
    return 0;
}


int cdipc_open(cdipc_ch_t *ch, const char *rpath,
        cdipc_role_t role, int id)
{
    char fpath[PATH_MAX];

    memset(ch, 0, sizeof(cdipc_ch_t));
    strncpy(ch->rpath, rpath, PATH_MAX);
    cdipc_get_full_path(fpath, rpath);


    ch->fd = shm_open(fpath, O_RDWR, S_IRWXU | S_IRWXG);
    if (ch->fd < 0) {
        df_error("shm_open, ret code: %d\n", ch->fd);
        return ch->fd;
    }

    ch->hdr = (cdipc_hdr_t*) mmap(NULL, sizeof(cdipc_hdr_t),
            PROT_READ | PROT_WRITE, MAP_SHARED, ch->fd, 0);
    if (ch->hdr == MAP_FAILED) {
        df_error("mmap\n");
        return -1;
    }
    if (ch->hdr->magic != CDIPC_MAGIC_NUM) {
        df_error("wrong magic num: %08x, expect: %08x\n",
                ch->hdr->magic, CDIPC_MAGIC_NUM);
        return -1;
    }

    ch->map_len = sizeof(cdipc_hdr_t) +
            sizeof(cdipc_pub_t) * ch->hdr->pub_amount +
            sizeof(cdipc_sub_t) * ch->hdr->sub_amount +
            (sizeof(cdipc_nd_t) + ch->hdr->max_dat_len) * ch->hdr->nd_amount;

    if (-1 == munmap(ch->hdr, sizeof(cdipc_hdr_t))) {
        df_error("munmap\n");
        return -1;
    }

    ch->hdr = (cdipc_hdr_t*) mmap(NULL, ch->map_len,
            PROT_READ | PROT_WRITE, MAP_SHARED, ch->fd, 0);
    if (ch->hdr == MAP_FAILED) {
        df_error("re-mmap\n");
        return -1;
    }

    ch->pubs = (void *) ch->hdr + sizeof(cdipc_hdr_t);
    ch->subs = (void *) ch->pubs + sizeof(cdipc_pub_t) * ch->hdr->pub_amount;
    ch->role = role;

    if (role == CDIPC_PUB) {
        ch->pub = ch->pubs + id;
    } else if (role == CDIPC_SUB) {
        ch->sub = ch->subs + id;
    }

    return 0;
}

int cdipc_close(cdipc_ch_t *ch)
{
    if (munmap(ch->hdr, ch->map_len)) {
        df_error("munmap\n");
        return -1;
    }
    ch->hdr = NULL;

    if (close(ch->fd)) {
        df_error("close fd\n");
        return -1;
    }
    ch->fd = -1;
    return 0;
}


// for pub:

int cdipc_alloc(cdipc_ch_t *ch, const struct timespec *abstime)
{
    int r = 0;
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_pub_t *pub = ch->pub;
    assert(ch->role == CDIPC_PUB);

    if (pub->cur) {
        df_warn("aready allocated\n");
        pub->cur->owner = pub->id;
        return 0;
    }
    if (hdr->type == CDIPC_SERVICE && pub->ans) {
        df_warn("unexpected ans\n");
        pub->cur = pub->ans;
        pub->ans = NULL;
        pub->cur->owner = pub->id;
        return 0;
    }

    pthread_mutex_lock(&hdr->mutex);

    while (!(pub->cur = list_get_entry(&hdr->free, cdipc_nd_t))) {
        r = pthread_cond_timedwait(&hdr->cond, &hdr->mutex, abstime);
        if (r == ETIMEDOUT) {
            break;
        } else if (r != 0) {
            df_error("cond_timedwait, ret: %d\n", r);
            break;
        }
    }
    if (pub->cur)
        pub->cur->owner = pub->id;
    pthread_mutex_unlock(&hdr->mutex);
    return r;
}

int cdipc_put(cdipc_ch_t *ch, const struct timespec *abstime)
{
    int i, r = 0;
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_pub_t *pub = ch->pub;
    assert(ch->role == CDIPC_PUB);

    if (!pub->cur) {
        df_error("cur empty\n");
        return -1;
    }

    pthread_mutex_lock(&hdr->mutex);

    while (true) {
        bool need_wait = false;
        for (i = 0; i < hdr->sub_amount; i++) {
            cdipc_sub_t *sub = ch->subs + i;
            if (sub->need_wait && sub->pend.len == sub->max_len) {
                need_wait = true;
                break;
            }
        }
        if (!need_wait)
            break;

        r = pthread_cond_timedwait(&hdr->cond, &hdr->mutex, abstime);
        if (r == ETIMEDOUT) {
            break;
        } else if (r != 0) {
            df_error("cond_timedwait, ret: %d\n", r);
            break;
        }
    }

    if (r == 0) {
        pub->cur->ref = 0;
        for (i = 0; i < hdr->sub_amount; i++) {
            cdipc_sub_t *sub = ch->subs + i;
            if (sub->pend.len == sub->max_len) {
                cdipc_nd_t *nd = list_get_entry(&sub->pend, cdipc_nd_t);
                nd->owner = -1;
                list_put(&hdr->free, &nd->node);
            }
            if (sub->max_len != 0) {
                list_put(&sub->pend, &pub->cur->node);
                pub->cur->ref++;
            }
        }
        pub->cur = NULL;
    }

    pthread_mutex_unlock(&hdr->mutex);

    return r;
}

// for sub:

int cdipc_get(cdipc_ch_t *ch, const struct timespec *abstime)
{
    int i, r = 0;
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_sub_t *sub = ch->sub;
    assert(ch->role == CDIPC_SUB);

    pthread_mutex_lock(&hdr->mutex);

pick_node:
    while (!(sub->cur = list_get_entry(&sub->pend, cdipc_nd_t))) {
        r = pthread_cond_timedwait(&hdr->cond, &hdr->mutex, abstime);
        if (r == ETIMEDOUT) {
            break;
        } else if (r != 0) {
            df_error("cond_timedwait, ret: %d\n", r);
            break;
        }
    }

    if (r == 0 && sub->cur->owner < 0) {
        if (--sub->cur->ref <= 0) {
            list_put(&hdr->free, &sub->cur->node);
        }
        sub->cur = NULL;
        df_debug("avoid cancelled node\n");
        goto pick_node;
    }

    pthread_mutex_unlock(&hdr->mutex);
    return r;
}

int cdipc_response(cdipc_ch_t *ch)
{
    int i, r = 0;
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_sub_t *sub = ch->sub;
    assert(ch->role == CDIPC_SUB && hdr->type == CDIPC_SERVICE);

    if (!sub->cur) {
        df_error("cur empty\n");
        return -1;
    }

    pthread_mutex_lock(&hdr->mutex);

    if (sub->cur->owner < 0) {
        df_debug("avoid cancelled node\n");
        if (--sub->cur->ref != 0)
            df_warn("ref not zero: %d\n", sub->cur->ref);
        list_put(&hdr->free, &sub->cur->node);
        sub->cur = NULL;
    } else {
        cdipc_pub_t *pub = ch->pubs + sub->cur->owner;
        if (pub->ans) {
            df_error("pub->ans not empty\n");
            r = -1;
        } else {
            pub->ans = sub->cur;
            sub->cur = NULL;
        }
    }

    pthread_mutex_unlock(&hdr->mutex);
    return r;
}

// for both:

int cdipc_release(cdipc_ch_t *ch)
{
    cdipc_hdr_t *hdr = ch->hdr;

    if (ch->role == CDIPC_SUB) {
        cdipc_sub_t *sub = ch->sub;
        assert(hdr->type == CDIPC_TOPIC);
        if (!sub->cur) {
            df_error("sub->cur empty\n");
            return -1;
        }
        pthread_mutex_lock(&hdr->mutex);
        if (--sub->cur->ref <= 0) {
            list_put(&hdr->free, &sub->cur->node);
        }
        sub->cur = NULL;
        pthread_mutex_unlock(&hdr->mutex);

    } else if (ch->role == CDIPC_PUB) {
        cdipc_pub_t *pub = ch->pub;
        assert(hdr->type == CDIPC_SERVICE);
        if (!pub->ans) {
            df_error("pub->ans empty\n");
            return -1;
        }
        pthread_mutex_lock(&hdr->mutex);
        pub->ans->owner = -1;
        list_put(&hdr->free, &pub->ans->node);
        pub->ans = NULL;
        pthread_mutex_unlock(&hdr->mutex);
    }

    return 0;
}
