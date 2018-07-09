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

#include "cd_utils.h"
#include "cd_debug.h"
#include "rlist.h"
#include "cdipc.h"

int cdipc_create(const char *name, cdipc_type_t type,
        int max_pub, int max_sub, int max_nd, size_t max_len)
{
    int i, r;
    cdipc_ch_t _ch;
    cdipc_ch_t *ch = &_ch;

    if (!max_pub || !max_sub || !max_nd || !max_len) {
        dnf_error(name, "zero arguments detected\n");
        return -1;
    }

    memset(ch, 0, sizeof(cdipc_ch_t));
    ch->map_len = sizeof(cdipc_hdr_t) +
            sizeof(cdipc_pub_t) * max_pub +
            sizeof(cdipc_sub_t) * max_sub +
            sizeof(cdipc_wp_t) * max_nd * max_sub +
            (sizeof(cdipc_nd_t) + max_len) * max_nd;
    strncpy(ch->name, name, NAME_MAX);

    ch->fd = shm_open(name, O_CREAT | O_EXCL | O_RDWR | O_TRUNC, S_IRWXU | S_IRWXG);
    if (ch->fd < 0) {
        dnf_error(ch->name, "shm_open: %s, ret code: %d\n", name, ch->fd);
        return ch->fd;
    }

    if (ftruncate(ch->fd, ch->map_len) == -1) {
        dnf_error(ch->name, "ftruncate to size %ld\n", ch->map_len);
        goto exit_free_fd;
    }

    ch->hdr = (cdipc_hdr_t*) mmap(NULL, ch->map_len,
            PROT_READ | PROT_WRITE, MAP_SHARED, ch->fd, 0);
    if (ch->hdr == MAP_FAILED) {
        dnf_error(ch->name, "mmap\n");
        goto exit_free_fd;
    }

    memset(ch->hdr, 0, sizeof(cdipc_hdr_t));
    ch->hdr->type = type;
    ch->hdr->max_pub = max_pub;
    ch->hdr->max_sub = max_sub;
    ch->hdr->max_nd = max_nd;
    ch->hdr->max_len = max_len;

    pthread_mutexattr_t mutexattr;
    if ((r = pthread_mutexattr_init(&mutexattr))) {
        dnf_error(ch->name, "pthread_mutexattr_init\n");
        goto exit_free_mmap;
    }
    if ((r = pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED))) {
        dnf_error(ch->name, "pthread_mutexattr_setpshared\n");
        goto exit_free_mmap;
    }
#ifdef HAVE_MUTEX_PRIORITY_INHERIT
    if ((r = pthread_mutexattr_setprotocol(&mutexattr, PTHREAD_PRIO_INHERIT))) {
        dnf_error(ch->name, "pthread_mutexattr_setprotocol");
        goto exit_free_mmap;
    }
#endif
#ifdef HAVE_MUTEX_ROBUST
    if ((r = pthread_mutexattr_setrobust(&mutexattr, PTHREAD_MUTEX_ROBUST))) {
        dnf_error(ch->name, "pthread_mutexattr_setrobust");
        goto exit_free_mmap;
    }
#endif
#if defined (HAVE_MUTEX_ERROR_CHECK) && defined (DEBUG)
    if ((r = pthread_mutexattr_settype(&mutexattr, PTHREAD_MUTEX_ERRORCHECK))) {
        dnf_error(ch->name, "pthread_mutexattr_settype");
        goto exit_free_mmap;
    }
#endif
    if ((r = pthread_mutex_init(&ch->hdr->mutex, &mutexattr))) {
        dnf_error(ch->name, "pthread_mutex_init, ret: %d\n", r);
        goto exit_free_mmap;
    }
    if ((r = pthread_mutexattr_destroy(&mutexattr))) {
        dnf_error(ch->name, "pthread_mutexattr_destroy\n");
        goto exit_free_mmap;
    }

    pthread_condattr_t condattr;
    if ((r = pthread_condattr_init(&condattr))) {
        dnf_error(ch->name, "pthread_condattr_init\n");
        goto exit_free_mmap;
    }
    if ((r = pthread_condattr_setpshared(&condattr, PTHREAD_PROCESS_SHARED))) {
        dnf_error(ch->name, "pthread_condattr_setpshared\n");
        goto exit_free_mmap;
    }
    if ((r = pthread_condattr_setclock(&condattr, CLOCK_MONOTONIC))) {
        dnf_error(ch->name, "pthread_condattr_setclock\n");
        goto exit_free_mmap;
    }
    if ((r = pthread_cond_init(&ch->hdr->cond, &condattr))) {
        dnf_error(ch->name, "pthread_cond_init\n");
        goto exit_free_mmap;
    }
    if ((r = pthread_condattr_destroy(&condattr))) {
        dnf_error(ch->name, "pthread_condattr_destroy\n");
        goto exit_free_mmap;
    }

    ch->pubs = (void *)ch->hdr + sizeof(cdipc_hdr_t);
    ch->subs = (void *)ch->pubs + sizeof(cdipc_pub_t) * max_pub;
    cdipc_wp_t *wps = (void *)ch->subs + sizeof(cdipc_sub_t) * max_sub;
    cdipc_nd_t *nds = (void *)wps + sizeof(cdipc_wp_t) * max_nd * max_sub;

    for (i = 0; i < max_pub; i++) {
        cdipc_pub_t *pub = ch->pubs + i;
        memset(pub, 0, sizeof(cdipc_pub_t));
        pub->id = i;
    }
    for (i = 0; i < max_sub; i++) {
        cdipc_sub_t *sub = ch->subs + i;
        memset(sub, 0, sizeof(cdipc_sub_t));
        sub->id = i;
    }
    for (i = 0; i < max_nd * max_sub; i++) {
        cdipc_wp_t *wp = wps + i;
        memset(wp, 0, sizeof(cdipc_wp_t));
        rlist_put(ch->hdr, &ch->hdr->free_wp, &wp->node);
    }
    for (i = 0; i < max_nd; i++) {
        cdipc_nd_t *nd = (void *)nds + (sizeof(cdipc_nd_t) + max_len) * i;
        memset(nd, 0, sizeof(cdipc_nd_t));
        nd->id = i;
        nd->pub_id = -1;
        nd->pub_id_bk = -1;
        rlist_put(ch->hdr, &ch->hdr->free, &nd->node);
    }

    ch->hdr->magic = CDIPC_MAGIC_NUM;
    return cdipc_close(ch);

exit_free_mmap:
    munmap(ch->hdr, ch->map_len);
exit_free_fd:
    close(ch->fd);
    cdipc_unlink(name);
    return -1;
}

int cdipc_unlink(const char *name)
{
    int r;

    if ((r = shm_unlink(name))) {
        dnf_error(name, "shm_unlink\n");
        return -1;
    }
    return 0;
}


int cdipc_open(cdipc_ch_t *ch, const char *name,
        cdipc_role_t role, int id)
{
    memset(ch, 0, sizeof(cdipc_ch_t));
    strncpy(ch->name, name, NAME_MAX);

    ch->fd = shm_open(name, O_RDWR, S_IRWXU | S_IRWXG);
    if (ch->fd < 0) {
        dnf_error(ch->name, "shm_open, ret code: %d\n", ch->fd);
        return ch->fd;
    }

    ch->hdr = (cdipc_hdr_t*) mmap(NULL, sizeof(cdipc_hdr_t),
            PROT_READ | PROT_WRITE, MAP_SHARED, ch->fd, 0);
    if (ch->hdr == MAP_FAILED) {
        dnf_error(ch->name, "mmap\n");
        return -1;
    }
    if (ch->hdr->magic != CDIPC_MAGIC_NUM) {
        dnf_error(ch->name, "wrong magic num: %08x, expect: %08x\n",
                ch->hdr->magic, CDIPC_MAGIC_NUM);
        munmap(ch->hdr, sizeof(cdipc_hdr_t));
        return -1;
    }

    ch->map_len = sizeof(cdipc_hdr_t) +
            sizeof(cdipc_pub_t) * ch->hdr->max_pub +
            sizeof(cdipc_sub_t) * ch->hdr->max_sub +
            sizeof(cdipc_wp_t) * ch->hdr->max_nd * ch->hdr->max_sub +
            (sizeof(cdipc_nd_t) + ch->hdr->max_len) * ch->hdr->max_nd;

    if (-1 == munmap(ch->hdr, sizeof(cdipc_hdr_t))) {
        dnf_error(ch->name, "munmap\n");
        return -1;
    }

    ch->hdr = (cdipc_hdr_t*) mmap(NULL, ch->map_len,
            PROT_READ | PROT_WRITE, MAP_SHARED, ch->fd, 0);
    if (ch->hdr == MAP_FAILED) {
        dnf_error(ch->name, "re-mmap\n");
        return -1;
    }

    ch->pubs = (void *)ch->hdr + sizeof(cdipc_hdr_t);
    ch->subs = (void *)ch->pubs + sizeof(cdipc_pub_t) * ch->hdr->max_pub;
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
        dnf_error(ch->name, "munmap\n");
        return -1;
    }
    ch->hdr = NULL;

    if (close(ch->fd)) {
        dnf_error(ch->name, "close fd\n");
        return -1;
    }
    ch->fd = -1;
    return 0;
}


// for pub:

cdipc_nd_t *cdipc_pub_alloc(cdipc_ch_t *ch, const struct timespec *abstime)
{
    int r = 0;
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_pub_t *pub = ch->pub;
    cdipc_nd_t *nd = NULL;
    assert(ch->role == CDIPC_PUB);

    if (pthread_mutex_lock(&hdr->mutex)) {
        dnf_error(ch->name, "mutex_lock\n");
        return NULL;
    }
    while (!(nd = rlist_get_entry(hdr, &hdr->free, cdipc_nd_t))) {
        if (abstime) {
            r = pthread_cond_timedwait(&hdr->cond, &hdr->mutex, abstime);
        } else {
            r = pthread_cond_wait(&hdr->cond, &hdr->mutex);
        }
        if (r == ETIMEDOUT) {
            break;
        } else if (r != 0) {
            dnf_error(ch->name, "cond_timedwait, ret: %d\n", r);
            break;
        }
    }
    if (nd) {
        nd->abort = false;
        nd->pub_id = pub->id;
        nd->pub_id_bk = pub->id;
        nd->sub_ref = 0;
    }
    pthread_mutex_unlock(&hdr->mutex);
    return nd;
}

int cdipc_pub_put(cdipc_ch_t *ch, cdipc_nd_t *nd,
        const struct timespec *abstime)
{
    int i, r = 0;
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_pub_t *pub = ch->pub;
    assert(ch->role == CDIPC_PUB);

    if (pthread_mutex_lock(&hdr->mutex)) {
        dnf_error(ch->name, "mutex_lock\n");
        return -1;
    }

    while (true) {
        bool need_wait = false;
        for (i = 0; i < hdr->max_sub; i++) {
            cdipc_sub_t *sub = ch->subs + i;
            if (sub->need_wait && sub->pend_head.len == sub->max_len) {
                need_wait = true;
                break;
            }
        }
        if (!need_wait)
            break;

        if (abstime) {
            r = pthread_cond_timedwait(&hdr->cond, &hdr->mutex, abstime);
        } else {
            r = pthread_cond_wait(&hdr->cond, &hdr->mutex);
        }
        if (r == ETIMEDOUT) {
            break;
        } else if (r != 0) {
            dnf_error(ch->name, "cond_timedwait, ret: %d\n", r);
            break;
        }
    }

    if (r == 0) {
        bool drop = true;
        if (hdr->type == CDIPC_TOPIC)
            nd->pub_id = -1;
        for (i = 0; i < hdr->max_sub; i++) {
            cdipc_sub_t *sub = ch->subs + i;
            if (sub->max_len != 0) {
                drop = false;
                if (sub->pend_head.len == sub->max_len) {
                    cdipc_wp_t *wp = rlist_get_entry(hdr, &sub->pend_head, cdipc_wp_t);
                    assert(wp != NULL);
                    cdipc_nd_t *nd = cd_r2nd(hdr, wp->r_nd);
                    rlist_put(hdr, &hdr->free_wp, &wp->node);
                    nd->sub_ref &= ~(1 << i);
                    if (!nd->sub_ref && nd->pub_id < 0)
                        rlist_put(hdr, &hdr->free, &nd->node);
                }
                cdipc_wp_t *wp = rlist_get_entry(hdr, &hdr->free_wp, cdipc_wp_t);
                nd->sub_ref |= 1 << i;
                wp->r_nd = cd_nd2r(hdr, nd);
                rlist_put(hdr, &sub->pend_head, &wp->node);
            }
        }
        if (drop) {
            dnf_debug(ch->name, "drop\n");
            rlist_put(hdr, &hdr->free, &nd->node);
        }
        pthread_cond_broadcast(&hdr->cond);
    }

    pthread_mutex_unlock(&hdr->mutex);
    return r;
}

int cdipc_pub_wait(cdipc_ch_t *ch, cdipc_nd_t *nd,
        const struct timespec *abstime)
{
    int i, r = 0;
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_pub_t *pub = ch->pub;
    assert(ch->role == CDIPC_PUB);

    if (pthread_mutex_lock(&hdr->mutex)) {
        dnf_error(ch->name, "mutex_lock\n");
        return -1;
    }

    while (nd->sub_ref & 1) {
        if (abstime) {
            r = pthread_cond_timedwait(&hdr->cond, &hdr->mutex, abstime);
        } else {
            r = pthread_cond_wait(&hdr->cond, &hdr->mutex);
        }
        if (r == ETIMEDOUT) {
            break;
        } else if (r != 0) {
            dnf_error(ch->name, "cond_timedwait, ret: %d\n", r);
            break;
        }
    }

    pthread_mutex_unlock(&hdr->mutex);
    return r;
}

int cdipc_pub_free(cdipc_ch_t *ch, cdipc_nd_t *nd)
{
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_pub_t *pub = ch->pub;
    assert(ch->role == CDIPC_PUB && hdr->type == CDIPC_SERVICE);

    if (pthread_mutex_lock(&hdr->mutex)) {
        dnf_error(ch->name, "mutex_lock\n");
        return -1;
    }
    nd->pub_id = -1;
    if (!nd->sub_ref && nd->pub_id < 0)
        rlist_put(hdr, &hdr->free, &nd->node);
    pthread_cond_broadcast(&hdr->cond);
    pthread_mutex_unlock(&hdr->mutex);
    return 0;
}

// for sub:

cdipc_nd_t *cdipc_sub_get(cdipc_ch_t *ch, const struct timespec *abstime)
{
    int i, r = 0;
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_sub_t *sub = ch->sub;
    cdipc_wp_t *wp;
    cdipc_nd_t *nd = NULL;
    assert(ch->role == CDIPC_SUB);

    if (pthread_mutex_lock(&hdr->mutex)) {
        dnf_error(ch->name, "mutex_lock\n");
        return NULL;
    }

pick_node:
    while (!(wp = rlist_get_entry(hdr, &sub->pend_head, cdipc_wp_t))) {
        if (abstime) {
            r = pthread_cond_timedwait(&hdr->cond, &hdr->mutex, abstime);
        } else {
            r = pthread_cond_wait(&hdr->cond, &hdr->mutex);
        }
        if (r == ETIMEDOUT) {
            break;
        } else if (r != 0) {
            dnf_error(ch->name, "cond_timedwait, ret: %d\n", r);
            break;
        }
    }
    if (wp) {
        nd = cd_r2nd(hdr, wp->r_nd);
        rlist_put(hdr, &hdr->free_wp, &wp->node);

        if (nd->abort) {
            nd->sub_ref &= ~(1 << sub->id);
            if (!nd->sub_ref && nd->pub_id < 0)
                rlist_put(hdr, &hdr->free, &nd->node);
            nd = NULL;
            df_debug("avoid abort node\n");
            pthread_cond_broadcast(&hdr->cond);
            goto pick_node;
        }
    }

    pthread_cond_broadcast(&hdr->cond);
    pthread_mutex_unlock(&hdr->mutex);
    return nd;
}

int cdipc_sub_ret(cdipc_ch_t *ch, cdipc_nd_t *nd)
{
    int i, r = 0;
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_sub_t *sub = ch->sub;
    assert(ch->role == CDIPC_SUB && hdr->type == CDIPC_SERVICE);

    if (sub->id != 0) {
        dnf_error(ch->name, "only allow sub id 0\n");
        return -1;
    }

    if (pthread_mutex_lock(&hdr->mutex)) {
        dnf_error(ch->name, "mutex_lock\n");
        return -1;
    }

    nd->sub_ref &= ~(1 << sub->id);

    if (nd->abort) {
        df_debug("avoid cancelled node\n");
        if (!nd->sub_ref && nd->pub_id < 0)
            rlist_put(hdr, &hdr->free, &nd->node);
    }

    // TODO: set nd status

    pthread_cond_broadcast(&hdr->cond);
    pthread_mutex_unlock(&hdr->mutex);
    return r;
}

int cdipc_sub_free(cdipc_ch_t *ch, cdipc_nd_t *nd)
{
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_sub_t *sub = ch->sub;
    assert(ch->role == CDIPC_SUB && hdr->type == CDIPC_TOPIC);

    if (pthread_mutex_lock(&hdr->mutex)) {
        dnf_error(ch->name, "mutex_lock\n");
        return -1;
    }

    nd->sub_ref &= ~(1 << sub->id);
    if (!nd->sub_ref && nd->pub_id < 0)
        rlist_put(hdr, &hdr->free, &nd->node);

    pthread_cond_broadcast(&hdr->cond);
    pthread_mutex_unlock(&hdr->mutex);
    return 0;
}
