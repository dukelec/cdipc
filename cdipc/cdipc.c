/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <duke@dukelec.com>
 */

#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <assert.h>
#include "cdipc.h"


static void cdipc_cal_addr(cdipc_ch_t *ch, bool update_hdr)
{
    cdipc_hdr_t *hdr = ch->hdr;
    void *end_addr;
    size_t align_mask = sizeof(void *) - 1;
    if (update_hdr) {
        hdr->max_len = (hdr->max_len + align_mask) & ~align_mask;
        hdr->max_len_r = (hdr->max_len_r + align_mask) & ~align_mask;
        if (hdr->type != CDIPC_SERVICE)
            hdr->max_len_r = 0;

    }
    ch->pubs = (void *)ch->hdr + sizeof(cdipc_hdr_t);
    ch->subs = (void *)ch->pubs + sizeof(cdipc_pub_t) * hdr->max_pub;
    ch->wps = (void *)ch->subs + sizeof(cdipc_sub_t) * hdr->max_sub;
    ch->nds = (void *)ch->wps + sizeof(cdipc_wp_t) * hdr->max_nd * hdr->max_sub;
    ch->nd_len = sizeof(cdipc_nd_t) + hdr->max_len + hdr->max_len_r;
    end_addr = (void *)ch->nds + ch->nd_len * hdr->max_nd;
    ch->map_len = (ptrdiff_t)end_addr - (ptrdiff_t)ch->hdr;
}

int cdipc_create(const char *name, cdipc_type_t type, int max_pub, int max_sub,
        int max_nd, size_t max_len, size_t max_len_r)
{
    int i, r;
    cdipc_hdr_t hdr_tmp = {0};
    cdipc_ch_t _ch = {0};
    cdipc_ch_t *ch = &_ch;

    if (!max_pub || !max_sub || !max_nd || !max_len ||
            (type == CDIPC_SERVICE && !max_len_r)) {
        dnf_error(name, "zero arguments detected\n");
        return -1;
    }

    hdr_tmp.type = type;
    hdr_tmp.max_pub = max_pub;
    hdr_tmp.max_sub = max_sub;
    hdr_tmp.max_nd = max_nd;
    hdr_tmp.max_len = max_len;
    hdr_tmp.max_len_r = max_len_r;
    ch->hdr = &hdr_tmp;
    cdipc_cal_addr(ch, true); // only for map_len
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
    memcpy(ch->hdr, &hdr_tmp, sizeof(cdipc_hdr_t));
    cdipc_cal_addr(ch, false); // re-cal for pointers

    if ((r = cd_mutex_init(&ch->hdr->mutex, NULL))) {
        dnf_error(ch->name, "cd_mutex_init, ret: %d\n", r);
        goto exit_free_mmap;
    }

    if ((r = cd_cond_init(&ch->hdr->cond, NULL))) {
        dnf_error(ch->name, "cd_cond_init\n");
        goto exit_free_mmap;
    }

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
        cdipc_wp_t *wp = ch->wps + i;
        memset(wp, 0, sizeof(cdipc_wp_t));
        rlist_put(ch->hdr, &ch->hdr->free_wp, &wp->node);
    }
    for (i = 0; i < max_nd; i++) {
        cdipc_nd_t *nd = (void *)ch->nds + ch->nd_len * i;
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


// normally: -1 for auto detect, 0 for reset to zero
void cdipc_set_tid(cdipc_ch_t *ch, int tid)
{
    if (tid == -1)
        tid = syscall(SYS_gettid);

    if (ch->role == CDIPC_PUB && ch->pub)
        ch->pub->tid = tid;
    else if (ch->role == CDIPC_SUB && ch->sub)
        ch->sub->tid = tid;
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
    cdipc_cal_addr(ch, false);

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
    cdipc_cal_addr(ch, false); // update pointers after re-mmap

    ch->role = role;
    if (role == CDIPC_PUB) {
        ch->pub = ch->pubs + id;
        cdipc_set_tid(ch, -1);
    } else if (role == CDIPC_SUB) {
        ch->sub = ch->subs + id;
        cdipc_set_tid(ch, -1);
    } else {
        dnf_debug(ch->name, "neither sub nor pub\n");
    }

    return 0;
}

int cdipc_recover(cdipc_ch_t *ch)
{
    int n = 0;
    int i;
    cdipc_hdr_t *hdr = ch->hdr;
    int tid = ch->role == CDIPC_SUB ? ch->sub->tid : ch->pub->tid;

    if (cd_mutex_lock(&hdr->mutex, tid, NULL)) {
        dnf_error(ch->name, "mutex_lock\n");
        return -1;
    }

    if (ch->role == CDIPC_SUB) {
        cdipc_sub_t *sub = ch->sub;
        for (i = 0; i < hdr->max_nd; i++) {
            cdipc_nd_t *nd = (void *)ch->nds + ch->nd_len * i;
            if (nd->sub_ref & (1 << sub->id)) {
                bool found = false;
                rlist_node_t *rnode, *node;
                for (rnode = sub->pend_head.rfirst; rnode != NULL; rnode = node->rnext) {
                    node = (void *)rnode + (ptrdiff_t)hdr;
                    cdipc_wp_t *wp = rlist_entry(node, cdipc_wp_t);
                    if (cd_r2nd(hdr, wp->r_nd) == nd) {
                        found = true;
                        break;
                    }
                }
                if (found)
                    continue;
                n++;
                nd->sub_ref &= ~(1 << sub->id);
                nd->len_r = 0;
                nd->abort = true;
                if (!nd->sub_ref && nd->pub_id < 0)
                    rlist_put(hdr, &hdr->free, &nd->node);
            }
        }
    } else if (ch->role == CDIPC_PUB) {
        cdipc_pub_t *pub = ch->pub;
        for (i = 0; i < hdr->max_nd; i++) {
            cdipc_nd_t *nd = (void *)ch->nds + ch->nd_len * i;
            if (nd->pub_id == pub->id) {
                n++;
                nd->pub_id = -1;
                nd->abort = true;
                if (!nd->sub_ref && nd->pub_id < 0)
                    rlist_put(hdr, &hdr->free, &nd->node);
            }
        }
    }

    if (n)
        cd_cond_broadcast(&hdr->cond);
    cd_mutex_unlock(&hdr->mutex, tid);
    return n;
}

int cdipc_close(cdipc_ch_t *ch)
{
    cdipc_set_tid(ch, 0);

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

    if (cd_mutex_lock(&hdr->mutex, pub->tid, NULL)) {
        dnf_error(ch->name, "mutex_lock\n");
        return NULL;
    }
    while (!(nd = rlist_get_entry(hdr, &hdr->free, cdipc_nd_t))) {
        r = cd_cond_wait(&hdr->cond, &hdr->mutex, pub->tid, abstime);
        if (r == ETIMEDOUT) {
            break;
        } else if (r != 0) {
            dnf_error(ch->name, "cond_wait, ret: %d\n", r);
            break;
        }
    }
    if (nd) {
        nd->abort = false;
        nd->pub_id = pub->id;
        nd->pub_id_bk = pub->id;
        nd->sub_ref = 0;
        nd->len = 0;
        nd->len_r = 0;
    }
    cd_mutex_unlock(&hdr->mutex, pub->tid);
    return nd;
}

int cdipc_pub_put(cdipc_ch_t *ch, cdipc_nd_t *nd,
        const struct timespec *abstime)
{
    int i, r = 0;
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_pub_t *pub = ch->pub;
    assert(ch->role == CDIPC_PUB);

    if (cd_mutex_lock(&hdr->mutex, pub->tid, NULL)) {
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

        r = cd_cond_wait(&hdr->cond, &hdr->mutex, pub->tid, abstime);
        if (r == ETIMEDOUT) {
            break;
        } else if (r != 0) {
            dnf_error(ch->name, "cond_wait, ret: %d\n", r);
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
        cd_cond_broadcast(&hdr->cond);
    }

    cd_mutex_unlock(&hdr->mutex, pub->tid);
    return r;
}

int cdipc_pub_wait(cdipc_ch_t *ch, cdipc_nd_t *nd,
        const struct timespec *abstime)
{
    int i, r = 0;
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_pub_t *pub = ch->pub;
    assert(ch->role == CDIPC_PUB);

    if (cd_mutex_lock(&hdr->mutex, pub->tid, NULL)) {
        dnf_error(ch->name, "mutex_lock\n");
        return -1;
    }

    while (nd->sub_ref & 1) {
        r = cd_cond_wait(&hdr->cond, &hdr->mutex, pub->tid, abstime);
        if (r == ETIMEDOUT) {
            break;
        } else if (r != 0) {
            dnf_error(ch->name, "cond_wait, ret: %d\n", r);
            break;
        }
    }

    cd_mutex_unlock(&hdr->mutex, pub->tid);
    return r;
}

int cdipc_pub_free(cdipc_ch_t *ch, cdipc_nd_t *nd)
{
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_pub_t *pub = ch->pub;
    assert(ch->role == CDIPC_PUB && hdr->type == CDIPC_SERVICE);

    if (cd_mutex_lock(&hdr->mutex, pub->tid, NULL)) {
        dnf_error(ch->name, "mutex_lock\n");
        return -1;
    }
    nd->pub_id = -1;
    if (!nd->sub_ref && nd->pub_id < 0)
        rlist_put(hdr, &hdr->free, &nd->node);
    cd_cond_broadcast(&hdr->cond);
    cd_mutex_unlock(&hdr->mutex, pub->tid);
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

    if (cd_mutex_lock(&hdr->mutex, sub->tid, NULL)) {
        dnf_error(ch->name, "mutex_lock\n");
        return NULL;
    }

pick_node:
    while (!(wp = rlist_get_entry(hdr, &sub->pend_head, cdipc_wp_t))) {
        r = cd_cond_wait(&hdr->cond, &hdr->mutex, sub->tid, abstime);
        if (r == ETIMEDOUT) {
            break;
        } else if (r != 0) {
            dnf_error(ch->name, "cond_wait, ret: %d\n", r);
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
            cd_cond_broadcast(&hdr->cond);
            goto pick_node;
        }
    }

    cd_cond_broadcast(&hdr->cond);
    cd_mutex_unlock(&hdr->mutex, sub->tid);
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

    if (cd_mutex_lock(&hdr->mutex, sub->tid, NULL)) {
        dnf_error(ch->name, "mutex_lock\n");
        return -1;
    }

    nd->sub_ref &= ~(1 << sub->id);

    if (nd->abort) {
        df_debug("avoid cancelled node\n");
        if (!nd->sub_ref && nd->pub_id < 0)
            rlist_put(hdr, &hdr->free, &nd->node);
    }

    cd_cond_broadcast(&hdr->cond);
    cd_mutex_unlock(&hdr->mutex, sub->tid);
    return r;
}

int cdipc_sub_free(cdipc_ch_t *ch, cdipc_nd_t *nd)
{
    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_sub_t *sub = ch->sub;
    assert(ch->role == CDIPC_SUB && hdr->type == CDIPC_TOPIC);

    if (cd_mutex_lock(&hdr->mutex, sub->tid, NULL)) {
        dnf_error(ch->name, "mutex_lock\n");
        return -1;
    }

    nd->sub_ref &= ~(1 << sub->id);
    if (!nd->sub_ref && nd->pub_id < 0)
        rlist_put(hdr, &hdr->free, &nd->node);

    cd_cond_broadcast(&hdr->cond);
    cd_mutex_unlock(&hdr->mutex, sub->tid);
    return 0;
}
