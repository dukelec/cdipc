/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <duke@dukelec.com>
 */

#ifndef __CDIPC_H__
#define __CDIPC_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include <linux/limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "utils/cd_rlist.h"
#include "utils/cd_time.h"
#include "utils/cd_futex.h"

#define CDIPC_MAGIC_NUM 0xcdcd0002


typedef enum {
    CDIPC_TOPIC = 0,
    CDIPC_SERVICE
} cdipc_type_t;

typedef enum {
    CDIPC_PUB = 0,
    CDIPC_SUB
} cdipc_role_t;


typedef struct {
    rlist_node_t    node;
    int             id;
    uint64_t        sub_ref;    // reference map
                                // TODO: add support for more than 64 bits
    int             pub_id;
    int             pub_id_bk;  // for logging purpose
    bool            abort;

    size_t          len;
    size_t          len_r;      // return data at dat + hdr->max_len
    uint8_t         dat[];
} cdipc_nd_t;

typedef struct {
    rlist_node_t    node;
} cdipc_wp_t;                   // wrapper: wps[sub_id * max_nd + nd_id] links
                                // the nd into pend_head of the sub

typedef struct {
    int             id;
    int             tid;        // thread ID (TID; see gettid(2))
} cdipc_pub_t;

typedef struct {
    int             id;
    int             tid;        // thread ID
    int             max_len;
    bool            need_wait;
    rlist_head_t    pend_head;
    cd_cond_t       cond;       // wakes this sub only
} cdipc_sub_t;

typedef struct {
    uint32_t        magic;
    cdipc_type_t    type;

    int             max_pub;
    int             max_sub;
    int             max_nd;
    size_t          max_len;
    size_t          max_len_r;

    cd_mutex_t      mutex;
    bool            busy;       // set inside the lock, found set at lock: last holder died
    cd_cond_t       cond;       // wakes pubs: free node, pend room, reply

    rlist_head_t    free;
} cdipc_hdr_t;



typedef struct {
    int             fd;
    char            name[NAME_MAX];
    cdipc_hdr_t     *hdr;
    size_t          map_len;

    // save areas start address
    cdipc_pub_t     *pubs;
    cdipc_sub_t     *subs;
    cdipc_wp_t      *wps;
    cdipc_nd_t      *nds;
    size_t          nd_len; // one nd size, include datas

    cdipc_role_t    role;
    cdipc_pub_t     *pub;   // owner self if owner is pub
    cdipc_sub_t     *sub;   // owner self if owner is sub
} cdipc_ch_t;



// nd of a wrapper in pend_head
static inline cdipc_nd_t *cdipc_wp2nd(const cdipc_ch_t *ch, const cdipc_wp_t *wp)
{
    return (cdipc_nd_t *)((char *)ch->nds + ch->nd_len * ((wp - ch->wps) % ch->hdr->max_nd));
}

int cdipc_create(const char *name, cdipc_type_t type, int max_pub, int max_sub,
        int max_nd, size_t max_len, size_t max_len_r);
int cdipc_unlink(const char *name);

int cdipc_open(cdipc_ch_t *ch, const char *name, cdipc_role_t role, int id);
int cdipc_close(cdipc_ch_t *ch);

int cdipc_recover(cdipc_ch_t *ch);

cdipc_nd_t *cdipc_pub_alloc(cdipc_ch_t *ch, const struct timespec *abstime);
int cdipc_pub_put(cdipc_ch_t *ch, cdipc_nd_t *nd,
        const struct timespec *abstime);
// ECANCELED: request dropped or aborted, no valid reply
int cdipc_pub_wait(cdipc_ch_t *ch, cdipc_nd_t *nd,
        const struct timespec *abstime);
// free before reply cancels the request
int cdipc_pub_free(cdipc_ch_t *ch, cdipc_nd_t *nd);
cdipc_nd_t *cdipc_sub_get(cdipc_ch_t *ch, const struct timespec *abstime);
int cdipc_sub_ret(cdipc_ch_t *ch, cdipc_nd_t *nd);
int cdipc_sub_free(cdipc_ch_t *ch, cdipc_nd_t *nd);
int cdipc_sub_cfg(cdipc_ch_t *ch, int max_len, bool need_wait);

#ifdef __cplusplus
}
#endif

#endif
