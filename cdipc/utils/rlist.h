/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2017, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <duke@dukelec.com>
 */

#ifndef __RLIST_H__
#define __RLIST_H__

typedef struct rlist_node {
   struct rlist_node *rnext;
} rlist_node_t;

typedef struct {
    rlist_node_t *rfirst;
    rlist_node_t *rlast;
    uint32_t    len;
} rlist_head_t;


rlist_node_t *rlist_get(const void *base, rlist_head_t *head);
void rlist_put(const void *base, rlist_head_t *head, rlist_node_t *node);


#define rlist_entry(ptr, type)                                  \
    container_of(ptr, type, node)

#define rlist_entry_safe(ptr, type) ({                          \
        rlist_node_t *__ptr = (ptr);                            \
        __ptr ? container_of(__ptr, type, node) : NULL;         \
    })

#define rlist_get_entry(base, head, type)                       \
        rlist_entry_safe(rlist_get(base, head), type)

#endif

