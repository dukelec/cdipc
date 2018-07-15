/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2017, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <duke@dukelec.com>
 */

#include "cd_utils.h"
#include "cd_rlist.h"

// pick first item
rlist_node_t *rlist_get(const void *base, rlist_head_t *head)
{
    ptrdiff_t bs = (ptrdiff_t)base;
    rlist_node_t *node = NULL;
    if (head->len) {
        node = (void *)head->rfirst + bs;
        head->rfirst = node->rnext;
        if (--head->len == 0)
            head->rlast = NULL;
    }
    return node;
}

// append item at end
void rlist_put(const void *base, rlist_head_t *head, rlist_node_t *node)
{
    ptrdiff_t bs = (ptrdiff_t)base;
    rlist_node_t *rnode = (void *)node - bs;

    if (head->len++) {
        rlist_node_t *last = (void *)head->rlast + bs;
        last->rnext = rnode;
    } else {
        head->rfirst = rnode;
    }
    head->rlast = rnode;
    node->rnext = NULL;
}
