/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <duke@dukelec.com>
 */

#include <time.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <assert.h>

#include <cdipc/cdipc.h>
#include <cdipc/utils/cd_args.h>

const char *usage_main = \
    "Usage: cdipc [create|unlink|put|get|pend-cfg|dump] ...\n"
    "  create:   create a topic or service, under /dev/shm/\n"
    "  unlink:   delete a topic or service\n"
    "  put:      publish a message to a topic or request to service\n"
    "  get:      subscriber to a topic, or wait and reply for service\n"
    "  pend-cfg: set max_len and need_wait flag for a subscriber\n"
    "  dump:     dump topic or service information for debug\n"
    "\n"
    "Example for topic: (run put command in another terminal)\n"
    "  cdipc create --name test   # create a topic with 2 pub and 2 sub\n"
    "                             # 5 nodes of 256 bytes by default\n"
    "  cdipc pend-cfg --name test # change max_len to 2 for first sub\n"
    "                             # max_len is 0 and need_wait is false after create\n"
    "  cdipc get --name test      # wait on sub id 0\n"
    "  cdipc put --name test      # publish string \"test msg\" to the topic\n"
    "\n"
    "Example for service:\n"
    "  cdipc create --name test --type service\n"
    "  cdipc pend-cfg --name test\n"
    "  cdipc get --name test      # reply \"ret msg\" when whatever received\n"
    "  cdipc put --name test      # send requst and wait for reply\n"
    "\n"
    "Notes:\n"
    "  default values can override by arguments,\n"
    "  type \"cdipc CMD --help\" for details\n";

const char *usage_create = \
    "Arguments for create:\n"
    "  --help           # this help message\n"
    "  --name NAME      # topic or service name\n"
    "  --type TYPE      # topic by default, or specify to service\n"
    "  --max-pub NUM    # max pub, default 2\n"
    "  --max-sub NUM    # max sub, default 2\n"
    "  --max-nd NUM     # max nd, default 5\n"
    "  --max-len SIZE   # max data size in nd, default 256 bytes\n"
    "  --max-len-r SIZE # max return size in nd, default 256 bytes\n";

const char *usage_unlink = \
    "Arguments for unlink:\n"
    "  --help           # this help message\n"
    "  --name NAME      # topic or service name\n";

const char *usage_put = \
    "Arguments for put:\n"
    "  --help           # this help message\n"
    "  --name NAME      # topic or service name\n"
    "  --id ID          # pub id, default 0\n"
    "  --timeout SEC    # default 10 sec\n"
    "  --dat STRING     # send data string, default \"test msg\"\n";

const char *usage_get = \
    "Arguments for get:\n"
    "  --help           # this help message\n"
    "  --name NAME      # topic or service name\n"
    "  --id ID          # sub id, default 0\n"
    "  --timeout SEC    # default 10 sec\n"
    "  --ret-dat STRING # return data, default \"ret msg\"\n";

const char *usage_pend_cfg = \
    "Arguments for pend-cfg:\n"
    "  --help           # this help message\n"
    "  --name NAME      # topic or service name\n"
    "  --id ID          # sub id, default 0\n"
    "  --wait BOOL      # need_wait, default false\n"
    "  --max NUM        # max pend, default 2\n";

const char *usage_dump = \
    "Arguments for dump:\n"
    "  --help           # this help message\n"
    "  --name NAME      # topic or service name\n";


int cmd_create(int argc, char **argv)
{
    cd_args_t ca;
    cd_args_parse(&ca, argc, argv);

    const char *name = cd_arg_get_def(&ca, "--name", "");
    cdipc_type_t type = !strcasecmp(cd_arg_get_def(&ca, "--type", "topic"), "service") ? \
            CDIPC_SERVICE : CDIPC_TOPIC;
    int max_pub = atol(cd_arg_get_def(&ca, "--max-pub", "2"));
    int max_sub = atol(cd_arg_get_def(&ca, "--max-sub", "2"));
    int max_nd = atol(cd_arg_get_def(&ca, "--max-nd", "5"));
    size_t max_len = atol(cd_arg_get_def(&ca, "--max-len", "256"));
    size_t max_len_r = atol(cd_arg_get_def(&ca, "--max-len-r", "256"));

    if (cd_arg_get2(&ca, "--help", "-h")) {
        printf("%s", usage_create);
        exit(0);
    }
    const char *left = cd_arg_get_left(&ca);
    if (left) {
        df_error("unknown arg: %s\n", left);
        printf("%s", usage_create);
        exit(-1);
    }
    if (!strlen(name)) {
        df_error("--name must specified\n\n%s", usage_create);
        return -1;
    }

    if (type != CDIPC_SERVICE)
        max_len_r = 0;
    df_info("name: %s; type: %d, pub: %d, sub: %d, nd: %d, len: %ld, len_r: %ld\n",
            name, type, max_pub, max_sub, max_nd, max_len, max_len_r);
    return cdipc_create(name, type, max_pub, max_sub, max_nd, max_len, max_len_r);
}


int cmd_unlink(int argc, char **argv)
{
    cd_args_t ca;
    cd_args_parse(&ca, argc, argv);

    const char *name = cd_arg_get_def(&ca, "--name", "");

    if (cd_arg_get2(&ca, "--help", "-h")) {
        printf("%s", usage_unlink);
        exit(0);
    }
    const char *left = cd_arg_get_left(&ca);
    if (left) {
        df_error("unknown arg: %s\n", left);
        printf("%s", usage_unlink);
        exit(-1);
    }
    if (!strlen(name)) {
        df_error("--name must specified\n\n%s", usage_unlink);
        return -1;
    }

    return cdipc_unlink(name);
}


int cmd_put(int argc, char **argv)
{
    int r = 0;
    cdipc_ch_t _ch = { 0 };
    cdipc_ch_t *ch = &_ch;
    cdipc_nd_t *nd;

    cd_args_t ca;
    cd_args_parse(&ca, argc, argv);

    const char *name = cd_arg_get_def(&ca, "--name", "");
    int id = atol(cd_arg_get_def(&ca, "--id", "0"));
    float timeout = atof(cd_arg_get_def(&ca, "--timeout", "10"));
    const char *dat = cd_arg_get_def(&ca, "--dat", "test msg");

    if (cd_arg_get2(&ca, "--help", "-h")) {
        printf("%s", usage_put);
        exit(0);
    }
    const char *left = cd_arg_get_left(&ca);
    if (left) {
        df_error("unknown arg: %s\n", left);
        printf("%s", usage_put);
        exit(-1);
    }
    if (!strlen(name)) {
        df_error("--name must specified\n\n%s", usage_put);
        return -1;
    }

    struct timespec now;
    struct timespec abstime;
    clock_gettime(CLOCK_MONOTONIC, &now);
    us2tv(tv2us(&now) + timeout * 1000000, &abstime);

    if ((r = cdipc_open(ch, name, CDIPC_PUB, id))) {
        return -1;
    }
    if ((r = cdipc_recover(ch)) > 0) {
        printf("recover: %d\n", r);
    }
    if (!(nd = cdipc_pub_alloc(ch, &abstime))) {
        return -1;
    }

    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_pub_t *pub = ch->pub;

    strcpy(nd->dat, dat);
    nd->len = strlen(dat);

    if ((r = cdipc_pub_put(ch, nd, &abstime))) {
        return -1;
    }

    if (hdr->type == CDIPC_SERVICE) {
        if ((r = cdipc_pub_wait(ch, nd, &abstime))) {
            return -1;
        }
        printf("ret: %s\n", nd->dat + hdr->max_len);
        if ((r = cdipc_pub_free(ch, nd))) {
            return -1;
        }
    }

    cdipc_close(ch);
    return 0;
}


int cmd_get(int argc, char **argv)
{
    int r = 0;
    cdipc_ch_t _ch = { 0 };
    cdipc_ch_t *ch = &_ch;
    cdipc_nd_t *nd;

    cd_args_t ca;
    cd_args_parse(&ca, argc, argv);

    const char *name = cd_arg_get_def(&ca, "--name", "");
    int id = atol(cd_arg_get_def(&ca, "--id", "0"));
    float timeout = atof(cd_arg_get_def(&ca, "--timeout", "10"));
    const char *ret_dat = cd_arg_get_def(&ca, "--ret-dat", "ret msg");

    if (cd_arg_get2(&ca, "--help", "-h")) {
        printf("%s", usage_get);
        exit(0);
    }
    const char *left = cd_arg_get_left(&ca);
    if (left) {
        df_error("unknown arg: %s\n", left);
        printf("%s", usage_get);
        exit(-1);
    }
    if (!strlen(name)) {
        df_error("--name must specified\n\n%s", usage_get);
        return -1;
    }

    struct timespec now;
    struct timespec abstime;
    clock_gettime(CLOCK_MONOTONIC, &now);
    us2tv(tv2us(&now) + timeout * 1000000, &abstime);

    if ((r = cdipc_open(ch, name, CDIPC_SUB, id))) {
        return -1;
    }
    if ((r = cdipc_recover(ch)) > 0) {
        printf("recover: %d\n", r);
    }

    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_sub_t *sub = ch->sub;

    if (!(nd = cdipc_sub_get(ch, &abstime))) {
        return -1;
    }
    printf("get: %s\n", nd->dat);

    if (hdr->type != CDIPC_SERVICE) {
        if ((r = cdipc_sub_free(ch, nd))) {
            return -1;
        }
    } else {
        strcpy(nd->dat + hdr->max_len, ret_dat);
        nd->len_r = strlen(ret_dat);

        if ((r = cdipc_sub_ret(ch, nd))) {
            return -1;
        }
    }

    cdipc_close(ch);
    return 0;
}


int cmd_pend_cfg(int argc, char **argv)
{
    int r = 0;
    cdipc_ch_t _ch = { 0 };
    cdipc_ch_t *ch = &_ch;

    cd_args_t ca;
    cd_args_parse(&ca, argc, argv);

    int id = atol(cd_arg_get_def(&ca, "--id", "0"));
    int pend_max = atol(cd_arg_get_def(&ca, "--max", "2"));
    const char *name = cd_arg_get_def(&ca, "--name", "");
    bool need_wait = !strcasecmp(cd_arg_get_def(&ca, "--wait", "false"), "true");

    if (cd_arg_get2(&ca, "--help", "-h")) {
        printf("%s", usage_pend_cfg);
        exit(0);
    }
    const char *left = cd_arg_get_left(&ca);
    if (left) {
        df_error("unknown arg: %s\n", left);
        printf("%s", usage_pend_cfg);
        exit(-1);
    }
    if (!strlen(name)) {
        df_error("--name must specified\n\n%s", usage_pend_cfg);
        return -1;
    }

    printf("set %s ch%d: need_wait: %d, pend_max: %d\n",
            name, id, need_wait, pend_max);

    if ((r = cdipc_open(ch, name, CDIPC_SUB, id))) {
        return -1;
    }

    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_sub_t *sub = ch->sub;

    sub->need_wait = need_wait;
    sub->max_len = pend_max;
    cdipc_close(ch);
    return 0;
}


int cmd_dump(int argc, char **argv)
{
    int i, r = 0;
    cdipc_ch_t _ch = { 0 };
    cdipc_ch_t *ch = &_ch;
    int tid = syscall(SYS_gettid);

    cd_args_t ca;
    cd_args_parse(&ca, argc, argv);

    const char *name = cd_arg_get_def(&ca, "--name", "");

    if (cd_arg_get2(&ca, "--help", "-h")) {
        printf("%s", usage_dump);
        exit(0);
    }
    const char *left = cd_arg_get_left(&ca);
    if (left) {
        df_error("unknown arg: %s\n", left);
        printf("%s", usage_dump);
        exit(-1);
    }
    if (!name || !strlen(name)) {
        df_error("--name must specified\n\n%s", usage_dump);
        return -1;
    }

    if ((r = cdipc_open(ch, name, -1, -1))) {
        return -1;
    }

    cdipc_hdr_t *hdr = ch->hdr;
    printf("our tid: %08x, futex: %08x, cond: %08x %08x\n",
            tid, hdr->mutex, hdr->cond.c, hdr->cond.m);
    cd_mutex_lock(&hdr->mutex, tid, NULL);

    printf("type: %s, max: pub %d, sub %d, nd %d, len %ld\n",
            hdr->type == CDIPC_SERVICE ? "service" : "topic",
            hdr->max_pub, hdr->max_sub, hdr->max_nd, hdr->max_len);
    printf("free: %d, free_wp: %d\n", hdr->free.len, hdr->free_wp.len);

    {
        rlist_node_t *rnode, *node;
        printf("free nodes: [");
        for (rnode = hdr->free.rfirst; rnode != NULL; rnode = node->rnext) {
            node = (void *)rnode + (ptrdiff_t)hdr;
            cdipc_nd_t *nd = rlist_entry(node, cdipc_nd_t);
            printf("%s%d", rnode == hdr->free.rfirst ? "" : ", ", nd->id);
        }
        printf("]\n");
    }
    for (i = 0; i < hdr->max_nd; i++) {
        cdipc_nd_t *nd = (void *)ch->nds + ch->nd_len * i;
        if (!nd->sub_ref && nd->pub_id < 0)
            continue;
        printf("- node %d, sub_ref: %016lx, pub_id: %d (%d), len: %ld, len_r: %ld, abort: %d\n",
                nd->id, nd->sub_ref, nd->pub_id, nd->pub_id_bk, nd->len, nd->len_r, nd->abort);
    }

    for (i = 0; i < hdr->max_pub; i++) {
        cdipc_pub_t *pub = ch->pubs + i;
        printf("pub %d: tid: %08x\n", pub->id, pub->tid);
    }

    for (i = 0; i < hdr->max_sub; i++) {
        rlist_node_t *rnode, *node;
        cdipc_sub_t *sub = ch->subs + i;
        printf("sub %d: tid: %08x, pend: %d, need_wait: %d, max_len: %d: [",
                sub->id, sub->tid, sub->pend_head.len, sub->need_wait, sub->max_len);
        for (rnode = sub->pend_head.rfirst; rnode != NULL; rnode = node->rnext) {
            node = (void *)rnode + (ptrdiff_t)hdr;
            cdipc_wp_t *wp = rlist_entry(node, cdipc_wp_t);
            cdipc_nd_t *nd = cd_r2nd(hdr, wp->r_nd);
            printf("%s%d", rnode == sub->pend_head.rfirst ? "" : ", ", nd->id);
        }
        printf("]\n");
    }

    cd_mutex_unlock(&hdr->mutex, tid);
    return 0;
}


int main(int argc, char **argv)
{
    if (argc > 1) {
        if (0 == strcmp(argv[1], "create")) {
            return cmd_create(argc - 1, &argv[1]);
        }
        if (0 == strcmp(argv[1], "unlink")) {
            return cmd_unlink(argc - 1, &argv[1]);
        }
        if (0 == strcmp(argv[1], "put")) {
            return cmd_put(argc - 1, &argv[1]);
        }
        if (0 == strcmp(argv[1], "get")) {
            return cmd_get(argc - 1, &argv[1]);
        }
        if (0 == strcmp(argv[1], "pend-cfg")) {
            return cmd_pend_cfg(argc - 1, &argv[1]);
        }
        if (0 == strcmp(argv[1], "dump")) {
            return cmd_dump(argc - 1, &argv[1]);
        }
    }

    printf("%s", usage_main);
    return -1;
}
