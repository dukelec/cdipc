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
#include <fcntl.h>
#include <assert.h>

#include <cdipc/utils/cd_utils.h>
#include <cdipc/utils/cd_debug.h>
#include <cdipc/utils/rlist.h>
#include <cdipc/utils/cd_time.h>
#include <cdipc/utils/cd_futex.h>
#include <cdipc/cdipc.h>

const char *usage_main = \
    "Usage: cdipc [create|unlink|put|get|pend-cfg|dump] ...\n"
    "  create:   create a topic or service, under /dev/shm/\n"
    "  unlink:   delete a topic or service\n"
    "  put:      publish a message to a topic or request to service\n"
    "  get:      subscriber to a topic, or wait and reply for service\n"
    "  pend-cfg: set max_len and need_wait flag for a subscriber\n"
    "  dump:     dump topic or service information for debug\n"
    "\n"
    "Example for topic:\n"
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
    "You can override default values by specify them through arguments,\n"
    "type cdipc CMD --help for details\n";

const char *usage_create = \
    "Arguments for create:\n"
    "  --help           # this help message\n"
    "  --name NAME      # topic or service name\n"
    "  --type TYPE      # topic by default, or specify to service\n"
    "  --max-pub NUM    # max pub, default 2\n"
    "  --max-sub NUM    # max sub, default 2\n"
    "  --max-nd NUM     # max nd, default 5\n"
    "  --max-len SIZE   # max data size in nd, default 256 bytes\n";

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
    "  --recover        # run recover at first, default false\n"
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


enum OPT_CREATE_IDX {
    OPT_CREATE_HELP = 1000,
    OPT_CREATE_NAME,
    OPT_CREATE_TYPE,
    OPT_CREATE_MAX_PUB,
    OPT_CREATE_MAX_SUB,
    OPT_CREATE_MAX_ND,
    OPT_CREATE_MAX_LEN
};

static struct option opt_create[] = {
        { "help",       no_argument, NULL, OPT_CREATE_HELP },
        { "name",       required_argument, NULL, OPT_CREATE_NAME },
        { "type",       required_argument, NULL, OPT_CREATE_TYPE },
        { "max-pub",    required_argument, NULL, OPT_CREATE_MAX_PUB },
        { "max-sub",    required_argument, NULL, OPT_CREATE_MAX_SUB },
        { "max-nd",     required_argument, NULL, OPT_CREATE_MAX_ND },
        { "max-len",    required_argument, NULL, OPT_CREATE_MAX_LEN },
        { 0, 0, 0, 0 }
};

int cmd_create(int argc, char **argv)
{
    char name[NAME_MAX] = { 0 };
    cdipc_type_t type = CDIPC_TOPIC;
    int max_pub = 2;
    int max_sub = 2;
    int max_nd = 5;
    size_t max_len = 256;

    while (true) {
        int option = getopt_long(argc, argv, "", opt_create, NULL);
        if (option == -1) {
            if (optind < argc) {
                printf ("non-option argv-elements: ");
                while (optind < argc)
                    printf ("%s ", argv[optind++]);
                putchar ('\n');
            }
            break;
        }
        switch (option) {
        case OPT_CREATE_HELP:
            printf("%s", usage_create);
            exit(0);
        case OPT_CREATE_NAME:
            strncpy(name, optarg, NAME_MAX);
            df_debug("set name: %s\n", name);
            break;
        case OPT_CREATE_TYPE:
            if (0 == strcasecmp(optarg, "service")) {
                type = CDIPC_SERVICE;
                df_debug("set type: service\n");
            } else if (0 != strcasecmp(optarg, "topic")) {
                df_error("wrong type, must be topic or service\n");
                exit(-1);
            }
            break;
        case OPT_CREATE_MAX_PUB:
            max_pub = atol(optarg);
            df_debug("set max_pub: %d\n", max_pub);
            break;
        case OPT_CREATE_MAX_SUB:
            max_sub = atol(optarg);
            df_debug("set max_sub: %d\n", max_sub);
            break;
        case OPT_CREATE_MAX_ND:
            max_nd = atol(optarg);
            df_debug("set max_nd: %d\n", max_nd);
            break;
        case OPT_CREATE_MAX_LEN:
            max_len = atol(optarg);
            df_debug("set max_len: %ld\n", max_len);
            break;
        case 0:
        case '?':
        default:
            break;
        }
    }
    if (!strlen(name)) {
        df_error("--name must specified\n\n%s", usage_create);
        return -1;
    }
    df_debug("name: %s; type: %d, pub: %d, sub: %d, nd: %d, len: %ld\n",
            name, type, max_pub, max_sub, max_nd, max_len);
    return cdipc_create(name, type, max_pub, max_sub, max_nd, max_len);
}


enum OPT_UNLINK_IDX {
    OPT_UNLINK_HELP = 1000,
    OPT_UNLINK_NAME
};

static struct option opt_unlink[] = {
        { "help",       no_argument, NULL, OPT_UNLINK_HELP },
        { "name",       required_argument, NULL, OPT_UNLINK_NAME },
        { 0, 0, 0, 0 }
};

int cmd_unlink(int argc, char **argv)
{
    char name[NAME_MAX] = { 0 };

    while (true) {
        int option = getopt_long(argc, argv, "", opt_unlink, NULL);
        if (option == -1) {
            if (optind < argc) {
                printf ("non-option argv-elements: ");
                while (optind < argc)
                    printf ("%s ", argv[optind++]);
                putchar ('\n');
            }
            break;
        }
        switch (option) {
        case OPT_UNLINK_HELP:
            printf("%s", usage_unlink);
            exit(0);
        case OPT_UNLINK_NAME:
            strncpy(name, optarg, NAME_MAX);
            df_debug("set name: %s\n", name);
            break;
        case 0:
        case '?':
        default:
            break;
        }
    }
    if (!strlen(name)) {
        df_error("--name must specified\n\n%s", usage_unlink);
        return -1;
    }
    return cdipc_unlink(name);
}


enum OPT_PUT_IDX {
    OPT_PUT_HELP = 1000,
    OPT_PUT_NAME,
    OPT_PUT_ID,
    OPT_PUT_TIMEOUT,
    OPT_PUT_DAT
};

static struct option opt_put[] = {
        { "help",       no_argument, NULL, OPT_PUT_HELP },
        { "name",       required_argument, NULL, OPT_PUT_NAME },
        { "id",         required_argument, NULL, OPT_PUT_ID },
        { "timeout",    required_argument, NULL, OPT_PUT_TIMEOUT },
        { "dat",        required_argument, NULL, OPT_PUT_DAT },
        { 0, 0, 0, 0 }
};

int cmd_put(int argc, char **argv)
{
    int r = 0;
    cdipc_ch_t _ch = { 0 };
    cdipc_ch_t *ch = &_ch;
    cdipc_nd_t *nd;
    char name[NAME_MAX] = { 0 };
    int id = 0;
    float timeout = 10;
    char *dat = "test msg";

    while (true) {
        int option = getopt_long(argc, argv, "", opt_put, NULL);
        if (option == -1) {
            if (optind < argc) {
                printf ("non-option argv-elements: ");
                while (optind < argc)
                    printf ("%s ", argv[optind++]);
                putchar ('\n');
            }
            break;
        }
        switch (option) {
        case OPT_PUT_HELP:
            printf("%s", usage_put);
            exit(0);
        case OPT_PUT_NAME:
            strncpy(name, optarg, NAME_MAX);
            df_debug("set name: %s\n", name);
            break;
        case OPT_PUT_ID:
            id = atol(optarg);
            df_debug("set id: %d\n", id);
            break;
        case OPT_PUT_TIMEOUT:
            timeout = atof(optarg);
            df_debug("set timeout: %f\n", timeout);
            break;
        case OPT_PUT_DAT:
            dat = strdup(optarg);
            df_debug("set dat: %s\n", dat);
            break;
        case 0:
        case '?':
        default:
            break;
        }
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
        printf("ret: %s\n", nd->dat + nd->len);
        if ((r = cdipc_pub_free(ch, nd))) {
            return -1;
        }
    }

    return 0;
}


enum OPT_GET_IDX {
    OPT_GET_HELP = 1000,
    OPT_GET_NAME,
    OPT_GET_ID,
    OPT_GET_RECOVER,
    OPT_GET_TIMEOUT,
    OPT_GET_RET_DAT
};

static struct option opt_get[] = {
        { "help",       no_argument, NULL, OPT_GET_HELP },
        { "name",       required_argument, NULL, OPT_GET_NAME },
        { "id",         required_argument, NULL, OPT_GET_ID },
        { "recover",    no_argument, NULL, OPT_GET_RECOVER },
        { "timeout",    required_argument, NULL, OPT_GET_TIMEOUT },
        { "ret-dat",    required_argument, NULL, OPT_GET_RET_DAT },
        { 0, 0, 0, 0 }
};

int cmd_get(int argc, char **argv)
{
    int r = 0;
    cdipc_ch_t _ch = { 0 };
    cdipc_ch_t *ch = &_ch;
    cdipc_nd_t *nd;
    char name[NAME_MAX] = { 0 };
    int id = 0;
    bool recover = false;
    float timeout = 10;
    char *ret_dat = "ret msg";

    while (true) {
        int option = getopt_long(argc, argv, "", opt_get, NULL);
        if (option == -1) {
            if (optind < argc) {
                printf ("non-option argv-elements: ");
                while (optind < argc)
                    printf ("%s ", argv[optind++]);
                putchar ('\n');
            }
            break;
        }
        switch (option) {
        case OPT_GET_HELP:
            printf("%s", usage_get);
            exit(0);
        case OPT_GET_NAME:
            strncpy(name, optarg, NAME_MAX);
            df_debug("set name: %s\n", name);
            break;
        case OPT_GET_ID:
            id = atol(optarg);
            df_debug("set id: %d\n", id);
            break;
        case OPT_GET_RECOVER:
            recover = true;
            printf("selecting recover\n");
            break;
        case OPT_GET_TIMEOUT:
            timeout = atof(optarg);
            df_debug("set timeout: %f\n", timeout);
            break;
        case OPT_GET_RET_DAT:
            ret_dat = strdup(optarg);
            df_debug("set ret_dat: %s\n", ret_dat);
            break;
        case 0:
        case '?':
        default:
            break;
        }
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
    if (recover)
        printf("recover: %d\n", cdipc_recover(ch));

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
        strcpy(nd->dat + nd->len, ret_dat);
        nd->ret_len = strlen(ret_dat);

        if ((r = cdipc_sub_ret(ch, nd))) {
            return -1;
        }
    }

    return 0;
}


enum OPT_PEND_CFG_IDX {
    OPT_PEND_CFG_HELP = 1000,
    OPT_PEND_CFG_NAME,
    OPT_PEND_CFG_ID,
    OPT_PEND_CFG_WAIT,
    OPT_PEND_CFG_MAX
};

static struct option opt_pend_cfg[] = {
        { "help",       no_argument, NULL, OPT_PEND_CFG_HELP },
        { "name",       required_argument, NULL, OPT_PEND_CFG_NAME },
        { "id",         required_argument, NULL, OPT_PEND_CFG_ID },
        { "wait",       required_argument, NULL, OPT_PEND_CFG_WAIT },
        { "max",        required_argument, NULL, OPT_PEND_CFG_MAX },
        { 0, 0, 0, 0 }
};

int cmd_pend_cfg(int argc, char **argv)
{
    int r = 0;
    cdipc_ch_t _ch = { 0 };
    cdipc_ch_t *ch = &_ch;
    char name[NAME_MAX] = { 0 };
    int id = 0;
    bool need_wait = false;
    int pend_max = 2;

    while (true) {
        int option = getopt_long(argc, argv, "", opt_pend_cfg, NULL);
        if (option == -1) {
            if (optind < argc) {
                printf ("non-option argv-elements: ");
                while (optind < argc)
                    printf ("%s ", argv[optind++]);
                putchar ('\n');
            }
            break;
        }
        switch (option) {
        case OPT_PEND_CFG_HELP:
            printf("%s", usage_pend_cfg);
            exit(0);
        case OPT_PEND_CFG_NAME:
            strncpy(name, optarg, NAME_MAX);
            df_debug("set name: %s\n", name);
            break;
        case OPT_PEND_CFG_ID:
            id = atol(optarg);
            df_debug("set id: %d\n", id);
            break;
        case OPT_PEND_CFG_WAIT:
            if (0 == strcasecmp(optarg, "true")) {
                need_wait = true;
                df_debug("set need_wait: true\n");
            } else {
                df_debug("keep need_wait: false\n");
            }
            break;
        case OPT_PEND_CFG_MAX:
            pend_max = atol(optarg);
            df_debug("set pend_max: %d\n", pend_max);
            break;
        case 0:
        case '?':
        default:
            break;
        }
    }
    if (!strlen(name)) {
        df_error("--name must specified\n\n%s", usage_pend_cfg);
        return -1;
    }

    if ((r = cdipc_open(ch, name, CDIPC_SUB, id))) {
        return -1;
    }

    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_sub_t *sub = ch->sub;

    sub->need_wait = need_wait;
    sub->max_len = pend_max;
    return 0;
}


enum OPT_DUMP_IDX {
    OPT_DUMP_HELP = 1000,
    OPT_DUMP_NAME
};

static struct option opt_dump[] = {
        { "help",       no_argument, NULL, OPT_DUMP_HELP },
        { "name",       required_argument, NULL, OPT_DUMP_NAME },
        { 0, 0, 0, 0 }
};

int cmd_dump(int argc, char **argv)
{
    int i, r = 0;
    cdipc_ch_t _ch = { 0 };
    cdipc_ch_t *ch = &_ch;
    char name[NAME_MAX] = { 0 };

    while (true) {
        int option = getopt_long(argc, argv, "", opt_dump, NULL);
        if (option == -1) {
            if (optind < argc) {
                printf ("non-option argv-elements: ");
                while (optind < argc)
                    printf ("%s ", argv[optind++]);
                putchar ('\n');
            }
            break;
        }
        switch (option) {
        case OPT_DUMP_HELP:
            printf("%s", usage_dump);
            exit(0);
        case OPT_DUMP_NAME:
            strncpy(name, optarg, NAME_MAX);
            df_debug("set name: %s\n", name);
            break;
        case 0:
        case '?':
        default:
            break;
        }
    }
    if (!strlen(name)) {
        df_error("--name must specified\n\n%s", usage_dump);
        return -1;
    }

    if ((r = cdipc_open(ch, name, 0, 0))) {
        return -1;
    }

    cdipc_hdr_t *hdr = ch->hdr;
    cd_mutex_lock(&hdr->mutex, NULL);

    printf("futex: %08x, cond: %08x %08x\n", hdr->mutex, hdr->cond.c, hdr->cond.m);

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
    {
        cdipc_wp_t *wps = (void *)ch->subs + sizeof(cdipc_sub_t) * hdr->max_sub;
        cdipc_nd_t *nds = (void *)wps + sizeof(cdipc_wp_t) * hdr->max_nd * hdr->max_sub;

        for (i = 0; i < hdr->max_nd; i++) {
            cdipc_nd_t *nd = (void *)nds + (sizeof(cdipc_nd_t) + hdr->max_len) * i;
            if (!nd->sub_ref && nd->pub_id < 0)
                continue;
            printf("- node %d, sub_ref: %016lx, pub_id: %d (%d), len: %ld, ret_len: %ld\n",
                    nd->id, nd->sub_ref, nd->pub_id, nd->pub_id_bk, nd->len, nd->ret_len);
        }
    }

    for (i = 0; i < hdr->max_sub; i++) {
        rlist_node_t *rnode, *node;
        cdipc_sub_t *sub = ch->subs + i;
        printf("sub %d: pend: %d, need_wait: %d, max_len: %d: [",
                sub->id, sub->pend_head.len, sub->need_wait, sub->max_len);
        for (rnode = sub->pend_head.rfirst; rnode != NULL; rnode = node->rnext) {
            node = (void *)rnode + (ptrdiff_t)hdr;
            cdipc_wp_t *wp = rlist_entry(node, cdipc_wp_t);
            cdipc_nd_t *nd = cd_r2nd(hdr, wp->r_nd);
            printf("%s%d", rnode == sub->pend_head.rfirst ? "" : ", ", nd->id);
        }
        printf("]\n");
    }

    cd_mutex_unlock(&hdr->mutex);
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

