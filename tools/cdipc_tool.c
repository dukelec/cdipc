/*
 * Software License Agreement (MIT License)
 *
 * Copyright (c) 2018, DUKELEC, Inc.
 * All rights reserved.
 *
 * Author: Duke Fong <duke@dukelec.com>
 */

#include <getopt.h>
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <assert.h>

#define DEBUG
#include "cdipc.h"
#include "cd_time.h"


enum OPT_CREATE_IDX {
    OPT_CREATE_NAME = 1000,
    OPT_CREATE_TYPE,
    OPT_CREATE_MAX_PUB,
    OPT_CREATE_MAX_SUB,
    OPT_CREATE_MAX_ND,
    OPT_CREATE_MAX_LEN
};

static struct option opt_create[] = {
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
    int max_sub = 1;
    int max_nd = 1;
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
        df_error("--name must specified\n");
        return -1;
    }
    df_debug("name: %s; type: %d, pub: %d, sub: %d, nd: %d, len: %ld\n",
            name, type, max_pub, max_sub, max_nd, max_len);
    return cdipc_create(name, type, max_pub, max_sub, max_nd, max_len);
}


enum OPT_UNLINK_IDX {
    OPT_UNLINK_NAME = 1000
};

static struct option opt_unlink[] = {
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
        df_error("--name must specified\n");
        return -1;
    }
    return cdipc_unlink(name);
}


enum OPT_PUT_IDX {
    OPT_PUT_NAME = 1000,
    OPT_PUT_ID,
    OPT_PUT_TIMEOUT,
    OPT_PUT_DAT
};

static struct option opt_put[] = {
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
    char name[NAME_MAX] = { 0 };
    int id = 0;
    int timeout_ms = 10000;
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
        case OPT_PUT_NAME:
            strncpy(name, optarg, NAME_MAX);
            df_debug("set name: %s\n", name);
            break;
        case OPT_PUT_ID:
            id = atol(optarg);
            df_debug("set id: %d\n", id);
            break;
        case OPT_PUT_TIMEOUT:
            timeout_ms = atol(optarg);
            df_debug("set timeout_ms: %d\n", timeout_ms);
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
        df_error("--name must specified\n");
        return -1;
    }

    struct timespec now;
    struct timespec abstime;
    clock_gettime(CLOCK_MONOTONIC, &now);
    us2tv(tv2us(&now) + timeout_ms * 1000, &abstime);

    if ((r = cdipc_open(ch, name, CDIPC_PUB, id))) {
        return -1;
    }
    if ((r = cdipc_pub_alloc(ch, &abstime))) {
        return -1;
    }

    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_pub_t *pub = ch->pub;

    strcpy(pub->cur->dat, dat);
    pub->cur->len = strlen(dat);

    if ((r = cdipc_pub_put(ch, &abstime))) {
        return -1;
    }

    if (hdr->type == CDIPC_SERVICE) {
        if ((r = cdipc_pub_get(ch, &abstime))) {
            return -1;
        }
        printf("ret: %s\n", pub->ans->dat);
        if ((r = cdipc_pub_free(ch))) {
            return -1;
        }
    }

    return 0;
}


enum OPT_GET_IDX {
    OPT_GET_NAME = 1000,
    OPT_GET_ID,
    OPT_GET_TIMEOUT,
    OPT_GET_DAT
};

static struct option opt_get[] = {
        { "name",       required_argument, NULL, OPT_GET_NAME },
        { "id",         required_argument, NULL, OPT_GET_ID },
        { "timeout",    required_argument, NULL, OPT_GET_TIMEOUT },
        { 0, 0, 0, 0 }
};

int cmd_get(int argc, char **argv)
{
    int r = 0;
    cdipc_ch_t _ch = { 0 };
    cdipc_ch_t *ch = &_ch;
    char name[NAME_MAX] = { 0 };
    int id = 0;
    int timeout_ms = 10000;

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
        case OPT_GET_NAME:
            strncpy(name, optarg, NAME_MAX);
            df_debug("set name: %s\n", name);
            break;
        case OPT_GET_ID:
            id = atol(optarg);
            df_debug("set id: %d\n", id);
            break;
        case OPT_GET_TIMEOUT:
            timeout_ms = atol(optarg);
            df_debug("set timeout_ms: %d\n", timeout_ms);
            break;
        case 0:
        case '?':
        default:
            break;
        }
    }
    if (!strlen(name)) {
        df_error("--name must specified\n");
        return -1;
    }

    struct timespec now;
    struct timespec abstime;
    clock_gettime(CLOCK_MONOTONIC, &now);
    us2tv(tv2us(&now) + timeout_ms * 1000, &abstime);

    if ((r = cdipc_open(ch, name, CDIPC_SUB, id))) {
        return -1;
    }

    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_sub_t *sub = ch->sub;

    if ((r = cdipc_sub_get(ch, &abstime))) {
        return -1;
    }
    printf("get: %s\n", sub->cur->dat);

    if (hdr->type != CDIPC_SERVICE) {
        if ((r = cdipc_sub_free(ch))) {
            return -1;
        }
    }

    return 0;
}


enum OPT_RET_IDX {
    OPT_RET_NAME = 1000,
    OPT_RET_ID,
    OPT_RET_TIMEOUT,
    OPT_RET_DAT
};

static struct option opt_ret[] = {
        { "name",       required_argument, NULL, OPT_RET_NAME },
        { "id",         required_argument, NULL, OPT_RET_ID },
        { "dat",        required_argument, NULL, OPT_RET_DAT },
        { 0, 0, 0, 0 }
};

int cmd_ret(int argc, char **argv)
{
    int r = 0;
    cdipc_ch_t _ch = { 0 };
    cdipc_ch_t *ch = &_ch;
    char name[NAME_MAX] = { 0 };
    int id = 0;
    char *dat = "ret msg";

    while (true) {
        int option = getopt_long(argc, argv, "", opt_ret, NULL);
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
        case OPT_RET_NAME:
            strncpy(name, optarg, NAME_MAX);
            df_debug("set name: %s\n", name);
            break;
        case OPT_RET_ID:
            id = atol(optarg);
            df_debug("set id: %d\n", id);
            break;
        case OPT_RET_DAT:
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
        df_error("--name must specified\n");
        return -1;
    }

    if ((r = cdipc_open(ch, name, CDIPC_SUB, id))) {
        return -1;
    }

    cdipc_hdr_t *hdr = ch->hdr;
    cdipc_sub_t *sub = ch->sub;

    if (hdr->type != CDIPC_SERVICE) {
        dnf_error(name, "not service\n");
        return -1;
    }
    strcpy(sub->cur->dat, dat);
    sub->cur->len = strlen(dat);

    if ((r = cdipc_sub_ret(ch))) {
        return -1;
    }

    return 0;
}


enum OPT_DUMP_IDX {
    OPT_DUMP_NAME = 1000
};

static struct option opt_dump[] = {
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
        case OPT_RET_NAME:
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
        df_error("--name must specified\n");
        return -1;
    }

    if ((r = cdipc_open(ch, name, 0, 0))) {
        return -1;
    }

    cdipc_hdr_t *hdr = ch->hdr;
    pthread_mutex_lock(&hdr->mutex);

    printf("type: %s\n", hdr->type == CDIPC_SERVICE ? "service" : "topic");
    printf("max: pub %d, sub %d, nd %d, len %ld\n",
            hdr->max_pub, hdr->max_sub, hdr->max_nd, hdr->max_len);
    printf("free: %d\n", hdr->free.len);

    for (i = 0; i < hdr->max_pub; i++) {
        cdipc_pub_t *pub = ch->pubs + i;
        printf("pub %d: cur: %d, ans: %d\n", pub->id,
                pub->cur ? pub->cur->id : -1, pub->ans ? pub->ans->id : -1);
    }

    for (i = 0; i < hdr->max_sub; i++) {
        cdipc_sub_t *sub = ch->subs + i;
        printf("sub %d: cur: %d, pend: %d\n", sub->id,
                sub->cur ? sub->cur->id : -1, sub->pend.len);
    }

    pthread_mutex_unlock(&hdr->mutex);
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
        if (0 == strcmp(argv[1], "ret")) {
            return cmd_ret(argc - 1, &argv[1]);
        }
        if (0 == strcmp(argv[1], "dump")) {
            return cmd_dump(argc - 1, &argv[1]);
        }
    }

    printf("Usage: cdipc [create|unlink|put|get|ret|dump] ...\n");
    return -1;
}

