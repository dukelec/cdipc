
#define CLOCK_MONOTONIC 1

int clock_gettime(int __clock_id, struct timespec *__tp);


typedef struct {
    int     size;
    char    *data;
} swig_string_data_t;


static uint8_t *buf_offset(uint8_t *base, int offset)
{
    return base + offset;
}

static swig_string_data_t buf_read(uint8_t *data, int size)
{
    swig_string_data_t sdata = { 0 };
    sdata.size = size;
    sdata.data = data;
    return sdata;
}

static void *buf_write(uint8_t *to, char *data, int size)
{
    return memcpy(to, data, size);
}
