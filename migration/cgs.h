#ifndef QEMU_MIGRATION_CGS_H
#define QEMU_MIGRATION_CGS_H

#include "qemu/osdep.h"

typedef struct CgsDataChannel {
    void *buf;
    uint32_t buf_size;
} CgsDataChannel;

extern CgsDataChannel cgs_data_channel;

int cgs_mig_init(void);

void cgs_mig_cleanup(void);

#endif
