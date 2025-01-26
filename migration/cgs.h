#ifndef QEMU_MIGRATION_CGS_H
#define QEMU_MIGRATION_CGS_H

#include "qemu/osdep.h"
#include "exec/hwaddr.h"

typedef struct CgsDataChannel {
    void *buf;
    uint32_t buf_size;
} CgsDataChannel;

extern CgsDataChannel cgs_data_channel;

int cgs_mig_init(void);

void cgs_mig_cleanup(void);

int cgs_mig_start(int data_size);

int cgs_mig_get_memory_state(hwaddr cgs_private_gpa, uint16_t gfn_num);

#endif
