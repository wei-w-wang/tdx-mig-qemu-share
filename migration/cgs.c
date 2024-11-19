#include "cgs.h"
#include "sysemu/kvm.h"
#include "qemu/error-report.h"
#include "qemu/memalign.h"
#include "hw/boards.h"

CgsDataChannel cgs_data_channel;

/* The default memory migration sends 1 page only each time */
uint32_t cgs_mig_batch_memory_pages = 1;

int cgs_mig_init(void)
{
    int ret;
    struct kvm_cap_cgm cap_cgm = {
        .nr_ubuf_pages = cgs_mig_batch_memory_pages,
        .nr_threads = 1,
    };

    if (!current_machine->cgs) {
        return 0;
    }

    ret = kvm_check_extension(kvm_state, KVM_CAP_CGM);
    if (ret != KVM_CGM_UAPI_VERSION) {
        error_report("KVM_CAP_CGM check failed");
        return -EINVAL;
    }

    ret = kvm_vm_enable_cap(kvm_state, KVM_CAP_CGM, 0,
                            (uint64_t)(&cap_cgm));
    if (ret < 0) {
        error_report("KVM_CAP_CGM enable failed");
        return ret;
    }

    cgs_data_channel.buf_size = cap_cgm.nr_ubuf_pages * TARGET_PAGE_SIZE;
    cgs_data_channel.buf = qemu_memalign(TARGET_PAGE_SIZE,
                                         cgs_data_channel.buf_size);
    if ((uintptr_t)cgs_data_channel.buf & (TARGET_PAGE_SIZE - 1)) {
        error_report("unexpected: cgs_data_channel.buf=%lx",
                      (uint64_t)cgs_data_channel.buf);
        return -EINVAL;
    }

    return 0;
}

void cgs_mig_cleanup(void)
{
    if (!current_machine->cgs)
        return;

    g_free(cgs_data_channel.buf);
}

int cgs_mig_start(int data_size)
{
    struct kvm_cgm_data data = {
        .uaddr = (uint64_t)cgs_data_channel.buf,
        .size = data_size,
    };
    int ret;

    ret = kvm_vm_ioctl(kvm_state, KVM_CGM_START, &data);
    if (ret < 0) {
        return ret;
    }

    return (int)data.size;
}

int cgs_mig_get_memory_state(hwaddr cgs_private_gpa, uint16_t gfn_num)
{
    struct kvm_cgm_memory_state state = { 0 };
    hwaddr gfn = cgs_private_gpa >> TARGET_PAGE_BITS;
    int ret;

    state.gfns_uaddr = (unsigned long)&gfn;
    state.gfn_num = gfn_num;
    state.data.uaddr = (unsigned long)cgs_data_channel.buf;
    ret = kvm_vm_ioctl(kvm_state, KVM_CGM_GET_MEMORY_STATE, &state);
    if (ret < 0) {
        return ret;
    }

    return state.data.size;
}

int cgs_mig_set_memory_state(uint64_t data_size, hwaddr gfn, uint16_t gfn_num)
{
    struct kvm_cgm_memory_state state = { 0 };

    state.gfns_uaddr = (unsigned long)&gfn;
    state.gfn_num = gfn_num;
    state.data.uaddr = (unsigned long)cgs_data_channel.buf;
    state.data.size = data_size;

    return kvm_vm_ioctl(kvm_state, KVM_CGM_SET_MEMORY_STATE, &state);
}

/* Return number of bytes sent or the error value (< 0) */
int cgs_mig_get_epoch_token(void)
{
    int ret;

    struct kvm_cgm_data data = {
        .uaddr = (uint64_t)cgs_data_channel.buf,
        .size = 0,
    };

    ret = kvm_vm_ioctl(kvm_state, KVM_CGM_GET_EPOCH_TOKEN, &data);
    if (ret < 0) {
        return ret;
    }

    return (int)data.size;
}

int cgs_mig_set_epoch_token(uint64_t data_size)
{
    struct kvm_cgm_data data = {
        .uaddr = (uint64_t)cgs_data_channel.buf,
        .size = data_size,
    };

    return kvm_vm_ioctl(kvm_state, KVM_CGM_SET_EPOCH_TOKEN, &data);
}

int cgs_mig_get_vcpu_state(CPUState *cpu)
{
    int ret;

    struct kvm_cgm_data data = {
        .uaddr = (uint64_t)cgs_data_channel.buf,
        .size = 0,
    };

    ret = kvm_vcpu_ioctl(cpu, KVM_CGM_GET_VCPU_STATE, &data);
    if (ret < 0) {
        return ret;
    }

    return (int)data.size;
}

int cgs_mig_set_vcpu_state(CPUState *cpu, uint32_t data_size)
{
    struct kvm_cgm_data data = {
        .uaddr = (uint64_t)cgs_data_channel.buf,
        .size = data_size,
    };

    return kvm_vcpu_ioctl(cpu, KVM_CGM_SET_VCPU_STATE, &data);
}
