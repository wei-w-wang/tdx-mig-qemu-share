/*
 * QEMU TDX support
 *
 * Copyright Intel
 *
 * Author:
 *      Xiaoyao Li <xiaoyao.li@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory
 *
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/base64.h"
#include "qemu/mmap-alloc.h"
#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "sysemu/runstate.h"
#include "sysemu/sysemu.h"
#include "exec/ramblock.h"

#include <linux/kvm_para.h>

#include "cpu.h"
#include "cpu-internal.h"
#include "host-cpu.h"
#include "hw/i386/e820_memory_layout.h"
#include "hw/i386/x86.h"
#include "hw/i386/tdvf.h"
#include "hw/i386/x86.h"
#include "hw/i386/tdvf-hob.h"
#include "kvm_i386.h"
#include "tdx.h"
#include "migration/migration.h"
#include "migration/misc.h"
#include "migration/cgs.h"

#include "standard-headers/asm-x86/kvm_para.h"

#define TDX_MIN_TSC_FREQUENCY_KHZ   (100 * 1000)
#define TDX_MAX_TSC_FREQUENCY_KHZ   (10 * 1000 * 1000)

#define TDX_TD_ATTRIBUTES_DEBUG             BIT_ULL(0)
#define TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE   BIT_ULL(28)
#define TDX_TD_ATTRIBUTES_MIG               BIT_ULL(29)
#define TDX_TD_ATTRIBUTES_PKS               BIT_ULL(30)
#define TDX_TD_ATTRIBUTES_PERFMON           BIT_ULL(63)

#define SHA384_DIGEST_SIZE  48
#define MIGTD_HASH_STRING_OFFSET 12
#define MIGTD_HASH_STRING_LEN 128

#define TDX_SUPPORTED_KVM_FEATURES  ((1U << KVM_FEATURE_NOP_IO_DELAY) | \
                                     (1U << KVM_FEATURE_PV_UNHALT) | \
                                     (1U << KVM_FEATURE_PV_TLB_FLUSH) | \
                                     (1U << KVM_FEATURE_PV_SEND_IPI) | \
                                     (1U << KVM_FEATURE_POLL_CONTROL) | \
                                     (1U << KVM_FEATURE_PV_SCHED_YIELD) | \
                                     (1U << KVM_FEATURE_MSI_EXT_DEST_ID))

static TdxGuest *tdx_guest;

static struct kvm_tdx_capabilities *tdx_caps;

/* Valid after kvm_arch_init()->confidential_guest_kvm_init()->tdx_kvm_init() */
bool is_tdx_vm(void)
{
    return !!tdx_guest;
}

enum tdx_ioctl_level {
    TDX_VM_IOCTL,
    TDX_VCPU_IOCTL,
};

static int tdx_ioctl_internal(enum tdx_ioctl_level level, void *state,
                              int cmd_id, __u32 flags, void *data)
{
    struct kvm_tdx_cmd tdx_cmd = {};
    int r;

    tdx_cmd.id = cmd_id;
    tdx_cmd.flags = flags;
    tdx_cmd.data = (__u64)(unsigned long)data;

    switch (level) {
    case TDX_VM_IOCTL:
        r = kvm_vm_ioctl(kvm_state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
        break;
    case TDX_VCPU_IOCTL:
        r = kvm_vcpu_ioctl(state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
        break;
    default:
        error_report("Invalid tdx_ioctl_level %d", level);
        exit(1);
    }

    if (r && tdx_cmd.hw_error) {
        error_report("TDX ioctl %d return with %d, hw_errors: 0x%llx",
                     cmd_id, r, tdx_cmd.hw_error);
    }
    return r;
}

static inline int tdx_vm_ioctl(int cmd_id, __u32 flags, void *data)
{
    return tdx_ioctl_internal(TDX_VM_IOCTL, NULL, cmd_id, flags, data);
}

static inline int tdx_vcpu_ioctl(CPUState *cpu, int cmd_id, __u32 flags,
                                 void *data)
{
    return  tdx_ioctl_internal(TDX_VCPU_IOCTL, cpu, cmd_id, flags, data);
}

static int get_tdx_capabilities(Error **errp)
{
    struct kvm_tdx_capabilities *caps;
    /* 1st generation of TDX reports 6 cpuid configs */
    int nr_cpuid_configs = 6;
    size_t size;
    int r;

    do {
        size = sizeof(struct kvm_tdx_capabilities) +
                      nr_cpuid_configs * sizeof(struct kvm_cpuid_entry2);
        caps = g_malloc0(size);
        caps->cpuid.nent = nr_cpuid_configs;

        r = tdx_vm_ioctl(KVM_TDX_CAPABILITIES, 0, caps);
        if (r == -E2BIG) {
            g_free(caps);
            nr_cpuid_configs *= 2;
            if (nr_cpuid_configs > KVM_MAX_CPUID_ENTRIES) {
                error_setg(errp, "%s: KVM TDX seems broken that number of CPUID"
                           " entries in kvm_tdx_capabilities exceeds limit %d",
                           __func__, KVM_MAX_CPUID_ENTRIES);
                return r;
            }
        } else if (r < 0) {
            g_free(caps);
            error_setg_errno(errp, -r, "%s: KVM_TDX_CAPABILITIES failed", __func__);
            return r;
        }
    } while (r == -E2BIG);

    tdx_caps = caps;

    return 0;
}

void tdx_set_tdvf_region(MemoryRegion *tdvf_mr)
{
    assert(!tdx_guest->tdvf_mr);
    tdx_guest->tdvf_mr = tdvf_mr;
}

static TdxFirmwareEntry *tdx_get_hob_entry(TdxGuest *tdx)
{
    TdxFirmwareEntry *entry;

    for_each_tdx_fw_entry(&tdx->tdvf, entry) {
        if (entry->type == TDVF_SECTION_TYPE_TD_HOB) {
            return entry;
        }
    }

    return NULL;
}

static void tdx_add_ram_entry(uint64_t address, uint64_t length,
                              enum TdxRamType type)
{
    uint32_t nr_entries = tdx_guest->nr_ram_entries;
    tdx_guest->ram_entries = g_renew(TdxRamEntry, tdx_guest->ram_entries,
                                     nr_entries + 1);

    tdx_guest->ram_entries[nr_entries].address = address;
    tdx_guest->ram_entries[nr_entries].length = length;
    tdx_guest->ram_entries[nr_entries].type = type;
    tdx_guest->nr_ram_entries++;
}

static TdxRamEntry *tdx_find_ram_range(uint64_t address, uint64_t length)
{
    TdxRamEntry *e;
    int i;

    for (i = 0; i < tdx_guest->nr_ram_entries; i++) {
        e = &tdx_guest->ram_entries[i];

        if (address + length <= e->address ||
            e->address + e->length <= address) {
            continue;
        }

        /*
         * The to-be-accepted ram range must be fully contained by one
         * RAM entry.
         */
        if (e->address > address ||
            e->address + e->length < address + length) {
            return NULL;
        }

        if (e->type == TDX_RAM_ADDED) {
            return NULL;
        }

        break;
    }

    if (i == tdx_guest->nr_ram_entries) {
        return NULL;
    }

    return e;
}

static int tdx_accept_ram_range(uint64_t address, uint64_t length)
{
    uint64_t head_start, tail_start, head_length, tail_length;
    uint64_t tmp_address, tmp_length;
    TdxRamEntry *e;

    e = tdx_find_ram_range(address, length);
    if (!e) {
        return -EINVAL;
    }

    tmp_address = e->address;
    tmp_length = e->length;

    e->address = address;
    e->length = length;
    e->type = TDX_RAM_ADDED;

    head_length = address - tmp_address;
    if (head_length > 0) {
        head_start = tmp_address;
        tdx_add_ram_entry(head_start, head_length, TDX_RAM_UNACCEPTED);
    }

    tail_start = address + length;
    if (tail_start < tmp_address + tmp_length) {
        tail_length = tmp_address + tmp_length - tail_start;
        tdx_add_ram_entry(tail_start, tail_length, TDX_RAM_UNACCEPTED);
    }

    return 0;
}

static int tdx_ram_entry_compare(const void *lhs_, const void* rhs_)
{
    const TdxRamEntry *lhs = lhs_;
    const TdxRamEntry *rhs = rhs_;

    if (lhs->address == rhs->address) {
        return 0;
    }
    if (le64_to_cpu(lhs->address) > le64_to_cpu(rhs->address)) {
        return 1;
    }
    return -1;
}

static void tdx_init_ram_entries(void)
{
    unsigned i, j, nr_e820_entries;

    nr_e820_entries = e820_get_table(NULL);
    tdx_guest->ram_entries = g_new(TdxRamEntry, nr_e820_entries);

    for (i = 0, j = 0; i < nr_e820_entries; i++) {
        uint64_t addr, len;

        if (e820_get_entry(i, E820_RAM, &addr, &len)) {
            tdx_guest->ram_entries[j].address = addr;
            tdx_guest->ram_entries[j].length = len;
            tdx_guest->ram_entries[j].type = TDX_RAM_UNACCEPTED;
            j++;
        }
    }
    tdx_guest->nr_ram_entries = j;
}

static void tdx_post_init_vcpus(void)
{
    TdxFirmwareEntry *hob;
    void *hob_addr = NULL;
    CPUState *cpu;
    int r;

    hob = tdx_get_hob_entry(tdx_guest);
    if (hob) {
        hob_addr = (void *)hob->address;
    }

    CPU_FOREACH(cpu) {
        r = tdx_vcpu_ioctl(cpu, KVM_TDX_INIT_VCPU, 0, hob_addr);
        if (r < 0) {
            error_report("KVM_TDX_INIT_VCPU failed %s", strerror(-r));
            exit(1);
        }
    }
}

static void tdx_run_migtd(char *uri)
{
    char migtd_name[17] = {0};
    char *args[4];

    sprintf(migtd_name, "migtd-%d", kvm_get_vm_pid());

    args[0] = tdx_guest->migtd_setup_path;
    args[1] = migtd_name;
    args[2] = uri;
    args[3] = NULL;
    execv(tdx_guest->migtd_setup_path, args);
    _exit(EXIT_SUCCESS);
}

static void child_cleanup(int sig)
{
    int status;

    RETRY_ON_EINTR(waitpid(-1, &status, 0));
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        error_report("The MigTD process terminated abnormally");
    }
}

static void tdx_launch_migration_assistant(Error **errp)
{
    pid_t pid;
    SocketAddress saddr;

    signal(SIGCHLD, child_cleanup);
    migration_get_socket_addr(&saddr);

    pid = fork();
    if (pid < 0) {
        error_setg(errp, "Failed to fork for MigTD");
    }

    if (!pid) {
        tdx_run_migtd(saddr.u.inet.host);
    }
}

static int tdx_migration_state_notifier(NotifierWithReturn *notifier,
                                        MigrationEvent *e, Error **errp)
{
    if (e->type == MIG_EVENT_PRECOPY_SETUP) {
        tdx_launch_migration_assistant(errp);
    }

    return 0;
}

static int tdx_migration_do_prepare(bool is_src)
{
    char pgrep_cmd[32] = {0};
    char migtd_pid_str[32] = {0};
    pid_t migtd_pid;
    struct kvm_cgm_prepare prepare;
    int ret;
    FILE *cmd_pipe;

    sprintf(pgrep_cmd, "pgrep migtd-%d", kvm_get_vm_pid());
    cmd_pipe = popen(pgrep_cmd, "r");

    fgets(migtd_pid_str, 32, cmd_pipe);
    migtd_pid = atoi(migtd_pid_str);
    ret = pclose(cmd_pipe);
    if (ret < 0) {
        error_report("migration prepare: pclose failed %s", strerror(-ret));
        return -EACCES;
    }

    prepare.is_src = is_src;
    prepare.vmid.type = KVM_VM_ID_TYPE_PID;
    prepare.vmid.pid = migtd_pid;

    return kvm_vm_ioctl(kvm_state, KVM_CGM_PREPARE, &prepare);
}

static int tdx_migration_prepare(bool is_src)
{
    int ret, max_tries = 10;

    do {
        ret = tdx_migration_do_prepare(is_src);
        if (ret == -ENOENT) {
            usleep(10000);
        }
    } while (ret == -ENOENT && max_tries--);

    if (ret < 0) {
        error_report("migration prepare uAPI failed %s", strerror(-ret));
    }

    return ret;
}

static void tdx_finalize_vm(Notifier *notifier, void *unused)
{
    struct ConfidentialGuestSupport *cgs = CONFIDENTIAL_GUEST_SUPPORT(tdx_guest);
    TdxFirmware *tdvf = &tdx_guest->tdvf;
    TdxFirmwareEntry *entry;
    RAMBlock *ram_block;
    int r;

    if (tdx_guest->attributes & TDX_TD_ATTRIBUTES_MIG) {
        cgs->migration_prepare = tdx_migration_prepare;
        migration_add_notifier(&tdx_guest->migration_state_notifier,
                               tdx_migration_state_notifier);
    }

    tdx_init_ram_entries();

    for_each_tdx_fw_entry(tdvf, entry) {
        switch (entry->type) {
        case TDVF_SECTION_TYPE_BFV:
        case TDVF_SECTION_TYPE_CFV:
        case TDVF_SECTION_TYPE_PAYLOAD:
            entry->mem_ptr = tdvf->mem_ptr + entry->data_offset;
            break;
        case TDVF_SECTION_TYPE_TD_HOB:
        case TDVF_SECTION_TYPE_TEMP_MEM:
            entry->mem_ptr = qemu_ram_mmap(-1, entry->size,
                                           qemu_real_host_page_size(), 0, 0);
            tdx_accept_ram_range(entry->address, entry->size);
            break;
        /* PERM_MEM is allocated and added later via PAGE.AUG */
        case TDVF_SECTION_TYPE_PERM_MEM:
            if (!tdx_find_ram_range(entry->address, entry->size)) {
                error_report("Failed to reserve ram for TDVF section %d",
                             entry->type);
                exit(1);
            }
            break;
        default:
            error_report("Unsupported TDVF section %d", entry->type);
            exit(1);
        }
    }

    qsort(tdx_guest->ram_entries, tdx_guest->nr_ram_entries,
          sizeof(TdxRamEntry), &tdx_ram_entry_compare);

    tdvf_hob_create(tdx_guest, tdx_get_hob_entry(tdx_guest));

    tdx_post_init_vcpus();

    /*
     * Don't finalize for the migration destination TD.
     * It will be finalzed after all the TD states successfully imported.
     */
    if (runstate_check(RUN_STATE_INMIGRATE)) {
        return;
    }

    for_each_tdx_fw_entry(tdvf, entry) {
        struct kvm_tdx_init_mem_region region;
        uint32_t flags;

        if (entry->type == TDVF_SECTION_TYPE_PERM_MEM) {
            continue;
        }

        region = (struct kvm_tdx_init_mem_region) {
            .source_addr = (uint64_t)entry->mem_ptr,
            .gpa = entry->address,
            .nr_pages = entry->size >> 12,
        };

        flags = entry->attributes & TDVF_SECTION_ATTRIBUTES_MR_EXTEND ?
                KVM_TDX_MEASURE_MEMORY_REGION : 0;

        do {
            if (kvm_gmem_default_shared) {
                r = kvm_convert_memory(entry->address,
                                       entry->size, true, false);
                if (r < 0) {
                    error_report("Populate initial private memory failed %s",
                                 strerror(-r));
                    exit(1);
                }
            }

            r = tdx_vcpu_ioctl(first_cpu, KVM_TDX_INIT_MEM_REGION, flags,
                               &region);
        } while (r == -EAGAIN || r == -EINTR);
        if (r < 0) {
            error_report("KVM_TDX_INIT_MEM_REGION failed %s", strerror(-r));
            exit(1);
        }

        if (entry->type == TDVF_SECTION_TYPE_TD_HOB ||
            entry->type == TDVF_SECTION_TYPE_TEMP_MEM) {
            qemu_ram_munmap(-1, entry->mem_ptr, entry->size);
            entry->mem_ptr = NULL;
        }
    }

    /*
     * TDVF image has been copied into private region above via
     * KVM_MEMORY_MAPPING. It becomes useless.
     */
    ram_block = tdx_guest->tdvf_mr->ram_block;
    ram_block_discard_range(ram_block, 0, ram_block->max_length);

    r = tdx_vm_ioctl(KVM_TDX_FINALIZE_VM, 0, NULL);
    if (r < 0) {
        error_report("KVM_TDX_FINALIZE_VM failed %s", strerror(-r));
        exit(0);
    }
    cgs->ready = true;
}

static Notifier tdx_machine_done_notify = {
    .notify = tdx_finalize_vm,
};

static int tdx_kvm_init(ConfidentialGuestSupport *cgs, Error **errp)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    X86MachineState *x86ms = X86_MACHINE(ms);
    TdxGuest *tdx = TDX_GUEST(cgs);
    int r = 0;

    kvm_mark_guest_state_protected();

    if (x86ms->smm == ON_OFF_AUTO_AUTO) {
        x86ms->smm = ON_OFF_AUTO_OFF;
    } else if (x86ms->smm == ON_OFF_AUTO_ON) {
        error_setg(errp, "TDX VM doesn't support SMM");
        return -EINVAL;
    }

    if (x86ms->pic == ON_OFF_AUTO_AUTO) {
        x86ms->pic = ON_OFF_AUTO_OFF;
    } else if (x86ms->pic == ON_OFF_AUTO_ON) {
        error_setg(errp, "TDX VM doesn't support PIC");
        return -EINVAL;
    }

    if (!tdx_caps) {
        r = get_tdx_capabilities(errp);
        if (r) {
            return r;
        }
    }

    /* TDX relies on KVM_HC_MAP_GPA_RANGE to handle TDG.VP.VMCALL<MapGPA> */
    if (!kvm_enable_hypercall(BIT_ULL(KVM_HC_MAP_GPA_RANGE))) {
        return -EOPNOTSUPP;
    }

    x86ms->eoi_intercept_unsupported = true;

    /*
     * Set kvm_readonly_mem_allowed to false, because TDX only supports readonly
     * memory for shared memory but not for private memory. Besides, whether a
     * memslot is private or shared is not determined by QEMU.
     *
     * Thus, just mark readonly memory not supported for simplicity.
     */
    kvm_readonly_mem_allowed = false;

    qemu_add_machine_init_done_notifier(&tdx_machine_done_notify);

    tdx_guest = tdx;
    return 0;
}

static int tdx_kvm_type(X86ConfidentialGuest *cg)
{
    /* Do the object check */
    TDX_GUEST(cg);

    return KVM_X86_TDX_VM;
}

static void tdx_cpu_instance_init(X86ConfidentialGuest *cg, CPUState *cpu)
{
    X86CPU *x86cpu = X86_CPU(cpu);

    object_property_set_bool(OBJECT(cpu), "pmu", false, &error_abort);

    /* invtsc is fixed1 for TD guest */
    object_property_set_bool(OBJECT(cpu), "invtsc", true, &error_abort);

    x86cpu->enable_cpuid_0x1f = true;
}

static void tdx_cpu_realizefn(X86ConfidentialGuest *cg, CPUState *cs,
                              Error **errp)
{
    X86CPU *cpu = X86_CPU(cs);
    uint32_t host_phys_bits = host_cpu_phys_bits();

    if (!cpu->phys_bits) {
        cpu->phys_bits = host_phys_bits;
    } else if (cpu->phys_bits != host_phys_bits) {
        error_setg(errp, "TDX only supports host physical bits (%u)",
                   host_phys_bits);
    }
}

/*
 * Fixed0 and Fixed1 bits info are grabbed from TDX 1.5.06 spec.
 */
KvmCpuidInfo tdx_fixed0_bits = {
    .cpuid.nent = 3,
    .entries[0] = {
        .function = 0x1,
        .index = 0x0,
        .ecx = CPUID_EXT_VMX | CPUID_EXT_SMX,
        .edx = CPUID_PSE36 | CPUID_IA64,
    },
    .entries[1] = {
        .function = 0x7,
        .index = 0x0,
        .flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX,
        .ebx = CPUID_7_0_EBX_TSC_ADJUST | CPUID_7_0_EBX_SGX |
               CPUID_7_0_EBX_PCOMMIT,
        .ecx = CPUID_7_0_ECX_SGX_LC | (1U << 15) | (0x1fU << 17) | (1U << 26) |
               (1U << 29),
        .edx = (1U << 0) | (1U << 1) | (1U << 7) | (1U << 9) | (1U << 11) |
               (1U << 12) | (1U << 13) | (1U << 15) | (1U << 17) | (1U << 21),
    },
    .entries[2] = {
        .function = 0x80000001,
        .index = 0x0,
        .ecx = 0xFFFFFEDE,
        .edx = 0xD3EFF7FF,
    },
};

KvmCpuidInfo tdx_fixed1_bits = {
    .cpuid.nent = 6,
    .entries[0] = {
        .function = 0x1,
        .index = 0,
        .ecx = CPUID_EXT_SSE3 | CPUID_EXT_PCLMULQDQ | CPUID_EXT_DTES64 |
               CPUID_EXT_DSCPL | CPUID_EXT_SSE3 | CPUID_EXT_CX16 |
               CPUID_EXT_PDCM | CPUID_EXT_PCID | CPUID_EXT_SSE41 |
               CPUID_EXT_SSE42 | CPUID_EXT_X2APIC | CPUID_EXT_MOVBE |
               CPUID_EXT_POPCNT | CPUID_EXT_AES | CPUID_EXT_XSAVE |
               CPUID_EXT_RDRAND | CPUID_EXT_HYPERVISOR,
        .edx = CPUID_FP87 | CPUID_VME | CPUID_DE | CPUID_PSE | CPUID_TSC |
               CPUID_MSR | CPUID_PAE | CPUID_MCE | CPUID_CX8 | CPUID_APIC |
               CPUID_SEP | CPUID_MTRR | CPUID_PGE | CPUID_MCA | CPUID_CMOV |
               CPUID_PAT | CPUID_CLFLUSH | CPUID_DTS | CPUID_MMX | CPUID_FXSR |
               CPUID_SSE | CPUID_SSE2,
    },
    .entries[1] = {
        .function = 0x6,
        .index = 0,
        .eax = CPUID_6_EAX_ARAT,
    },
    .entries[2] = {
        .function = 0x7,
        .index = 0,
        .flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX,
        .ebx = CPUID_7_0_EBX_FSGSBASE | CPUID_7_0_EBX_FDP_EXCPTN_ONLY |
               CPUID_7_0_EBX_SMEP | CPUID_7_0_EBX_INVPCID |
               CPUID_7_0_EBX_ZERO_FCS_FDS | CPUID_7_0_EBX_RDSEED |
               CPUID_7_0_EBX_SMAP | CPUID_7_0_EBX_CLFLUSHOPT |
               CPUID_7_0_EBX_CLWB | CPUID_7_0_EBX_SHA_NI,
        .ecx = CPUID_7_0_ECX_BUS_LOCK_DETECT | CPUID_7_0_ECX_MOVDIRI |
               CPUID_7_0_ECX_MOVDIR64B,
        .edx = (1U << 10) | CPUID_7_0_EDX_SPEC_CTRL | CPUID_7_0_EDX_STIBP |
               CPUID_7_0_EDX_FLUSH_L1D | CPUID_7_0_EDX_ARCH_CAPABILITIES |
               CPUID_7_0_EDX_CORE_CAPABILITY | CPUID_7_0_EDX_SPEC_CTRL_SSBD,
    },
    .entries[3] = {
        .function = 0x7,
        .index = 2,
        .flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX,
        .edx = (1U << 0) | (1U << 1) | (1U << 2) | (1U << 4),
    },
    .entries[4] = {
        .function = 0x80000001,
        .index = 0,
        .ecx = CPUID_EXT3_LAHF_LM | CPUID_EXT3_ABM | CPUID_EXT3_3DNOWPREFETCH,
        .edx = CPUID_EXT2_NX | CPUID_EXT2_PDPE1GB | CPUID_EXT2_RDTSCP |
               CPUID_EXT2_LM,
    },
    .entries[5] = {
        .function = 0x80000007,
        .index = 0,
        .edx = CPUID_APM_INVTSC,
    },
};

typedef struct TdxAttrsMap {
    uint32_t attr_index;
    uint32_t cpuid_leaf;
    uint32_t cpuid_subleaf;
    int cpuid_reg;
    uint32_t feat_mask;
} TdxAttrsMap;

static TdxAttrsMap tdx_attrs_maps[] = {
    {.attr_index = 27,
     .cpuid_leaf = 7,
     .cpuid_subleaf = 1,
     .cpuid_reg = R_EAX,
     .feat_mask = CPUID_7_1_EAX_LASS},
    {.attr_index = 30,
     .cpuid_leaf = 7,
     .cpuid_subleaf = 0,
     .cpuid_reg = R_ECX,
     .feat_mask = CPUID_7_0_ECX_PKS,},
    {.attr_index = 31,
     .cpuid_leaf = 7,
     .cpuid_subleaf = 0,
     .cpuid_reg = R_ECX,
     .feat_mask = CPUID_7_0_ECX_KeyLocker,
    },
};

static void tdx_mask_cpuid_by_attrs(uint32_t feature, uint32_t index,
                                    int reg, uint32_t *value)
{
    TdxAttrsMap *map;
    uint64_t unavail = 0;
    int i;

    for (i = 0; i < ARRAY_SIZE(tdx_attrs_maps); i++) {
        map = &tdx_attrs_maps[i];

        if (feature != map->cpuid_leaf || index != map->cpuid_subleaf ||
            reg != map->cpuid_reg) {
            continue;
        }

        if (!((1ULL << map->attr_index) & tdx_caps->supported_attrs)) {
            unavail |= map->feat_mask;
        }
    }

    if (unavail) {
        *value &= ~unavail;
    }
}

static void tdx_mask_cpuid_by_xfam(uint32_t feature, uint32_t index,
                                          int reg, uint32_t *value)
{
    const FeatureWordInfo *f;
    const ExtSaveArea *esa;
    uint64_t unavail = 0;
    int i;

    assert(tdx_caps);

    for (i = 0; i < ARRAY_SIZE(x86_ext_save_areas); i++) {
        if ((1ULL << i) & tdx_caps->supported_xfam) {
            continue;
        }

        if (!((1ULL << i) & CPUID_XSTATE_MASK)) {
            continue;
        }

        esa = &x86_ext_save_areas[i];
        f = &feature_word_info[esa->feature];
        assert(f->type == CPUID_FEATURE_WORD);
        if (f->cpuid.eax != feature ||
            (f->cpuid.needs_ecx && f->cpuid.ecx != index) ||
            f->cpuid.reg != reg) {
            continue;
        }

        unavail |= esa->bits;
    }

    if (unavail) {
        *value &= ~unavail;
    }
}

static uint32_t tdx_adjust_cpuid_features(X86ConfidentialGuest *cg,
                                          uint32_t feature, uint32_t index,
                                          int reg, uint32_t value)
{
    struct kvm_cpuid_entry2 *e;
    uint32_t fixed0, fixed1;

    switch (feature) {
    case 0x7:
        if (index == 0 && reg == R_EBX) {
            /* QEMU Intel PT support is broken */
            value &= ~CPUID_7_0_EBX_INTEL_PT;
        }
        break;
    case 0x40000001:
        if (reg == R_EAX) {
            value &= TDX_SUPPORTED_KVM_FEATURES;
        }
        break;
    case 0x80000001:
        if (reg == R_EDX) {
            value &= ~CPUID_EXT2_AMD_ALIASES;
        }
        break;
    case 0x80000008:
        if (reg == R_EBX) {
            value &= CPUID_8000_0008_EBX_WBNOINVD;
        }
        break;
    default:
        break;
    }

    tdx_mask_cpuid_by_attrs(feature, index, reg, &value);
    tdx_mask_cpuid_by_xfam(feature, index, reg, &value);

    e = cpuid_find_entry(&tdx_fixed0_bits.cpuid, feature, index);
    if (e) {
        fixed0 = cpuid_entry_get_reg(e, reg);
        value &= ~fixed0;
    }

    e = cpuid_find_entry(&tdx_fixed1_bits.cpuid, feature, index);
    if (e) {
        fixed1 = cpuid_entry_get_reg(e, reg);
        value |= fixed1;
    }

    return value;
}


static void tdx_fetch_cpuid(CPUState *cpu, struct kvm_cpuid2 *fetch_cpuid)
{
    int r;

    r = tdx_vcpu_ioctl(cpu, KVM_TDX_GET_CPUID, 0, fetch_cpuid);
    if (r) {
        error_report("KVM_TDX_GET_CPUID failed %s", strerror(-r));
        exit(1);
    }
}

static int tdx_check_features(X86ConfidentialGuest *cg, CPUState *cs)
{
    uint64_t actual, requested, unavailable, forced_on;
    g_autofree struct kvm_cpuid2 *fetch_cpuid;
    const char *forced_on_prefix = NULL;
    const char *unav_prefix = NULL;
    struct kvm_cpuid_entry2 *entry;
    X86CPU *cpu = X86_CPU(cs);
    CPUX86State *env = &cpu->env;
    FeatureWordInfo *wi;
    FeatureWord w;
    bool mismatch = false;

    fetch_cpuid = g_malloc0(sizeof(*fetch_cpuid) +
                    sizeof(struct kvm_cpuid_entry2) * KVM_MAX_CPUID_ENTRIES);
    tdx_fetch_cpuid(cs, fetch_cpuid);

    if (cpu->check_cpuid || cpu->enforce_cpuid) {
        unav_prefix = "TDX doesn't support requested feature";
        forced_on_prefix = "TDX forcibly sets the feature";
    }

    for (w = 0; w < FEATURE_WORDS; w++) {
        wi = &feature_word_info[w];
        actual = 0;

        switch (wi->type) {
        case CPUID_FEATURE_WORD:
            entry = cpuid_find_entry(fetch_cpuid, wi->cpuid.eax, wi->cpuid.ecx);
            if (!entry) {
                /*
                 * If KVM doesn't report it means it's totally configurable
                 * by QEMU
                 */
                continue;
            }

            actual = cpuid_entry_get_reg(entry, wi->cpuid.reg);
            break;
        case MSR_FEATURE_WORD:
            /*
             * TODO:
             * validate MSR features when KVM has interface report them.
             */
            continue;
        }

        requested = env->features[w];
        unavailable = requested & ~actual;
        /*
         * Intel enumerates SYSCALL bit as 1 only when processor in 64-bit
         * mode and before vcpu running it's not in 64-bit mode.
         */
        if (w == FEAT_8000_0001_EDX && unavailable & CPUID_EXT2_SYSCALL) {
            unavailable &= ~CPUID_EXT2_SYSCALL;
        }
        mark_unavailable_features(cpu, w, unavailable, unav_prefix);
        if (unavailable) {
            mismatch = true;
        }

        forced_on = actual & ~requested;
        mark_forced_on_features(cpu, w, forced_on, forced_on_prefix);
        if (forced_on) {
            mismatch = true;
        }
    }

    if (cpu->enforce_cpuid && mismatch) {
        return -1;
    }

    return 0;
}

static int tdx_validate_attributes(TdxGuest *tdx, Error **errp)
{
    if ((tdx->attributes & ~tdx_caps->supported_attrs)) {
            error_setg(errp, "Invalid attributes 0x%lx for TDX VM "
                       "(supported: 0x%llx)",
                       tdx->attributes, tdx_caps->supported_attrs);
            return -1;
    }

    if (tdx->attributes & TDX_TD_ATTRIBUTES_DEBUG) {
        error_setg(errp, "Current QEMU doesn't support attributes.debug[bit 0] "
                         "for TDX VM");
        return -1;
    }

    return 0;
}

static int setup_td_guest_attributes(X86CPU *x86cpu, Error **errp)
{
    CPUX86State *env = &x86cpu->env;

    tdx_guest->attributes |= (env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_PKS) ?
                             TDX_TD_ATTRIBUTES_PKS : 0;
    tdx_guest->attributes |= x86cpu->enable_pmu ? TDX_TD_ATTRIBUTES_PERFMON : 0;

    return tdx_validate_attributes(tdx_guest, errp);
}

static int setup_td_xfam(X86CPU *x86cpu, Error **errp)
{
    CPUX86State *env = &x86cpu->env;
    uint64_t xfam;

    xfam = env->features[FEAT_XSAVE_XCR0_LO] |
           env->features[FEAT_XSAVE_XCR0_HI] |
           env->features[FEAT_XSAVE_XSS_LO] |
           env->features[FEAT_XSAVE_XSS_HI];

    if (xfam & ~tdx_caps->supported_xfam) {
        error_setg(errp, "Invalid XFAM 0x%lx for TDX VM (supported: 0x%llx))",
                   xfam, tdx_caps->supported_xfam);
        return -1;
    }

    tdx_guest->xfam = xfam;
    return 0;
}

static void tdx_filter_cpuid(struct kvm_cpuid2 *cpuids)
{
    int i, dest_cnt = 0;
    struct kvm_cpuid_entry2 *src, *dest, *conf;

    for (i = 0; i < cpuids->nent; i++) {
        src = cpuids->entries + i;
        conf = cpuid_find_entry(&tdx_caps->cpuid, src->function, src->index);
        if (!conf) {
            continue;
        }
        dest = cpuids->entries + dest_cnt;

        dest->function = src->function;
        dest->index = src->index;
        dest->flags = src->flags;
        dest->eax = src->eax & conf->eax;
        dest->ebx = src->ebx & conf->ebx;
        dest->ecx = src->ecx & conf->ecx;
        dest->edx = src->edx & conf->edx;

        dest_cnt++;
    }
    cpuids->nent = dest_cnt++;
}

static int tdx_prebind_migtd(void *migtd_hash, Error **errp)
{
    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    /* Base64 data needs to be NULL terminated, so add 1 more byte */
    char string[MIGTD_HASH_STRING_LEN + 1] = {0};
    g_autofree uint8_t *data;
    bool found = false;
    int i;

    fp = fopen(tdx_guest->migtd_setup_path, "r");
    if (!fp) {
        printf("failed to read the file\n");
    }

    while (getline(&line, &len, fp) != -1) {
        if (strstr(line, "MIGTD_HASH=")) {
            memcpy(string, line + MIGTD_HASH_STRING_OFFSET,
                   MIGTD_HASH_STRING_LEN);
	    found = true;
            break;
        }
    }
    if (!found) {
        error_setg(errp, "TDX: failed to find migtd hash in the setup script");
        return -1;
    }

    data = qbase64_decode(string, MIGTD_HASH_STRING_LEN , &len, errp);
    if (!data || len != SHA384_DIGEST_SIZE * 2) {
        error_setg(errp, "TDX: failed to decode migtd hash");
        return -1;
    }

    for (i = 0; i < SHA384_DIGEST_SIZE; i++) {
         if (sscanf((char *)data + i * 2, "%02hhx", (char *)migtd_hash + i) != 1) {
            error_setg(errp, "invalid format for migtd hash %s", string);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

int tdx_pre_create_vcpu(CPUState *cpu, Error **errp)
{
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    g_autofree struct kvm_tdx_init_vm *init_vm = NULL;
    uint32_t flags = 0;
    size_t data_len;
    int r = 0;

    QEMU_LOCK_GUARD(&tdx_guest->lock);
    if (tdx_guest->initialized) {
        return r;
    }

    init_vm = g_malloc0(sizeof(struct kvm_tdx_init_vm) +
                        sizeof(struct kvm_cpuid_entry2) * KVM_MAX_CPUID_ENTRIES);

    if (!kvm_check_extension(kvm_state, KVM_CAP_X86_APIC_BUS_CYCLES_NS)) {
        error_setg(errp, "KVM doesn't support KVM_CAP_X86_APIC_BUS_CYCLES_NS");
        return -EOPNOTSUPP;
    }

    if ((tdx_guest->attributes & TDX_TD_ATTRIBUTES_MIG) &&
        tdx_prebind_migtd((void *)init_vm->migtd_hash, errp)) {
        return -1;
    }

    r = kvm_vm_enable_cap(kvm_state, KVM_CAP_X86_APIC_BUS_CYCLES_NS,
                          0, TDX_APIC_BUS_CYCLES_NS);
    if (r < 0) {
        error_setg_errno(errp, -r,
                         "Unable to set core crystal clock frequency to 25MHz");
        return r;
    }

    if (env->tsc_khz && (env->tsc_khz < TDX_MIN_TSC_FREQUENCY_KHZ ||
                         env->tsc_khz > TDX_MAX_TSC_FREQUENCY_KHZ)) {
        error_setg(errp, "Invalid TSC %ld KHz, must specify cpu_frequency "
                         "between [%d, %d] kHz", env->tsc_khz,
                         TDX_MIN_TSC_FREQUENCY_KHZ, TDX_MAX_TSC_FREQUENCY_KHZ);
       return -EINVAL;
    }

    if (env->tsc_khz % (25 * 1000)) {
        error_setg(errp, "Invalid TSC %ld KHz, it must be multiple of 25MHz",
                   env->tsc_khz);
        return -EINVAL;
    }

    /* it's safe even env->tsc_khz is 0. KVM uses host's tsc_khz in this case */
    r = kvm_vm_ioctl(kvm_state, KVM_SET_TSC_KHZ, env->tsc_khz);
    if (r < 0) {
        error_setg_errno(errp, -r, "Unable to set TSC frequency to %ld kHz",
                         env->tsc_khz);
        return r;
    }

#define SHA384_DIGEST_SIZE  48
    if (tdx_guest->mrconfigid) {
        g_autofree uint8_t *data = qbase64_decode(tdx_guest->mrconfigid,
                              strlen(tdx_guest->mrconfigid), &data_len, errp);
        if (!data || data_len != SHA384_DIGEST_SIZE) {
            error_setg(errp, "TDX: failed to decode mrconfigid");
            return -1;
        }
        memcpy(init_vm->mrconfigid, data, data_len);
    }

    if (tdx_guest->mrowner) {
        g_autofree uint8_t *data = qbase64_decode(tdx_guest->mrowner,
                              strlen(tdx_guest->mrowner), &data_len, errp);
        if (!data || data_len != SHA384_DIGEST_SIZE) {
            error_setg(errp, "TDX: failed to decode mrowner");
            return -1;
        }
        memcpy(init_vm->mrowner, data, data_len);
    }

    if (tdx_guest->mrownerconfig) {
        g_autofree uint8_t *data = qbase64_decode(tdx_guest->mrownerconfig,
                            strlen(tdx_guest->mrownerconfig), &data_len, errp);
        if (!data || data_len != SHA384_DIGEST_SIZE) {
            error_setg(errp, "TDX: failed to decode mrownerconfig");
            return -1;
        }
        memcpy(init_vm->mrownerconfig, data, data_len);
    }

    r = setup_td_guest_attributes(x86cpu, errp);
    if (r) {
        return r;
    }

    r = setup_td_xfam(x86cpu, errp);
    if (r) {
        return r;
    }

    init_vm->cpuid.nent = kvm_x86_build_cpuid(env, init_vm->cpuid.entries, 0);
    tdx_filter_cpuid(&init_vm->cpuid);

    init_vm->attributes = tdx_guest->attributes;
    init_vm->xfam = tdx_guest->xfam;

    if (runstate_check(RUN_STATE_INMIGRATE)) {
        flags = KVM_TDX_INIT_VM_F_DELAY_INIT;
    }

    do {
        r = tdx_vm_ioctl(KVM_TDX_INIT_VM, flags, init_vm);
    } while (r == -EAGAIN);
    if (r < 0) {
        error_setg_errno(errp, -r, "KVM_TDX_INIT_VM failed");
        return r;
    }

    tdx_guest->initialized = true;

    return 0;
}

int tdx_parse_tdvf(void *flash_ptr, int size)
{
    return tdvf_parse_metadata(&tdx_guest->tdvf, flash_ptr, size);
}

static void tdx_panicked_on_fatal_error(X86CPU *cpu, uint64_t error_code,
                                        char *message, uint64_t gpa)
{
    GuestPanicInformation *panic_info;

    panic_info = g_new0(GuestPanicInformation, 1);
    panic_info->type = GUEST_PANIC_INFORMATION_TYPE_TDX;
    panic_info->u.tdx.error_code = (uint32_t) error_code;
    panic_info->u.tdx.message = message;
    panic_info->u.tdx.gpa = gpa;

    qemu_system_guest_panicked(panic_info);
}

int tdx_handle_report_fatal_error(X86CPU *cpu, struct kvm_run *run)
{
    uint64_t error_code = run->system_event.data[0];
    char *message = NULL;
    uint64_t gpa = -1ull;

    if (error_code & 0xffff) {
        error_report("TDX: REPORT_FATAL_ERROR: invalid error code: 0x%lx",
                     error_code);
        return -1;
    }

    /* It has optional message */
    if (run->system_event.data[2]) {
#define TDX_FATAL_MESSAGE_MAX        64
        message = g_malloc0(TDX_FATAL_MESSAGE_MAX + 1);

        memcpy(message, &run->system_event.data[2], TDX_FATAL_MESSAGE_MAX);
        message[TDX_FATAL_MESSAGE_MAX] = '\0';
    }

#define TDX_REPORT_FATAL_ERROR_GPA_VALID    BIT_ULL(63)
    if (error_code & TDX_REPORT_FATAL_ERROR_GPA_VALID) {
        gpa = run->system_event.data[1];
    }

    tdx_panicked_on_fatal_error(cpu, error_code, message, gpa);

    return -1;
}

static bool tdx_guest_get_sept_ve_disable(Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    return !!(tdx->attributes & TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE);
}

static void tdx_guest_set_sept_ve_disable(Object *obj, bool value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    if (value) {
        tdx->attributes |= TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE;
    } else {
        tdx->attributes &= ~TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE;
    }
}

static char *tdx_guest_get_mrconfigid(Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    return g_strdup(tdx->mrconfigid);
}

static void tdx_guest_set_mrconfigid(Object *obj, const char *value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    g_free(tdx->mrconfigid);
    tdx->mrconfigid = g_strdup(value);
}

static char *tdx_guest_get_mrowner(Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    return g_strdup(tdx->mrowner);
}

static void tdx_guest_set_mrowner(Object *obj, const char *value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    g_free(tdx->mrowner);
    tdx->mrowner = g_strdup(value);
}

static char *tdx_guest_get_mrownerconfig(Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    return g_strdup(tdx->mrownerconfig);
}

static void tdx_guest_set_mrownerconfig(Object *obj, const char *value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    g_free(tdx->mrownerconfig);
    tdx->mrownerconfig = g_strdup(value);
}

static char *tdx_guest_get_migtd_setup(Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    return g_strdup(tdx->migtd_setup_path);
}

static void tdx_guest_set_migtd_setup(Object *obj, const char *value,
                                      Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    if (tdx->initialized) {
        error_report("migtd setup script failed to set");
	return;
    }

    g_free(tdx->migtd_setup_path);
    tdx->migtd_setup_path = g_strdup(value);

    if (!runstate_check(RUN_STATE_INMIGRATE)) {
        kvm_gmem_default_shared = true;
    }
    tdx->attributes |= TDX_TD_ATTRIBUTES_MIG;
}

/* tdx guest */
OBJECT_DEFINE_TYPE_WITH_INTERFACES(TdxGuest,
                                   tdx_guest,
                                   TDX_GUEST,
                                   X86_CONFIDENTIAL_GUEST,
                                   { TYPE_USER_CREATABLE },
                                   { NULL })

static void tdx_guest_init(Object *obj)
{
    ConfidentialGuestSupport *cgs = CONFIDENTIAL_GUEST_SUPPORT(obj);
    TdxGuest *tdx = TDX_GUEST(obj);

    qemu_mutex_init(&tdx->lock);

    cgs->require_guest_memfd = true;
    tdx->attributes = TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE;

    object_property_add_uint64_ptr(obj, "attributes", &tdx->attributes,
                                   OBJ_PROP_FLAG_READWRITE);
    object_property_add_bool(obj, "sept-ve-disable",
                             tdx_guest_get_sept_ve_disable,
                             tdx_guest_set_sept_ve_disable);
    object_property_add_str(obj, "mrconfigid",
                            tdx_guest_get_mrconfigid,
                            tdx_guest_set_mrconfigid);
    object_property_add_str(obj, "mrowner",
                            tdx_guest_get_mrowner, tdx_guest_set_mrowner);
    object_property_add_str(obj, "mrownerconfig",
                            tdx_guest_get_mrownerconfig,
                            tdx_guest_set_mrownerconfig);
    object_property_add_str(obj, "migtd-setup", tdx_guest_get_migtd_setup,
                            tdx_guest_set_migtd_setup);
}

static void tdx_guest_finalize(Object *obj)
{
}

static void tdx_guest_class_init(ObjectClass *oc, void *data)
{
    ConfidentialGuestSupportClass *klass = CONFIDENTIAL_GUEST_SUPPORT_CLASS(oc);
    X86ConfidentialGuestClass *x86_klass = X86_CONFIDENTIAL_GUEST_CLASS(oc);

    klass->kvm_init = tdx_kvm_init;
    x86_klass->kvm_type = tdx_kvm_type;
    x86_klass->cpu_instance_init = tdx_cpu_instance_init;
    x86_klass->cpu_realizefn = tdx_cpu_realizefn;
    x86_klass->adjust_cpuid_features = tdx_adjust_cpuid_features;
    x86_klass->check_features = tdx_check_features;
}
