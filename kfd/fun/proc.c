//
//  proc.c
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/07/29.
//

#include "proc.h"
#include "offsets.h"
#include "krw.h"
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#import "common.h"

u64 getProc(pid_t pid) {
    usleep(200);
    print_message("get_kernproc");
    u64 proc = get_kernproc();
    
    while (true) {
        usleep(200);
        if(kread32(proc + off_p_pid) == pid) {
            return proc;
        }
        proc = kread64(proc + off_p_list_le_prev);
    }
    
    return 0;
}

u64 getProcByName(char* nm) {
    u64 proc = get_kernproc();
    
    while (true) {
        u64 nameptr = proc + off_p_name;
        char name[32];
        do_kread(nameptr, &name, 32);
//        print_message("[i] pid: %d, process name: %s\n", kread32(proc + off_p_pid), name);
        if(strcmp(name, nm) == 0) {
            return proc;
        }
        proc = kread64(proc + off_p_list_le_prev);
    }
    
    return 0;
}

int getPidByName(char* nm) {
    return kread32(getProcByName(nm) + off_p_pid);
}

int funProc(u64 proc) {
    int p_ppid = kread32(proc + off_p_ppid);
    print_message("[i] self proc->p_ppid: %d\n", p_ppid);
    print_message("[i] Patching proc->p_ppid %d -> 1 (for testing kwrite32, getppid)\n", p_ppid);
    kwrite32(proc + off_p_ppid, 0x1);
    print_message("[+] Patched getppid(): %u\n", getppid());
    kwrite32(proc + off_p_ppid, p_ppid);
    print_message("[+] Restored getppid(): %u\n", getppid());

    int p_original_ppid = kread32(proc + off_p_original_ppid);
    print_message("[i] self proc->p_original_ppid: %d\n", p_original_ppid);
    
    int p_pgrpid = kread32(proc + off_p_pgrpid);
    print_message("[i] self proc->p_pgrpid: %d\n", p_pgrpid);
    
    int p_uid = kread32(proc + off_p_uid);
    print_message("[i] self proc->p_uid: %d\n", p_uid);
    
    int p_gid = kread32(proc + off_p_gid);
    print_message("[i] self proc->p_gid: %d\n", p_gid);
    
    int p_ruid = kread32(proc + off_p_ruid);
    print_message("[i] self proc->p_ruid: %d\n", p_ruid);
    
    int p_rgid = kread32(proc + off_p_rgid);
    print_message("[i] self proc->p_rgid: %d\n", p_rgid);
    
    int p_svuid = kread32(proc + off_p_svuid);
    print_message("[i] self proc->p_svuid: %d\n", p_svuid);
    
    int p_svgid = kread32(proc + off_p_svgid);
    print_message("[i] self proc->p_svgid: %d\n", p_svgid);
    
    int p_sessionid = kread32(proc + off_p_sessionid);
    print_message("[i] self proc->p_sessionid: %d\n", p_sessionid);
    
    u64 p_puniqueid = kread64(proc + off_p_puniqueid);
    print_message("[i] self proc->p_puniqueid: 0x%llx\n", p_puniqueid);
    
    print_message("[i] Patching proc->p_puniqueid 0x%llx -> 0x4142434445464748 (for testing kwrite64)\n", p_puniqueid);
    kwrite64(proc + off_p_puniqueid, 0x4142434445464748);
    print_message("[+] Patched self proc->p_puniqueid: 0x%llx\n", kread64(proc + off_p_puniqueid));
    kwrite64(proc + off_p_puniqueid, p_puniqueid);
    print_message("[+] Restored self proc->p_puniqueid: 0x%llx\n", kread64(proc + off_p_puniqueid));
    
    return 0;
}
