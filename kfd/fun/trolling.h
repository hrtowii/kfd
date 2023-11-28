//
//  trolling.h
//  kfd
//
//  Created by LL on 28/11/23.
//

#ifndef trolling_h
#define trolling_h

int reboot3(uint64_t flags, ...);

void userspace_reboot() {
    reboot3(0x2000000000000000llu);
}

#endif /* trolling_h */
