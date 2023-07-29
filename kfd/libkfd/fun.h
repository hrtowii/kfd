//
//  fun.h
//  kfd
//
//  Created by Seo Hyun-gyu on 2023/07/25.
//

#ifndef fun_h
#define fun_h

#include <stdio.h>

// Generate the name for an offset.
#define OFFSET(base_, object_)      _##base_##_##object_##_offset_

// Generate the name for the size of an object.
#define SIZE(object_)               _##object_##_size_

typedef uint64_t kptr_t; // https://github.com/pattern-f/TQ-pre-jailbreak/blob/main/mylib/mycommon.h#L17

int do_fun(uint64_t kfd);
uint64_t do_kopen(uint64_t puaf_pages, uint64_t puaf_method, uint64_t kread_method, uint64_t kwrite_method);
void do_kclose(uint64_t kfd);
void do_respring();


#endif /* fun_h */
