// make printf to work: by default, the function printf is not included.
#ifndef CKB_C_STDLIB_PRINTF
#define CKB_C_STDLIB_PRINTF
#endif

// use deps/ckb-c-stdlib
#include <stdio.h>
#include <stdlib.h>

// printf will use syscalls "ckb_debug" to print message to console
#include <ckb_syscalls.h>

#include "libec.h"
#include "libsig.h"

/* TODO: Don't know why these are still needed */
void ext_printf(const char *format, ...) {
  char buf[CKB_C_STDLIB_PRINTF_BUFFER_SIZE];
  va_list va;
  va_start(va, format);
  vsnprintf_(buf, CKB_C_STDLIB_PRINTF_BUFFER_SIZE, format, va);
  va_end(va);
  ckb_debug(buf);
}

int get_random(unsigned char *buf, u16 len) {
  for (int i = 0; i < len; i++) {
    buf[i] = 0;
  }
  return 0;
}

int get_ms_time(u64 *time) {
  *time = 0;
  return 0;
}
