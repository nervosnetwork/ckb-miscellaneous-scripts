#include "libec.h"
#include "libsig.h"

/* TODO: Don't know why these are still needed */
void ext_printf(const char *format, ...) {
  // TODO: ckb-c-stdlib does not seem to support vprintf

  // va_list arglist;
  // va_start(arglist, format);
  // vprintf(format, arglist);
  // va_end(arglist);
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
