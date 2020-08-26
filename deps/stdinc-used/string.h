#ifndef CKB_C_STDLIB_STRING_H_
#define CKB_C_STDLIB_STRING_H_
#include <types.h>

void *memset(void *dest, int c, size_t n);
void *memcpy(void *restrict dest, const void *restrict src, size_t n);
void *memmove(void *dest, const void *src, size_t n);
int memcmp(const void *vl, const void *vr, size_t n);
size_t strlen(const char *s);
int strcmp(const char *l, const char *r);
char *strstr(const char *, const char *);
#endif /* CKB_C_STDLIB_STRING_H_ */
