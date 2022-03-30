#ifndef CKB_MISCELLANEOUS_SCRIPTS_C_CKB_DLFCN_DECL_ONLY_H_
#define CKB_MISCELLANEOUS_SCRIPTS_C_CKB_DLFCN_DECL_ONLY_H_

int ckb_dlopen(const uint8_t *dep_cell_data_hash, uint8_t *aligned_addr,
               size_t aligned_size, void **handle, size_t *consumed_size);
int ckb_dlopen2(const uint8_t *dep_cell_hash, uint8_t hash_type,
                uint8_t *aligned_addr, size_t aligned_size, void **handle,
                size_t *consumed_size);
void *ckb_dlsym(void *handle, const char *symbol);

#define ERROR_CONTEXT_FAILURE -21
#define ERROR_INVALID_ELF -22
#define ERROR_MEMORY_NOT_ENOUGH -23
#define R_RISCV_RELATIVE 3
typedef struct {
  uint64_t r_offset;
  uint64_t r_info;
  int64_t r_addend;
} Elf64_Rela;

typedef struct {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
} Elf64_Phdr;

typedef struct {
  uint8_t e_ident[16];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
} Elf64_Ehdr;


#endif //CKB_MISCELLANEOUS_SCRIPTS_C_CKB_DLFCN_DECL_ONLY_H_
