#include "ckb_syscall_simulator.h"
#include <assert.h>
#include "blockchain-api2.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "cJSON.h"

#define CHECK(ret) do { if ((ret) != 0) { printf("error = 0 %d\n", ret); goto EXIT;} } while (0)
#define FAIL(msg) printf("Failed at %s:%d: %s\n", __FILE__, __LINE__, (msg))

#define TX_HASH_SIZE 32
static cJSON* s_json = NULL;
static cJSON* s_tx_json = NULL;
static uint8_t s_tx_hash[TX_HASH_SIZE] = {0};

cJSON* get_item_at(cJSON* j, size_t index) {
  if (j == NULL) {
    FAIL("It can't be NULL");
    return NULL;
  }
  cJSON* elm = j->child;
  size_t target = 0;
  while (elm != NULL) {
    if (target == index)
      return elm;
    elm = elm->next;
    target++;
  }
  FAIL("Can't find item at index");
  return NULL;
}

unsigned char decode_hex(char s) {
  if (s >= '0' && s <= '9') {
    return s - '0';
  } else if (s >= 'a' && s <= 'f') {
    return s - 'a' + 10;
  } else if (s >= 'A' && s <= 'F') {
    return s - 'A' + 10;
  } else {
    FAIL("Invalid hex character");
  }
  return 0;
}

unsigned char compose_byte(const char* s) {
  return decode_hex(s[0]) << 4 | decode_hex(s[1]);
}

void load_data(const char* str, unsigned char* addr, uint64_t* len, size_t offset) {
  size_t str_len = strlen(str);
  if (str_len < 2 || str[0] != '0' || str[1] != 'x') {
    FAIL("The data part must be started with 0x");
    return;
  }
  ASSERT((str_len % 2) == 0);
  size_t data_len = (str_len - 2)/2;
  ASSERT(offset < data_len);

  size_t start = 2 + offset*2;
  for (size_t i = 0; i < *len; i++) {
    if ((offset + i) >= data_len) {
      *len = i;
      break;
    }
    addr[i] = compose_byte(&str[start + i * 2]);
  }
}

void load_offset(uint8_t* source_buff, uint64_t source_size,
                void* addr, uint64_t* len, size_t offset) {
  assert(source_size > offset);
  assert(*len > 0);

  uint64_t size = MIN(source_size - offset, *len);
  memcpy(addr, source_buff + offset, size);
  *len = size;
}

// todo
mol_seg_t build_script(uint8_t* code_hash, uint8_t hash_type, uint8_t* args, uint32_t args_len) {
  mol_builder_t b;
  mol_seg_res_t res;
  MolBuilder_Script_init(&b);
  byte code_hash[32] = {0x12, 0x34, 0x56, 0x78};
  byte hash_type = 0x12;

  MolBuilder_Script_set_code_hash(&b, code_hash, 32);
  MolBuilder_Script_set_hash_type(&b, hash_type);
  mol_seg_t bytes = build_Bytes();
  MolBuilder_Script_set_args(&b, bytes.ptr, bytes.size);

  res = MolBuilder_Script_build(b);
  assert(res.errno == 0);
  assert(MolReader_Script_verify(&res.seg, false) == 0);
  return res.seg;
}


int ckb_exit(int8_t code) {
  printf("ckb_exit\n");
  exit(0);
  return CKB_SUCCESS;
}

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset) {
  load_offset(s_tx_hash, TX_HASH_SIZE, addr, len, offset);
  return CKB_SUCCESS;
}

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset) {
  return 0;
}

int ckb_load_cell(void* addr, uint64_t* len, size_t offset, size_t index, size_t source) {
  return 0;
}

int ckb_load_input(void* addr, uint64_t* len, size_t offset, size_t index, size_t source) {
  return 0;
}


int ckb_load_header(void* addr, uint64_t* len, size_t offset, size_t index, size_t source) {
  return 0;
}

int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index, size_t source) {
  cJSON* tx = cJSON_GetObjectItem(s_tx_json, "tx");
  cJSON* witness = cJSON_GetObjectItem(tx, "witnesses");
  cJSON* witness_item = get_item_at(witness, index);
  load_data(witness_item->valuestring, addr, len, offset);
  return 0;
}

int ckb_load_script(void* addr, uint64_t* len, size_t offset) {
  return 0;
}

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field) {
  return 0;
}

int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field) {
  return 0;
}

int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field) {
  return 0;
}

int ckb_load_cell_code(void* addr, size_t memory_size, size_t content_offset,
                       size_t content_size, size_t index, size_t source) {
  return 0;
}

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source) {
  return 0;
}

int ckb_debug(const char* s) {
  return 0;
}

int load_actual_type_witness(uint8_t *buf, uint64_t *len, size_t index,
                             size_t *type_source) {
  return 0;
}


int ckb_look_for_dep_with_hash(const uint8_t* data_hash, size_t* index) {
  return 0;
}

int ckb_calculate_inputs_len() {
  return 0;
}

int ckb_look_for_dep_with_hash2(const uint8_t* code_hash, uint8_t hash_type,
                                size_t* index){
  return 0;
}

#ifndef  READALL_CHUNK
#define  READALL_CHUNK  262144
#endif

#define  READALL_OK          0  /* Success */
#define  READALL_INVALID    -1  /* Invalid parameters */
#define  READALL_ERROR      -2  /* Stream error */
#define  READALL_TOOMUCH    -3  /* Too much input */
#define  READALL_NOMEM      -4  /* Out of memory */

int readall(FILE *in, char **dataptr, size_t *sizeptr) {
  char  *data = NULL, *temp;
  size_t size = 0;
  size_t used = 0;
  size_t n;

  /* None of the parameters can be NULL. */
  if (in == NULL || dataptr == NULL || sizeptr == NULL)
    return READALL_INVALID;

  /* A read error already occurred? */
  if (ferror(in))
    return READALL_ERROR;

  while (1) {
    if (used + READALL_CHUNK + 1 > size) {
      size = used + READALL_CHUNK + 1;

      if (size <= used) {
        free(data);
        return READALL_TOOMUCH;
      }

      temp = realloc(data, size);
      if (temp == NULL) {
        free(data);
        return READALL_NOMEM;
      }
      data = temp;
    }

    n = fread(data + used, 1, READALL_CHUNK, in);
    if (n == 0)
      break;

    used += n;
  }

  if (ferror(in)) {
    free(data);
    return READALL_ERROR;
  }

  temp = realloc(data, used + 1);
  if (temp == NULL) {
    free(data);
    return READALL_NOMEM;
  }
  data = temp;
  data[used] = '\0';

  *dataptr = data;
  *sizeptr = used;

  return READALL_OK;
}

int init_json_data_source(const char* file_name) {
  FILE* input = NULL;
  if (file_name == NULL) {
    input = stdin;
  } else {
    input = fopen(file_name, "rb");
  }
  char* json_ptr = NULL;
  size_t json_size = 0;
  int ret = readall(input, &json_ptr, &json_size);
  if (ret != 0) {
    return ret;
  }
  s_json = cJSON_ParseWithLength(json_ptr, json_size);
  if (s_json == NULL) {
    char msg[128] = {0};
    sprintf(msg, "Failed to parse json file: %s", file_name);
    FAIL(msg);
    return -1;
  }
  fclose(input);
  free(json_ptr);
  // ---------

  cJSON* tx_hash = cJSON_GetObjectItem(s_json, "main");
  cJSON* fn = cJSON_GetObjectItem(s_json, tx_hash->valuestring);
  input = fopen(fn->valuestring, "rb");
  ret = readall(input, &json_ptr, &json_size);
  s_tx_json = cJSON_ParseWithLength(json_ptr, json_size);
  if (s_tx_json == NULL) {
    char msg[128] = {0};
    sprintf(msg, "Failed to parse json file: %s", fn->valuestring);
    FAIL(msg);
    return -1;
  }
  uint64_t tx_hash_len = TX_HASH_SIZE;
  load_data(tx_hash->valuestring, s_tx_hash, &tx_hash_len, 0);
  assert(tx_hash_len == TX_HASH_SIZE);

  fclose(input);
  free(json_ptr);

  return 0;
}

// the test data is from:
// npx ckb-transaction-dumper -x 0xa98c212cf055cedbbb665d475c0561b56c68ea735c8aa830c493264effaf18bd

int main(int argc, const char* argv[]) {
  const char* file_name = NULL;
  if (argc == 2 && argv[1] != NULL)
    file_name = argv[1];
  int ret = init_json_data_source(file_name);
  CHECK(ret);

  unsigned char witness[1024] = {0};
  uint64_t witness_len = 1024;
  ckb_load_witness(witness, &witness_len, 0, 0, 0);
  assert(witness_len == 85);
  assert(witness[0] == 0x55);
  assert(witness[1] == 0x00);
  assert(witness[83] == 0xe7);
  assert(witness[84] == 0x01);
  ret = 0;
EXIT:
  return ret;
}