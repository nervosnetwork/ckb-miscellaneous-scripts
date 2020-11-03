
// make assert working under release
#undef NDEBUG

#include "ckb_syscall_simulator.h"
#include <assert.h>
#include "blockchain-api2.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "cJSON.h"
#include "molecule_decl_only.h"
#include "blake2b_decl_only.h"

#define FAIL(msg) do { assert(false); printf("Failed at %s:%d: %s\n", __FILE__, __LINE__, (msg)); } while (0)

#define TX_HASH_SIZE 32
#define BLAKE160_SIZE 20

static cJSON* s_json = NULL;
static cJSON* s_tx_json = NULL;
static uint8_t s_tx_hash[TX_HASH_SIZE] = {0};

// -----------------------

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
  ASSERT(offset <= data_len);

  size_t start = 2 + offset*2;
  for (size_t i = 0; i < *len; i++) {
    if ((offset + i) >= data_len) {
      *len = i;
      break;
    }
    addr[i] = compose_byte(&str[start + i * 2]);
  }
}

size_t calculate_size(const char* str) {
  assert(strlen(str) % 2 == 0);
  return (strlen(str) - 2)/2;
}

void load_offset(uint8_t* source_buff, uint64_t source_size,
                void* addr, uint64_t* len, size_t offset) {
  assert(source_size > offset);
  assert(*len > 0);

  uint64_t size = MIN(source_size - offset, *len);
  memcpy(addr, source_buff + offset, size);
  *len = size;
}

void blake2b_hash(void* ptr, size_t size, uint8_t* hash) {
  blake2b_state ctx;
  blake2b_init(&ctx, TX_HASH_SIZE);
  blake2b_update(&ctx, ptr, size);
  blake2b_final(&ctx, hash, TX_HASH_SIZE);
}

void print_hex(uint8_t* ptr, size_t size) {
  printf("0x");
  for (size_t i = 0; i < size; i ++) {
    printf("%02x", ptr[i]);
  }
  printf("\n");
}

// todo: free
mol_seg_t build_Bytes(uint8_t* ptr, uint32_t len) {
  mol_builder_t b;
  mol_seg_res_t res;
  MolBuilder_Bytes_init(&b);
  for (uint32_t i = 0; i < len; i++) {
    MolBuilder_Bytes_push(&b, ptr[i]);
  }
  res = MolBuilder_Bytes_build(b);
  assert(res.errno == 0);
  return res.seg;
}

mol_seg_t build_script(uint8_t* code_hash, uint8_t hash_type, uint8_t* args, uint32_t args_len) {
  mol_builder_t b;
  mol_seg_res_t res;

  MolBuilder_Script_init(&b);
  MolBuilder_Script_set_code_hash(&b, code_hash, 32);
  MolBuilder_Script_set_hash_type(&b, hash_type);
  mol_seg_t bytes = build_Bytes(args, args_len);
  MolBuilder_Script_set_args(&b, bytes.ptr, bytes.size);

  res = MolBuilder_Script_build(b);
  assert(res.errno == 0);
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
  if (witness_item == NULL) {
    return CKB_INDEX_OUT_OF_BOUND;
  }
  load_data(witness_item->valuestring, addr, len, offset);
  return CKB_SUCCESS;
}

typedef struct data_hash_item_t {
  uint8_t hash[TX_HASH_SIZE];
  uint64_t len;
  uint8_t* data;
} data_hash_item_t;

#define MAX_HASH_ITEM_SIZE 1024

data_hash_item_t s_data_hash[MAX_HASH_ITEM_SIZE] = {0};
size_t s_data_hash_len = 0;

void prepare_hash(void) {
  cJSON* mock_info = cJSON_GetObjectItem(s_tx_json, "mock_info");
  assert(mock_info);
  cJSON* cell_deps = cJSON_GetObjectItem(mock_info, "cell_deps");
  assert(cell_deps);
  size_t index = 0;
  for (cJSON* it = cell_deps->child; it != NULL; it = it->next) {
    assert(index < MAX_HASH_ITEM_SIZE);
    data_hash_item_t* item = &s_data_hash[index];

    cJSON* data = cJSON_GetObjectItem(it, "data");
    item->len = calculate_size(data->valuestring);
    item->data = malloc(item->len);
    load_data(data->valuestring, item->data, &item->len, 0);
    blake2b_hash(item->data, item->len, item->hash);

    // printf("Cell data hash at index %zu:", index);
    // print_hex(item->hash, TX_HASH_SIZE);
    index++;
  }
  s_data_hash_len = index;
}

int ckb_load_script(void* addr, uint64_t* len, size_t offset) {
  cJSON* mock_info = cJSON_GetObjectItem(s_tx_json, "mock_info");
  cJSON* inputs = cJSON_GetObjectItem(mock_info, "inputs");
  cJSON* first_input = get_item_at(inputs, 0);
  cJSON* output = cJSON_GetObjectItem(first_input, "output");
  cJSON* lock_json = cJSON_GetObjectItem(output, "lock");
  cJSON* args_json = cJSON_GetObjectItem(lock_json, "args");
  cJSON* code_hash_json = cJSON_GetObjectItem(lock_json, "code_hash");
  cJSON* hash_type_json = cJSON_GetObjectItem(lock_json, "hash_type");
  // to be confirmed
  int hash_type = 0;
  if (strcmp(hash_type_json->valuestring, "type") == 0) {
    hash_type = 1;
  }

  uint8_t code_hash[TX_HASH_SIZE] = {0};
  uint64_t code_hash_len = TX_HASH_SIZE;
  load_data(code_hash_json->valuestring, code_hash, &code_hash_len, 0);

  uint64_t args_len = calculate_size(args_json->valuestring);
  uint8_t args[args_len];
  load_data(args_json->valuestring, args, &args_len, 0);
  mol_seg_t script = build_script(code_hash, hash_type, args, args_len);

  load_offset(script.ptr, script.size, addr, len, offset);
  return CKB_SUCCESS;
}

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field) {
  if (source == CKB_SOURCE_CELL_DEP) {
    if (field == CKB_CELL_FIELD_DATA_HASH) {
      if (index >= s_data_hash_len) {
        return CKB_INDEX_OUT_OF_BOUND;
      }
      load_offset(s_data_hash[index].hash, TX_HASH_SIZE, addr, len, offset);
    } else {
      assert(false);
    }
  } else {
    assert(false);
  }

  return 0;
}

int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field) {
  return 0;
}

int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field) {
  if (source == CKB_SOURCE_INPUT) {
    if (field == CKB_INPUT_FIELD_SINCE) {
      cJSON* tx = cJSON_GetObjectItem(s_tx_json, "tx");
      cJSON* inputs = cJSON_GetObjectItem(tx, "inputs");
      assert(inputs != NULL);
      cJSON* input = get_item_at(inputs, index);
      if (input == NULL) {
        return CKB_INDEX_OUT_OF_BOUND;
      } else {
        cJSON* since = cJSON_GetObjectItem(input, "since");
        load_data(since->valuestring, addr, len, offset);
      }

    } else {
      assert(false);
    }
  } else {
    assert(false);
  }
  return CKB_SUCCESS;
}

int ckb_load_cell_code(void* addr, size_t memory_size, size_t content_offset,
                       size_t content_size, size_t index, size_t source) {
  return 0;
}

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source) {
  if (source == CKB_SOURCE_CELL_DEP) {
    if (index >= s_data_hash_len) {
      return CKB_INDEX_OUT_OF_BOUND;
    }
    load_offset(s_data_hash[index].data, s_data_hash[index].len, addr, len, offset);
  } else {
    assert(false);
  }
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
  return ckb_look_for_dep_with_hash2(data_hash, 0, index);
}

int ckb_calculate_inputs_len() {
  uint64_t len = 0;
  /* lower bound, at least tx has one input */
  int lo = 0;
  /* higher bound */
  int hi = 4;
  int ret;
  /* try to load input until failing to increase lo and hi */
  while (1) {
    ret = ckb_load_input_by_field(NULL, &len, 0, hi, CKB_SOURCE_INPUT,
                                  CKB_INPUT_FIELD_SINCE);
    if (ret == CKB_SUCCESS) {
      lo = hi;
      hi *= 2;
    } else {
      break;
    }
  }

  /* now we get our lower bound and higher bound,
   count number of inputs by binary search */
  int i;
  while (lo + 1 != hi) {
    i = (lo + hi) / 2;
    ret = ckb_load_input_by_field(NULL, &len, 0, i, CKB_SOURCE_INPUT,
                                  CKB_INPUT_FIELD_SINCE);
    if (ret == CKB_SUCCESS) {
      lo = i;
    } else {
      hi = i;
    }
  }
  /* now lo is last input index and hi is length of inputs */
  return hi;
}

int ckb_look_for_dep_with_hash2(const uint8_t* code_hash, uint8_t hash_type,
                                size_t* index){
  size_t current = 0;
  size_t field =
      (hash_type == 1) ? CKB_CELL_FIELD_TYPE_HASH : CKB_CELL_FIELD_DATA_HASH;
  while (current < SIZE_MAX) {
    uint64_t len = 32;
    uint8_t hash[32];

    int ret = ckb_load_cell_by_field(hash, &len, 0, current,
                                     CKB_SOURCE_CELL_DEP, field);
    switch (ret) {
      case CKB_ITEM_MISSING:
        break;
      case CKB_SUCCESS:
        if (memcmp(code_hash, hash, 32) == 0) {
          /* Found a match */
          *index = current;
          return CKB_SUCCESS;
        }
        break;
      default:
        return CKB_INDEX_OUT_OF_BOUND;
    }
    current++;
  }
  return CKB_INDEX_OUT_OF_BOUND;
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


#define SCRIPT_SIZE 8192

void test_script(void) {
  unsigned char script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;
  int ret = ckb_load_script(script, &len, 0);
  assert(ret == CKB_SUCCESS);
  assert(len < SCRIPT_SIZE);

  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  assert(MolReader_Script_verify(&script_seg, false) == MOL_OK);

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  assert (args_bytes_seg.size == BLAKE160_SIZE);

  assert(args_bytes_seg.ptr[0] == 0x27);
  assert(args_bytes_seg.ptr[1] == 0xf5);
  assert(args_bytes_seg.ptr[18] == 0x9e);
  assert(args_bytes_seg.ptr[19] == 0xc9);
}

// the test data is from:
// npx ckb-transaction-dumper -x 0xa98c212cf055cedbbb665d475c0561b56c68ea735c8aa830c493264effaf18bd

int unit_test(int argc, const char* argv[]) {
  unsigned char witness[1024] = {0};
  uint64_t witness_len = 1024;
  ckb_load_witness(witness, &witness_len, 0, 0, 0);
  assert(witness_len == 85);
  assert(witness[0] == 0x55);
  assert(witness[1] == 0x00);
  assert(witness[83] == 0xe7);
  assert(witness[84] == 0x01);
  test_script();
  return 0;
}

int validate_simple();
int main(int argc, const char* argv[]) {
  const char* file_name = NULL;
  if (argc == 2 && argv[1] != NULL)
    file_name = argv[1];
  int ret = init_json_data_source(file_name);
  assert(ret == 0);
  prepare_hash();

  if (false) {
    ret = unit_test(argc, argv);
  } else {
    ret = validate_simple();
  }

  if (ret == 0) {
    printf("succeeded!");
  } else {
    printf("failed, error code: %d", ret);
  }
  return ret;
}
