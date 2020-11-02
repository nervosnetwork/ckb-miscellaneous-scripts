
#include "ckb_syscall_simulator.h"
#include <assert.h>
#include "blockchain-api2.h"
#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"

#define CHECK(ret) do { if ((ret) != 0) { printf("error = 0 %d\n", ret); goto EXIT;} } while (0)

int ckb_exit(int8_t code) {
  return 0;
}

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset) {
  return 0;
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

static cJSON* s_json = NULL;

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
    return -1;
  }


  return 0;
}

int main(int argc, const char* argv[]) {
  const char* file_name = NULL;
  if (argc == 2 && argv[1] != NULL)
    file_name = argv[1];
  int ret = init_json_data_source(file_name);
  CHECK(ret);

  ret = 0;
EXIT:
  return ret;
}