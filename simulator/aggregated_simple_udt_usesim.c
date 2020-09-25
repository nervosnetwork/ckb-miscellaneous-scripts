
#include "ckb_consts.h"
#include "ckb_syscall_agg_sudt.h"
#define ASSERT assert
#include "../c/aggregated_simple_udt.c"
#include <stdio.h>
#include <stdlib.h>

#define COUNT_OF(a) (sizeof(a)/sizeof(a[0]))

void exit(int);
#define CHECK(a, b) do { if ((a) != (b)) {printf("failed at line %d", __LINE__); assert(false); exit(-1); } } while (0)
#define CHECK_TRUE(a) CHECK(a, true)

static uint8_t s_temp_data[MAX_CELL_SIZE];
static uint32_t s_temp_length = 0;

void init_temp(void) {
  s_temp_length = 4;
  *((uint32_t*)s_temp_data) = 0;
}

// ID is always on the lower 16 bytes, for simplicity
void push_sudt(uint128_t id, uint128_t amount) {
  uint32_t space_left = sizeof(s_temp_data) - s_temp_length;
  CHECK_TRUE(space_left >= sizeof(sudt_entry_t));
  sudt_entry_t *p = (sudt_entry_t*)(s_temp_data + s_temp_length);
  s_temp_length += sizeof(sudt_entry_t);
  p->amount = amount;
  memcpy(&p->id, &id, sizeof(id));

  (*((uint32_t*)s_temp_data)) += 1;
}

void gen_input_cell(void) {
  fill_input_cell_data(s_temp_data, s_temp_length);
  init_temp(); // reset
}

void gen_output_cell(void) {
  fill_output_cell_data(s_temp_data, s_temp_length);
  init_temp(); // reset
}

void init_input_regular_sudt(void) {
  init_input_regular_cell_data();
  init_input_type_script_args();
}

void push_input_regular_sudt(uint128_t id, uint128_t amount) {
  push_input_regular_cell_data((uint8_t*)&amount);
  uint8_t buff[SUDT_ID_SIZE] = {0};
  memcpy(buff, &id, sizeof(id));
  push_input_type_script_args(buff);
}

void init_output_regular_sudt(void) {
  init_output_regular_cell_data();
  init_output_type_script_args();
}

void push_output_regular_sudt(uint128_t id, uint128_t amount) {
  push_output_regular_cell_data((uint8_t*)&amount);
  uint8_t buff[SUDT_ID_SIZE] = {0};
  memcpy(buff, &id, sizeof(id));
  push_output_type_script_args(buff);
}

typedef struct simple_entry_t {
  uint128_t id;
  uint128_t amount;
} simple_entry_t;

void test(int expected_ret, simple_entry_t* input, size_t input_len,
          simple_entry_t* output, size_t output_len,
          simple_entry_t* input_regular, size_t input_regular_len,
          simple_entry_t* output_regular, size_t output_regular_len) {
  init_temp();
  for (size_t i = 0; i < input_len; i++) {
    simple_entry_t* e = input+i;
    push_sudt(e->id, e->amount);
  }
  gen_input_cell();

  init_temp();
  for (size_t i = 0; i < output_len; i++) {
    simple_entry_t* e = output+i;
    push_sudt(e->id, e->amount);
  }
  gen_output_cell();

  if (input_regular) {
    init_input_regular_sudt();
    for (size_t i = 0; i < input_regular_len; i++) {
      simple_entry_t *e = input_regular + i;
      push_input_regular_sudt(e->id, e->amount);
    }
  }

  if (output_regular) {
    init_output_regular_sudt();
    for (size_t i = 0; i < output_regular_len; i++) {
      simple_entry_t *e = output_regular + i;
      push_output_regular_sudt(e->id, e->amount);
    }
  }

  int ret = inner_main();
  CHECK(ret, expected_ret);
}


void stress_test(void) {
  printf("------- begin stress test ----------\n");
  init_temp();
  for (size_t i = 0; i < 8192; i++) {
    push_sudt(i, i);
  }
  gen_input_cell();

  init_temp();
  for (size_t i = 0; i < 8192; i++) {
    push_sudt(i, i);
  }
  gen_output_cell();

  int ret = inner_main();
  CHECK(ret, 0);
}

void srand(unsigned seed);
long time(long *);

void random_test_once(bool fail_case) {
  size_t length = rand() % 8192;
  uint64_t data[length];

  for (size_t i = 0; i < length; i++) {
    data[i] = rand();
  }

  init_temp();
  for (size_t i = 0; i < length; i++) {
    push_sudt(data[i], data[i]);
  }
  gen_input_cell();

  init_temp();
  for (size_t i = 0; i < length; i++) {
    push_sudt(data[i], data[i]);
  }
  gen_output_cell();

  init_input_regular_sudt();
  init_output_regular_sudt();
  size_t loop_count = rand() % (MAX_ARGS_COUNT - 3);
  for (size_t i = 0; i < loop_count; i++) {
    uint128_t id = rand();
    uint128_t amount = rand();
    push_input_regular_sudt(id, amount);
    push_output_regular_sudt(id, amount);
  }
  if (fail_case) {
    if (rand() % 2) {
      push_input_regular_sudt(1, 1);
      push_output_regular_sudt(1, 1);
      // add extra one, should fail
      push_output_regular_sudt(1, 1);
      int ret = inner_main();
      CHECK(ret, ERROR_AMOUNT);
    } else {
      uint128_t extra_id = 0xFF;
      push_output_regular_sudt(extra_id << 64, 1);
      int ret = inner_main();
      CHECK(ret, ERROR_INVALID_OUTPUT);
    }
  } else {
    int ret = inner_main();
    CHECK(ret, CKB_SUCCESS);
  }
}

void test_1() {
  sudt_container_t container;
  init(&container);

  init_temp();
  push_sudt(1, 100);
  push_sudt(2, 100);
  push_sudt(3, 100);
  gen_input_cell();
  load(&container, 0, CKB_SOURCE_GROUP_INPUT);
  merge(&container);
  CHECK(container.count, 3);
}

void random_test() {
  srand (time(NULL));
  printf("------- begin random test ----------\n");
  for (int i = 0; i < 100; i++) {
    random_test_once(false);
  }
  for (int i = 0; i < 100; i++) {
    random_test_once(true);
  }
}

void normal_test(void) {
  {
    simple_entry_t input[]  = {{1, 100}, {2, 200}, {3, 300}, {1, 100}, {2, 200}, {3, 300}, {1, 100}, {2, 200}, {3, 300}};
    simple_entry_t output[] = {{1, 100}, {2, 200}, {3, 300}, {1, 100}, {2, 200}, {3, 300}, {1, 100}, {2, 200}, {3, 300}};
    test(0, input, COUNT_OF(input), output, COUNT_OF(output), 0, 0, 0, 0);
  }
  {
    simple_entry_t input[] = {{1, 100}, {2, 200}, {3, 300}};
    simple_entry_t output[] = {{1, 100}, {2, 200}, {3, 300}};
    test(0, input, COUNT_OF(input), output, COUNT_OF(output), 0, 0, 0, 0);
  }
  {
    simple_entry_t input[] = { {2, 200}, {3, 300}};
    simple_entry_t output[] = {{1, 100}, {2, 200}, {3, 300}};
    test(ERROR_INVALID_OUTPUT, input, COUNT_OF(input), output, COUNT_OF(output), 0, 0, 0, 0);
  }
  {
    // burn token
    simple_entry_t input[] = {{1, 100}, {2, 200}, {3, 300}, {3, 300}, {3, 300}, {2, 300}};
    simple_entry_t output[] = {{2, 200}, {3, 300}};
    test(0, input, COUNT_OF(input), output, COUNT_OF(output), 0, 0, 0, 0);
  }
  {
    // no output is valid, burn token
    simple_entry_t input[] = {{1, 100}};
    simple_entry_t output[] = {};
    test(0, input, COUNT_OF(input), output, 0, 0, 0, 0, 0);
  }
  {
    // mixed with deposition and withdraw
    simple_entry_t input[] = {{1, 100}, {2, 200}, {3, 300}};
    simple_entry_t output[] = {{1, 100}, {2, 200}, {3, 300}};
    simple_entry_t regular_input[] = {{1, 100}, {2, 200}, {3, 300}};
    simple_entry_t regular_output[] = {{1, 100}, {2, 200}, {3, 300}};
    test(0, input, COUNT_OF(input), output, COUNT_OF(output),
         regular_input, COUNT_OF(regular_input), regular_output, COUNT_OF(regular_output));
  }
  {
    //  deposition only
    simple_entry_t input[] = {};
    simple_entry_t output[] = {{1, 100}, {2, 200}, {3, 300}};
    simple_entry_t regular_input[] = {{1, 100}, {2, 200}, {3, 300}};
    simple_entry_t regular_output[] = {};
    test(0, input, COUNT_OF(input), output, COUNT_OF(output),
         regular_input, COUNT_OF(regular_input), regular_output, COUNT_OF(regular_output));
  }
  {
    //  deposition failed
    simple_entry_t input[] = {};
    simple_entry_t output[] = {{1, 1000000}, {2, 200}, {3, 300}};
    simple_entry_t regular_input[] = {{1, 100}, {2, 200}, {3, 300}};
    simple_entry_t regular_output[] = {};
    test(ERROR_AMOUNT, input, COUNT_OF(input), output, COUNT_OF(output),
         regular_input, COUNT_OF(regular_input), regular_output, COUNT_OF(regular_output));
  }
  {
    //  deposition failed
    simple_entry_t input[] = {};
    simple_entry_t output[] = {{1, 100}, {2, 200}, {3, 300}, {0xFFFF, 100}};
    simple_entry_t regular_input[] = {{1, 100}, {2, 200}, {3, 300}};
    simple_entry_t regular_output[] = {};
    test(ERROR_INVALID_OUTPUT, input, COUNT_OF(input), output, COUNT_OF(output),
         regular_input, COUNT_OF(regular_input), regular_output, COUNT_OF(regular_output));
  }
  {
    //  withdraw only
    simple_entry_t input[] = {{1, 100}, {2, 200}, {3, 300}};
    simple_entry_t output[] = {};
    simple_entry_t regular_input[] = {};
    simple_entry_t regular_output[] = {{1, 100}, {2, 200}, {3, 300}};
    test(0, input, COUNT_OF(input), output, COUNT_OF(output),
         regular_input, COUNT_OF(regular_input), regular_output, COUNT_OF(regular_output));
  }
  {
    //  withdraw failed
    simple_entry_t input[] = {{1, 100}, {2, 200}, {3, 300}};
    simple_entry_t output[] = {};
    simple_entry_t regular_input[] = {};
    simple_entry_t regular_output[] = {{1, 1000000}, {2, 200}, {3, 300}};
    test(ERROR_AMOUNT, input, COUNT_OF(input), output, COUNT_OF(output),
         regular_input, COUNT_OF(regular_input), regular_output, COUNT_OF(regular_output));
  }
  {
    //  withdraw failed
    simple_entry_t input[] = {{1, 100}, {2, 200}, {3, 300}};
    simple_entry_t output[] = {};
    simple_entry_t regular_input[] = {};
    simple_entry_t regular_output[] = {{1, 100}, {2, 200}, {3, 300}, {0xFF, 100}};
    test(ERROR_INVALID_OUTPUT, input, COUNT_OF(input), output, COUNT_OF(output),
         regular_input, COUNT_OF(regular_input), regular_output, COUNT_OF(regular_output));
  }
  {
    // withdraw, split
    simple_entry_t input[] = {{1, 100}, {2, 200}, {3, 300}};
    simple_entry_t output[] = {{1, 80}};
    simple_entry_t regular_input[] = {};
    simple_entry_t regular_output[] = {{1, 20}, {2, 200}, {3, 300}};
    test(0, input, COUNT_OF(input), output, COUNT_OF(output),
         regular_input, COUNT_OF(regular_input), regular_output, COUNT_OF(regular_output));
  }
  {
    // no output is valid
    simple_entry_t input[] = {{1, 100}, {2, 200}, {3, 300}};
    simple_entry_t output[] = {};
    simple_entry_t regular_input[] = {{1, 100}, {2, 200}, {3, 300}};
    simple_entry_t regular_output[] = {};
    test(0, input, COUNT_OF(input), output, COUNT_OF(output),
         regular_input, COUNT_OF(regular_input), regular_output, COUNT_OF(regular_output));
  }
}


int main() {
  printf("Start testing ... It fails when exit with non-zero or abort!\n");
  normal_test();
  stress_test();
  random_test();
  test_1();
  // TODO: multiple cell data
  printf("\n-------------------------\nAll test cases passed\n-------------------------\n");
  return 0;
}
