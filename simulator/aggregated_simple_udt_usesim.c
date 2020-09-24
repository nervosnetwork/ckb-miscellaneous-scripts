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
void add_sudt(uint128_t id, uint128_t amount) {
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

typedef struct simple_entry_t {
  uint128_t id;
  uint128_t amount;
} simple_entry_t;

void test(int expected_ret, simple_entry_t* input, size_t input_len, simple_entry_t* output, size_t output_len) {
  init_temp();
  for (size_t i = 0; i < input_len; i++) {
    simple_entry_t* e = input+i;
    add_sudt(e->id, e->amount);
  }
  gen_input_cell();

  init_temp();
  for (size_t i = 0; i < output_len; i++) {
    simple_entry_t* e = output+i;
    add_sudt(e->id, e->amount);
  }
  gen_output_cell();

  int ret = inner_main();
  CHECK(ret, expected_ret);
}


void stress_test(void) {
  printf("\n------- begin stress test ----------\n");
  init_temp();
  for (size_t i = 0; i < 8192; i++) {
    add_sudt(i, i);
  }
  gen_input_cell();

  init_temp();
  for (size_t i = 0; i < 8192; i++) {
    add_sudt(i, i);
  }
  gen_output_cell();

  int ret = inner_main();
  CHECK(ret, 0);
}

void srand(unsigned seed);

void random_test() {
  printf("\n------- begin random test ----------\n");
  srand (__LINE__);
  size_t length = rand() % 8192;
  uint64_t data[length];

  for (size_t i = 0; i < length; i++) {
    data[i] = rand();
  }

  init_temp();
  for (size_t i = 0; i < length; i++) {
    add_sudt(data[i], data[i]);
  }
  gen_input_cell();

  init_temp();
  for (size_t i = 0; i < length; i++) {
    add_sudt(data[i], data[i]);
  }
  gen_output_cell();

  int ret = inner_main();
  CHECK(ret, 0);
}

void test_1() {
  sudt_container_t container;
  init(&container);

  init_temp();
  add_sudt(1, 100);
  add_sudt(2, 100);
  add_sudt(3, 100);
  gen_input_cell();
  load(&container, 0, CKB_SOURCE_GROUP_INPUT);
  merge(&container);
  CHECK(container.count, 3);
}


int main() {
  printf("Start testing ... It fails when exit with non-zero or abort!\n");
  {
    simple_entry_t input[]  = {{1, 100}, {2, 200}, {3, 300}, {1, 100}, {2, 200}, {3, 300}, {1, 100}, {2, 200}, {3, 300}};
    simple_entry_t output[] = {{1, 100}, {2, 200}, {3, 300}, {1, 100}, {2, 200}, {3, 300}, {1, 100}, {2, 200}, {3, 300}};
    test(0, input, COUNT_OF(input), output, COUNT_OF(output));
  }
  {
    simple_entry_t input[] = {{1, 100}, {2, 200}, {3, 300}};
    simple_entry_t output[] = {{1, 100}, {2, 200}, {3, 300}};
    test(0, input, COUNT_OF(input), output, COUNT_OF(output));
  }
  {
    simple_entry_t input[] = { {2, 200}, {3, 300}};
    simple_entry_t output[] = {{1, 100}, {2, 200}, {3, 300}};
    test(ERROR_INVALID_OUTPUT, input, COUNT_OF(input), output, COUNT_OF(output));
  }
  {
    simple_entry_t input[] = {{1, 100}, {2, 200}, {3, 300}, {3, 300}, {3, 300}, {2, 300}};
    simple_entry_t output[] = {{2, 200}, {3, 300}};
    test(0, input, COUNT_OF(input), output, COUNT_OF(output));
  }
  {
    // no output is valid
    simple_entry_t input[] = {{1, 100}};
    simple_entry_t output[] = {};
    test(0, input, COUNT_OF(input), output, 0);
  }
  stress_test();
  random_test();

  test_1();

  printf("\n-------------\nAll test cases passed\n-----------\n");
  return 0;
}
