#include "../inc/utils/irand.h"

static uint32_t random_value = 0;

void mock_rand_int_set_value(uint32_t value) {
    random_value = value;
}


uint32_t __wrap_irand_int(void) {
    return random_value;
}
