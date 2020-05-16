/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <stddef.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include <stdint.h>
#include <stdbool.h>

#include "data.h"

#define DATA_HASHSET_SIZE 70

struct data_tag {
    COLLECTION_INTERFACE(data);
    int payload;
};

int hashset_data_equals(data* a, data* b) {
    if (a == b) return 1;
    if (a == NULL || b == NULL) return 0;
    return a->payload == b->payload;
}

unsigned int hashset_data_hash(data* element) {
    return (unsigned int)element->payload;
}

void hashset_data_update(data* old_element, data* new_element) {
  if (old_element == NULL || new_element == NULL) return;
  old_element->payload = new_element->payload;
}

static void hashset_data_foreach_set_to_neg1(data* element, void* ignored) {
    element->payload = -1;
}

HASHSET_DEFINITIONS(data, 70);

// hashset_##type##_init should initialize the table entries to NULL.
static void hashset_init_nulls_table_entries(void** state) {
    // Arrange
    data* data_hashset[DATA_HASHSET_SIZE] = { (data*)0x1 };

    // Act
    hashset_data_init(data_hashset);

    // Assert
    for (int i = 0; i < DATA_HASHSET_SIZE; ++i) {
        assert_null(data_hashset[i]);
    }
}

// hashset_##type##_init should handle a NULL argument.
static void hashset_init_handles_null_argument(void** state) {
    // Act
    hashset_data_init(NULL);

    // Assert
    // If the above fails, we get a SIGSEGV. The next assert is for the test to pass otherwise.
    assert_true(1);
}

// hashset_##type##_add_or_update should add every element to the correct place.
static void hashset_add_adds_all_elements_to_the_right_place(void** state) {
    // Arrange
    data data_pool[100] = {{ .previous = NULL, .next = NULL, .payload = 0 }};
    data* data_hashset[DATA_HASHSET_SIZE] = { NULL };
    hashset_data_init(data_hashset);

    // Act
    for (int i = 0; i < 100; ++i) {
        data_pool[i].payload = i;
        hashset_data_add_or_update(data_hashset, &data_pool[i]);
    }

    // Assert
    for (int i = 0; i < DATA_HASHSET_SIZE; ++i) {
        data* current_element = data_hashset[i];
        while (current_element != NULL) {
            // Check for correct place
            assert_int_equal(i, current_element->payload % DATA_HASHSET_SIZE);
            current_element->payload = -1;
            current_element = current_element->next;
        }
    }

    // Check that all the elements got inside the table
    for (int i = 0; i < 100; ++i) {
        assert_int_equal(-1, (int)data_pool[i].payload);
    }
}

// hashset_##type##_find should find every element added.
static void hashset_find_can_find_all_elements(void** state) {
    // Arrange
    srand(0);
    data data_pool[100] = {{ .previous = NULL, .next = NULL, .payload = 0 }};
    data* data_hashset[DATA_HASHSET_SIZE] = { NULL };
    hashset_data_init(data_hashset);
    for (int i = 0; i < 100; ++i) {
        data_pool[i].payload = rand();
        hashset_data_add_or_update(data_hashset, &data_pool[i]);
    }

    // Act & Assert
    for (int i = 0; i < 100; ++i) {
        data* found = hashset_data_find(data_hashset, &data_pool[i]);
        assert_int_equal((void*)&data_pool[i], (void*)found);
    }
}

// hashset_##type##_for_each should traverse all elements.
static void hashset_for_each_traverse_all_elements(void** state) {
    // Arrange
    data data_pool[100] = {{ .previous = NULL, .next = NULL, .payload = 0 }};
    data* data_hashset[DATA_HASHSET_SIZE] = { NULL };
    hashset_data_init(data_hashset);
    for (int i = 0; i < 100; ++i) {
        data_pool[i].payload = i;
        hashset_data_add_or_update(data_hashset, &data_pool[i]);
    }

    // Act
    hashset_data_for_each(data_hashset, hashset_data_foreach_set_to_neg1, NULL);

    // Assert
    for (int i = 0; i < 100; ++i) {
        assert_int_equal(-1, (int)data_pool[i].payload);
    }
}

// hashset_##type##_deinit should traverse all elements and deinit the table entries.
static void hashset_deinit_traverse_all_elements_and_nulls_table_entries(void** state) {
    // Arrange
    data data_pool[100] = {{ .previous = NULL, .next = NULL, .payload = 0 }};
    data* data_hashset[DATA_HASHSET_SIZE] = { NULL };
    hashset_data_init(data_hashset);
    for (int i = 0; i < 100; ++i) {
        data_pool[i].payload = i;
        hashset_data_add_or_update(data_hashset, &data_pool[i]);
    }

    // Act
    hashset_data_clear(data_hashset, hashset_data_foreach_set_to_neg1, NULL);

    // Assert
    // Check that we traversed all elements
    for (int i = 0; i < 100; ++i) {
        assert_int_equal(-1, (int)data_pool[i].payload);
        assert_null(data_pool[i].previous);
        assert_null(data_pool[i].next);
    }
    // Check that we NULLed all table entries
    for (int i = 0; i < DATA_HASHSET_SIZE; ++i) {
        assert_null(data_hashset[i]);
    }
}

// hashset_##type##_deinit should deinit the table entries without foreach function.
static void hashset_deinit_nulls_table_entries(void** state) {
    // Arrange
    data data_pool[100] = {{ .previous = NULL, .next = NULL, .payload = 0 }};
    data* data_hashset[DATA_HASHSET_SIZE] = { NULL };
    hashset_data_init(data_hashset);
    for (int i = 0; i < 100; ++i) {
        data_pool[i].payload = i;
        hashset_data_add_or_update(data_hashset, &data_pool[i]);
    }

    // Act
    hashset_data_clear(data_hashset, NULL, NULL);

    // Assert
    // Check that we nulled all elements list pointers
    for (int i = 0; i < 100; ++i) {
        assert_int_equal(i, (int)data_pool[i].payload);
        assert_null(data_pool[i].previous);
        assert_null(data_pool[i].next);
    }
    // Check that we NULLed all table entries
    for (int i = 0; i < DATA_HASHSET_SIZE; ++i) {
        assert_null(data_hashset[i]);
    }
}

static int hashset_ut_setup(void** state) {
    return 0;
}

static int hashset_ut_teardown(void** state) {
    return 0;
}

int main (void) {
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(hashset_init_nulls_table_entries, hashset_ut_setup, hashset_ut_teardown),
    cmocka_unit_test_setup_teardown(hashset_init_handles_null_argument, hashset_ut_setup, hashset_ut_teardown),
    cmocka_unit_test_setup_teardown(hashset_add_adds_all_elements_to_the_right_place, hashset_ut_setup, hashset_ut_teardown),
    cmocka_unit_test_setup_teardown(hashset_find_can_find_all_elements, hashset_ut_setup, hashset_ut_teardown),
    cmocka_unit_test_setup_teardown(hashset_for_each_traverse_all_elements, hashset_ut_setup, hashset_ut_teardown),
    cmocka_unit_test_setup_teardown(hashset_deinit_traverse_all_elements_and_nulls_table_entries, hashset_ut_setup, hashset_ut_teardown),
    cmocka_unit_test_setup_teardown(hashset_deinit_nulls_table_entries, hashset_ut_setup, hashset_ut_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
