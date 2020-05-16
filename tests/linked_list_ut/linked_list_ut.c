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

#include <stddef.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include "asc_security_core/object_pool.h"
#include "asc_security_core/utils/collection/linked_list.h"

#define OBJECT_1 "object1"
#define OBJECT_2 "object2"
#define OBJECT_3 "object3"
#define OBJECT_4 "object4"
#define OBJECT_5 "object5"
#define EXISTING_OBJECT OBJECT_2
#define NON_EXISTING_OBJECT "TEST"

#define OBJECT_COUNT 4
#define OBJECT_DATA_SIZE 100

typedef struct object_tag {
    COLLECTION_INTERFACE(struct object_tag);
    char data[OBJECT_DATA_SIZE];
} object;

LINKED_LIST_DECLARATIONS(object);
LINKED_LIST_DEFINITIONS(object);
OBJECT_POOL_DECLARATIONS(object, OBJECT_COUNT);
OBJECT_POOL_DEFINITIONS(object, OBJECT_COUNT);

typedef object* object_handle;

char* linked_list_ut_list_objects[] = {
    OBJECT_1,
    OBJECT_2,
    OBJECT_3,
    OBJECT_4,
    OBJECT_5
};

object object1;
object object2;
object object3;
object object4;
object object5;

static void linked_list_ut_action(object_handle object_handle, void *context) {
    memset(object_handle->data, 0, OBJECT_DATA_SIZE);
    memcpy(object_handle->data, NON_EXISTING_OBJECT, sizeof(NON_EXISTING_OBJECT));
}

static bool linked_list_ut_condition(object_handle object_handle, void* condition_input) {
    return (strcmp(object_handle->data, (char*)condition_input) == 0);
}

static void linked_list_ut_object_free(object_handle object_handle) {
    object_pool_free(object, object_handle);
}

static void linked_list_ut_create(void** state) {
    memcpy(&(object1.data), OBJECT_1, sizeof(OBJECT_1) +1);

    linked_list_object linked_list = { 0 };
    linked_list_object_handle linked_list_handle = &linked_list;

    linked_list_object_init(linked_list_handle, NULL);

    object_handle object_handle = linked_list_object_add_first(linked_list_handle, &object1);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_1, object_handle->data);
    assert_string_equal(OBJECT_1, linked_list_object_get_first(linked_list_handle)->data);
    assert_int_equal(1, linked_list_object_get_size(linked_list_handle));
}

static void linked_list_ut_create_and_add(void** state) {
    linked_list_object linked_list = { 0 };
    linked_list_object_handle linked_list_handle = &linked_list;

    linked_list_object_init(linked_list_handle, NULL);

    object_handle object_handle = linked_list_object_add_first(linked_list_handle, &object1);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_1, object_handle->data);
    assert_string_equal(OBJECT_1, linked_list_object_get_first(linked_list_handle)->data);
    assert_int_equal(1, linked_list_object_get_size(linked_list_handle));
}

static void linked_list_ut_add_first_twice(void** state) {
    linked_list_object linked_list = { 0 };
    linked_list_object_handle linked_list_handle = &linked_list;

    linked_list_object_init(linked_list_handle, NULL);

    object_handle object_handle = linked_list_object_add_first(linked_list_handle, &object1);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_1, object_handle->data);
    assert_int_equal(1, linked_list_object_get_size(linked_list_handle));
    assert_string_equal(OBJECT_1, linked_list_object_get_first(linked_list_handle)->data);

    object_handle = linked_list_object_add_first(linked_list_handle, &object2);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_2, object_handle->data);
    assert_int_equal(2, linked_list_object_get_size(linked_list_handle));
    assert_string_equal(OBJECT_2, linked_list_object_get_first(linked_list_handle)->data);
    assert_string_equal(OBJECT_1, linked_list_object_get_last(linked_list_handle)->data);
    assert_int_equal(2, linked_list_object_get_size(linked_list_handle));
}

static void linked_list_ut_remove_item(void** state) {
    linked_list_iterator_object linked_list_iterator = {0};
    linked_list_iterator_object_handle linked_list_iterator_handle = &linked_list_iterator;
    linked_list_object linked_list = { 0 };
    linked_list_object_handle linked_list_handle = &linked_list;

    linked_list_object_init(linked_list_handle, NULL);

    linked_list_object_add_last(linked_list_handle, &object1);
    linked_list_object_add_last(linked_list_handle, &object2);
    linked_list_object_add_last(linked_list_handle, &object3);
    linked_list_object_add_last(linked_list_handle, &object4);
    linked_list_object_add_last(linked_list_handle, &object5);

    linked_list_object_remove(linked_list_handle, &object3);

    linked_list_iterator_object_init(linked_list_iterator_handle, linked_list_handle);
    assert_string_equal(OBJECT_1, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_string_equal(OBJECT_2, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_string_equal(OBJECT_4, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_string_equal(OBJECT_5, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_null(linked_list_iterator_object_next(linked_list_iterator_handle));

    linked_list_object_remove(linked_list_handle, &object1);
    linked_list_iterator_object_init(linked_list_iterator_handle, linked_list_handle);
    assert_string_equal(OBJECT_2, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_string_equal(OBJECT_4, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_string_equal(OBJECT_5, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_null(linked_list_iterator_object_next(linked_list_iterator_handle));

    linked_list_object_remove(linked_list_handle, &object5);
    linked_list_iterator_object_init(linked_list_iterator_handle, linked_list_handle);
    assert_string_equal(OBJECT_2, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_string_equal(OBJECT_4, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_null(linked_list_iterator_object_next(linked_list_iterator_handle));

    linked_list_object_remove(linked_list_handle, &object5);
    linked_list_object_remove(linked_list_handle, &object5);
    linked_list_iterator_object_init(linked_list_iterator_handle, linked_list_handle);
    assert_string_equal(OBJECT_2, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_string_equal(OBJECT_4, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_null(linked_list_iterator_object_next(linked_list_iterator_handle));
}

static void linked_list_ut_concat_lists(void** state) {
    linked_list_iterator_object linked_list_iterator = {0};
    linked_list_iterator_object_handle linked_list_iterator_handle = &linked_list_iterator;

    linked_list_object linked_list_first = { 0 };
    linked_list_object_handle linked_list_first_handle = &linked_list_first;
    linked_list_object_init(linked_list_first_handle, NULL);

    linked_list_object linked_list_second = { 0 };
    linked_list_object_handle linked_list_second_handle = &linked_list_second;
    linked_list_object_init(linked_list_second_handle, NULL);

    linked_list_object_add_last(linked_list_first_handle, &object1);
    linked_list_object_add_last(linked_list_first_handle, &object2);
    linked_list_object_add_last(linked_list_first_handle, &object3);

    linked_list_object_add_last(linked_list_second_handle, &object4);
    linked_list_object_add_last(linked_list_second_handle, &object5);

    linked_list_object_concat(linked_list_first_handle, linked_list_second_handle);
    linked_list_object_handle linked_list_handle = linked_list_first_handle;

    linked_list_iterator_object_init(linked_list_iterator_handle, linked_list_handle);
    assert_string_equal(OBJECT_1, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_string_equal(OBJECT_2, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_string_equal(OBJECT_3, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_string_equal(OBJECT_4, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_string_equal(OBJECT_5, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_null(linked_list_iterator_object_next(linked_list_iterator_handle));

    linked_list_object_concat(linked_list_first_handle, NULL);
    linked_list_handle = linked_list_first_handle;
    linked_list_iterator_object_init(linked_list_iterator_handle, linked_list_handle);
    assert_string_equal(OBJECT_1, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_string_equal(OBJECT_2, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_string_equal(OBJECT_3, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_string_equal(OBJECT_4, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_string_equal(OBJECT_5, linked_list_iterator_object_next(linked_list_iterator_handle)->data);
    assert_null(linked_list_iterator_object_next(linked_list_iterator_handle));

    linked_list_object_concat(NULL, linked_list_handle);
}

static void linked_list_ut_add_first_null_input(void** state) {
    linked_list_object linked_list = { 0 };
    linked_list_object_handle linked_list_handle = &linked_list;

    linked_list_object_init(linked_list_handle, NULL);

    object_handle object_handle = linked_list_object_add_first(NULL, &object1);
    assert_null(object_handle);
    object_handle = linked_list_object_add_first(linked_list_handle, NULL);
    assert_null(object_handle);
}

static void linked_list_ut_remove_first(void** state) {
    linked_list_object linked_list = { 0 };
    linked_list_object_handle linked_list_handle = &linked_list;

    linked_list_object_init(linked_list_handle, NULL);

    object_handle object_handle = linked_list_object_add_first(linked_list_handle, &object1);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_1, object_handle->data);
    assert_int_equal(1, linked_list_object_get_size(linked_list_handle));
    assert_string_equal(OBJECT_1, linked_list_object_get_first(linked_list_handle)->data);

    object_handle = linked_list_object_add_first(linked_list_handle, &object2);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_2, object_handle->data);
    assert_int_equal(2, linked_list_object_get_size(linked_list_handle));
    assert_string_equal(OBJECT_2, linked_list_object_get_first(linked_list_handle)->data);

    object_handle = linked_list_object_remove_first(linked_list_handle);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_2, object_handle->data);
    assert_int_equal(1, linked_list_object_get_size(linked_list_handle));

    object_handle = linked_list_object_remove_first(linked_list_handle);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_1, object_handle->data);
    assert_int_equal(0, linked_list_object_get_size(linked_list_handle));

    object_handle = linked_list_object_remove_first(linked_list_handle);
    assert_null(object_handle);
    assert_null(linked_list_object_get_first(linked_list_handle));
    assert_null(linked_list_object_get_last(linked_list_handle));
}

static void linked_list_ut_remove_first_null_input(void** state) {
    linked_list_object linked_list = { 0 };
    linked_list_object_handle linked_list_handle = &linked_list;

    linked_list_object_init(linked_list_handle, NULL);

    object_handle object_handle = linked_list_object_remove_first(NULL);
    assert_null(object_handle);
}

static void linked_list_ut_remove_last_null_input(void** state) {
    linked_list_object linked_list = { 0 };
    linked_list_object_handle linked_list_handle = &linked_list;

    linked_list_object_init(linked_list_handle, NULL);

    object_handle object_handle = linked_list_object_remove_last(NULL);
    assert_null(object_handle);
}

static void linked_list_ut_add_last_twice(void** state) {
    linked_list_object linked_list = { 0 };
    linked_list_object_handle linked_list_handle = &linked_list;

    linked_list_object_init(linked_list_handle, NULL);

    object_handle object_handle = linked_list_object_add_last(linked_list_handle, &object1);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_1, object_handle->data);
    assert_int_equal(1, linked_list_object_get_size(linked_list_handle));

    object_handle = linked_list_object_add_last(linked_list_handle, &object2);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_2, object_handle->data);
    assert_string_equal(OBJECT_1, linked_list_object_get_first(linked_list_handle)->data);
    assert_string_equal(OBJECT_2, linked_list_object_get_last(linked_list_handle)->data);
    assert_int_equal(2, linked_list_object_get_size(linked_list_handle));

    object_handle = linked_list_object_remove_first(linked_list_handle);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_1, object_handle->data);
    assert_int_equal(1, linked_list_object_get_size(linked_list_handle));
    assert_string_equal(OBJECT_2, linked_list_object_get_first(linked_list_handle)->data);
    assert_string_equal(OBJECT_2, linked_list_object_get_last(linked_list_handle)->data);

    object_handle = linked_list_object_remove_last(linked_list_handle);
    assert_non_null(object_handle);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_2, object_handle->data);
    assert_int_equal(0, linked_list_object_get_size(linked_list_handle));
    assert_null(linked_list_object_get_first(linked_list_handle));
    assert_null(linked_list_object_get_last(linked_list_handle));
}

static void linked_list_ut_foreach_object(void** state) {
    linked_list_object linked_list = { 0 };
    linked_list_object_handle linked_list_handle = &linked_list;

    linked_list_object_init(linked_list_handle, NULL);

    object_handle object_handle;
    linked_list_object_add_first(linked_list_handle, &object1);
    linked_list_object_add_first(linked_list_handle, &object2);
    linked_list_object_add_first(linked_list_handle, &object3);
    linked_list_object_add_first(linked_list_handle, &object4);
    linked_list_object_add_first(linked_list_handle, &object5);

    linked_list_object_foreach(linked_list_handle, linked_list_ut_action, NULL);
    assert_string_equal(NON_EXISTING_OBJECT, linked_list_object_get_first(linked_list_handle)->data);

    linked_list_iterator_object linked_list_iterator = {0};
    linked_list_iterator_object_handle linked_list_iterator_handle = &linked_list_iterator;
    linked_list_iterator_object_init(linked_list_iterator_handle, linked_list_handle);
    while ((object_handle = linked_list_iterator_object_next(linked_list_iterator_handle)) != NULL) {
        assert_string_equal(NON_EXISTING_OBJECT, object_handle->data);
    }
}

static void linked_list_ut_find_existing_object(void** state) {
    linked_list_object linked_list = { 0 };
    linked_list_object_handle linked_list_handle = &linked_list;

    linked_list_object_init(linked_list_handle, NULL);

    linked_list_object_add_first(linked_list_handle, &object1);
    linked_list_object_add_first(linked_list_handle, &object2);
    linked_list_object_add_first(linked_list_handle, &object3);
    linked_list_object_add_first(linked_list_handle, &object4);
    linked_list_object_add_first(linked_list_handle, &object5);

    object_handle object_handle = linked_list_object_find(linked_list_handle, linked_list_ut_condition, EXISTING_OBJECT);
    assert_non_null(object_handle);
    assert_string_equal(EXISTING_OBJECT, object_handle->data);
}

static void linked_list_ut_find_non_existing_object(void** state) {
    linked_list_object linked_list = { 0 };
    linked_list_object_handle linked_list_handle = &linked_list;

    linked_list_object_init(linked_list_handle, NULL);

    linked_list_object_add_first(linked_list_handle, &object1);
    linked_list_object_add_first(linked_list_handle, &object2);
    linked_list_object_add_first(linked_list_handle, &object3);
    linked_list_object_add_first(linked_list_handle, &object4);
    linked_list_object_add_first(linked_list_handle, &object5);

    object_handle object_handle = linked_list_object_find(linked_list_handle, linked_list_ut_condition, NON_EXISTING_OBJECT);
    assert_null(object_handle);
}

static void linked_list_ut_iterate_through_list(void** state) {
    linked_list_object linked_list = { 0 };
    linked_list_object_handle linked_list_handle = &linked_list;

    linked_list_object_init(linked_list_handle, NULL);

    object_handle object_handle = linked_list_object_add_first(linked_list_handle, &object1);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_1, object_handle->data);
    assert_string_equal(OBJECT_1, linked_list_handle->head->data);
    assert_int_equal(1, linked_list_handle->size);

    linked_list_object_add_first(linked_list_handle, &object2);
    linked_list_object_add_first(linked_list_handle, &object3);
    linked_list_object_add_first(linked_list_handle, &object4);
    linked_list_object_add_first(linked_list_handle, &object5);

    linked_list_iterator_object linked_list_iterator = {0};
    linked_list_iterator_object_handle linked_list_iterator_handle = &linked_list_iterator;

    linked_list_iterator_object_init(linked_list_iterator_handle, linked_list_handle);
    uint32_t iteration = sizeof(linked_list_ut_list_objects) / sizeof(OBJECT_1);
    while ((object_handle = linked_list_iterator_object_next(linked_list_iterator_handle)) != NULL) {
        assert_string_equal(linked_list_ut_list_objects[iteration-1], object_handle->data);
        iteration--;
    }

    assert_null(object_handle);
}

static void linked_list_ut_deinit_with_different_deinit_functions(void** state) {
    linked_list_object linked_list = { 0 };
    linked_list_object_handle linked_list_handle = &linked_list;

    linked_list_object_init(linked_list_handle, NULL);
    linked_list_object_add_first(linked_list_handle, &object1);
    linked_list_object_add_first(linked_list_handle, &object2);
    linked_list_object_add_first(linked_list_handle, &object3);
    linked_list_object_add_first(linked_list_handle, &object4);
    linked_list_object_add_first(linked_list_handle, &object5);
    linked_list_object_deinit(linked_list_handle);

    assert_null(linked_list_handle->head);
    assert_null(linked_list_handle->tail);
    assert_int_equal(0, linked_list_handle->size);

    linked_list_object_init(linked_list_handle, linked_list_ut_object_free);
    object_handle object_handle;
    object_handle = object_pool_get(object);
    linked_list_object_add_first(linked_list_handle, object_handle);
    object_handle = object_pool_get(object);
    linked_list_object_add_first(linked_list_handle, object_handle);
    object_handle = object_pool_get(object);
    linked_list_object_add_first(linked_list_handle, object_handle);
    object_handle = object_pool_get(object);
    linked_list_object_add_first(linked_list_handle, object_handle);
    linked_list_object_deinit(linked_list_handle);

    assert_null(linked_list_handle->head);
    assert_null(linked_list_handle->tail);
    assert_int_equal(0, linked_list_handle->size);
}

static int linked_list_ut_setup(void** state) {
    memset(&(object1.data), 0, OBJECT_DATA_SIZE);
    memcpy(&(object1.data), OBJECT_1, sizeof(OBJECT_1));

    memset(&(object2.data), 0, OBJECT_DATA_SIZE);
    memcpy(&(object2.data), OBJECT_2, sizeof(OBJECT_2));

    memset(&(object3.data), 0, OBJECT_DATA_SIZE);
    memcpy(&(object3.data), OBJECT_3, sizeof(OBJECT_3));

    memset(&(object4.data), 0, OBJECT_DATA_SIZE);
    memcpy(&(object4.data), OBJECT_4, sizeof(OBJECT_4));

    memset(&(object5.data), 0, OBJECT_DATA_SIZE);
    memcpy(&(object5.data), OBJECT_5, sizeof(OBJECT_5));
    return 0;
}

static int linked_list_ut_teardown(void** state) {
    return 0;
}

int main (void) {
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(linked_list_ut_create, linked_list_ut_setup, linked_list_ut_teardown),
    cmocka_unit_test_setup_teardown(linked_list_ut_create_and_add, linked_list_ut_setup, linked_list_ut_teardown),
    cmocka_unit_test_setup_teardown(linked_list_ut_add_first_twice, linked_list_ut_setup, linked_list_ut_teardown),
    cmocka_unit_test_setup_teardown(linked_list_ut_remove_item, linked_list_ut_setup, linked_list_ut_teardown),
    cmocka_unit_test_setup_teardown(linked_list_ut_concat_lists, linked_list_ut_setup, linked_list_ut_teardown),
    cmocka_unit_test_setup_teardown(linked_list_ut_add_first_null_input, linked_list_ut_setup, linked_list_ut_teardown),
    cmocka_unit_test_setup_teardown(linked_list_ut_remove_first, linked_list_ut_setup, linked_list_ut_teardown),
    cmocka_unit_test_setup_teardown(linked_list_ut_remove_first_null_input, linked_list_ut_setup, linked_list_ut_teardown),
    cmocka_unit_test_setup_teardown(linked_list_ut_remove_last_null_input, linked_list_ut_setup, linked_list_ut_teardown),
    cmocka_unit_test_setup_teardown(linked_list_ut_add_last_twice, linked_list_ut_setup, linked_list_ut_teardown),
    cmocka_unit_test_setup_teardown(linked_list_ut_foreach_object, linked_list_ut_setup, linked_list_ut_teardown),
    cmocka_unit_test_setup_teardown(linked_list_ut_find_existing_object, linked_list_ut_setup, linked_list_ut_teardown),
    cmocka_unit_test_setup_teardown(linked_list_ut_find_non_existing_object, linked_list_ut_setup, linked_list_ut_teardown),
    cmocka_unit_test_setup_teardown(linked_list_ut_iterate_through_list, linked_list_ut_setup, linked_list_ut_teardown),
    cmocka_unit_test_setup_teardown(linked_list_ut_deinit_with_different_deinit_functions, linked_list_ut_setup, linked_list_ut_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}