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

#include "asc_security_core/utils/collection/stack.h"

#define OBJECT_1 "object1"
#define OBJECT_2 "object2"
#define OBJECT_3 "object3"
#define OBJECT_4 "object4"

#define OBJECT_DATA_SIZE 100
typedef struct object_tag {
    COLLECTION_INTERFACE(struct object_tag);
    char data[OBJECT_DATA_SIZE];
} object;

STACK_DECLARATIONS(object)
STACK_DEFINITIONS(object)

typedef object* object_handle;

static void stack_ut_create_and_destroy_object(void** state) {
    stack_object stack;
    stack_object_handle stack_handle;
    stack_handle = &stack;
    stack_object_init(stack_handle);

    object object = { 0 };
    memcpy(&(object.data), OBJECT_1, sizeof(OBJECT_1) +1);
    stack_object_push(stack_handle, &object);

    object_handle object_handle = stack_object_pop(stack_handle);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_1, object_handle->data);
}

static void stack_ut_push_pop_permutations(void** state) {
    stack_object stack;
    stack_object_handle stack_handle;
    stack_handle = &stack;
    stack_object_init(stack_handle);

    object_handle object_handle = NULL;

    object object1 = { 0 };
    memcpy(&(object1.data), OBJECT_1, sizeof(OBJECT_1) +1);

    object object2 = { 0 };
    memcpy(&(object2.data), OBJECT_2, sizeof(OBJECT_2) +1);

    object object3 = { 0 };
    memcpy(&(object3.data), OBJECT_3, sizeof(OBJECT_3) +1);

    object object4  = { 0 };
    memcpy(&(object4.data), OBJECT_4, sizeof(OBJECT_4) +1);

    stack_object_push(stack_handle, &object1);

    object_handle = stack_object_peek(stack_handle);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_1, object_handle->data);

    stack_object_push(stack_handle, &object2);

    object_handle = stack_object_peek(stack_handle);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_2, object_handle->data);

    stack_object_push(stack_handle, &object3);

    object_handle = stack_object_peek(stack_handle);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_3, object_handle->data);

    stack_object_push(stack_handle, &object4);

    object_handle = stack_object_peek(stack_handle);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_4, object_handle->data);

    object_handle = stack_object_pop(stack_handle);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_4, object_handle->data);

    object_handle = stack_object_pop(stack_handle);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_3, object_handle->data);

    object_handle = stack_object_peek(stack_handle);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_2, object_handle->data);

    stack_object_push(stack_handle, &object4);

    object_handle = stack_object_peek(stack_handle);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_4, object_handle->data);

    object_handle = stack_object_pop(stack_handle);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_4, object_handle->data);

    object_handle = stack_object_pop(stack_handle);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_2, object_handle->data);

    object_handle = stack_object_pop(stack_handle);
    assert_non_null(object_handle);
    assert_string_equal(OBJECT_1, object_handle->data);

    object_handle = stack_object_pop(stack_handle);
    assert_null(object_handle);
}

static int stack_ut_setup(void** state) {
    return 0;
}

static int stack_ut_teardown(void** state) {
    return 0;
}

int main (void) {
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(stack_ut_create_and_destroy_object, stack_ut_setup, stack_ut_teardown),
    cmocka_unit_test_setup_teardown(stack_ut_push_pop_permutations, stack_ut_setup, stack_ut_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
