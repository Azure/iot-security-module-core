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

#define OBJECT_POOL_TYPE_TEST_OBJECT_COUNT 4
typedef struct TEST_OBJECT_TAG {
    COLLECTION_INTERFACE(struct TEST_OBJECT_TAG);

    char data[100];
} TEST_OBJECT;

OBJECT_POOL_DECLARATIONS(TEST_OBJECT, OBJECT_POOL_TYPE_TEST_OBJECT_COUNT);
OBJECT_POOL_DEFINITIONS(TEST_OBJECT, OBJECT_POOL_TYPE_TEST_OBJECT_COUNT);

typedef TEST_OBJECT* TEST_OBJECT_HANDLE;

static void object_pool_ut_create_and_destroy_expect_success(void** state) {
    TEST_OBJECT_HANDLE test_handle = object_pool_get(TEST_OBJECT);
    assert_non_null(test_handle);

    object_pool_free(TEST_OBJECT, test_handle);
}

static void object_pool_ut_allocate_too_many_object_expect_failure(void** state) {
    TEST_OBJECT_HANDLE test_handle1 = object_pool_get(TEST_OBJECT);
    assert_non_null(test_handle1);

    TEST_OBJECT_HANDLE test_handle2 = object_pool_get(TEST_OBJECT);
    assert_non_null(test_handle2);

    TEST_OBJECT_HANDLE test_handle3 = object_pool_get(TEST_OBJECT);
    assert_non_null(test_handle3);

    TEST_OBJECT_HANDLE test_handle4 = object_pool_get(TEST_OBJECT);
    assert_non_null(test_handle4);

    TEST_OBJECT_HANDLE test_handle5 = object_pool_get(TEST_OBJECT);
    assert_null(test_handle5);

    object_pool_free(TEST_OBJECT, test_handle2);

    test_handle5 = object_pool_get(TEST_OBJECT);
    assert_non_null(test_handle5);

    test_handle2 = object_pool_get(TEST_OBJECT);
    assert_null(test_handle2);

    object_pool_free(TEST_OBJECT, test_handle1);
    object_pool_free(TEST_OBJECT, test_handle3);
    object_pool_free(TEST_OBJECT, test_handle4);
    object_pool_free(TEST_OBJECT, test_handle5);
}

static int  object_pool_ut_setup(void** state) {
    return 0;
}

static int  object_pool_ut_teardown(void** state) {
    return 0;
}

int main (void) {
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(object_pool_ut_create_and_destroy_expect_success, object_pool_ut_setup, object_pool_ut_teardown),
    cmocka_unit_test_setup_teardown(object_pool_ut_allocate_too_many_object_expect_failure, object_pool_ut_setup, object_pool_ut_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}