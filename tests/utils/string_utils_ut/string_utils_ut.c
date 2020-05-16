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

#include "asc_security_core/utils/string_utils.h"

static void string_utils_ut_value_or_empty(void** state) {
    assert_string_equal("", string_utils_value_or_empty(NULL));
    assert_string_equal("", string_utils_value_or_empty(""));
    assert_string_equal("a", string_utils_value_or_empty("a"));
}

static void string_utils_ut_is_blank(void** state) {
    assert_true(string_utils_is_blank(NULL));
    assert_true(string_utils_is_blank(""));
    assert_true(string_utils_is_blank(" "));
    assert_true(string_utils_is_blank("\t\r\n\f\v"));
    assert_false(string_utils_is_blank(" a"));
    assert_false(string_utils_is_blank("a "));
    assert_false(string_utils_is_blank("abc"));
}

int main (void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(string_utils_ut_value_or_empty),
        cmocka_unit_test(string_utils_ut_is_blank),
    };

    return cmocka_run_group_tests_name("string_utils_ut", tests, NULL, NULL);
}
