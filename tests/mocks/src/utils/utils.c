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

#include <stddef.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include "asc_security_core/asc/asc_span.h"

#include "../../inc/utils/utils.h"

#define MAX_ENTY_LENGTH 256

void assert_asc_span_equal(asc_span exp, const char *value) {
    char expected[MAX_ENTY_LENGTH];

    assert_int_equal(ASC_OK, asc_span_to_str(expected, MAX_ENTY_LENGTH, exp));
    assert_string_equal(expected, value);
}
