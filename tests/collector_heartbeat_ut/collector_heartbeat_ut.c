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

#include <stdlib.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdarg.h>
#include <cmocka.h>

#include "asc_security_core/configuration.h"
#include "asc_security_core/model/collector.h"
#include "asc_security_core/collectors/heartbeat.h"

static const char EXPECTED[ASC_EVENT_MAX_SIZE] = "{"
    "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
    "\"Name\":\"SystemInformation\","
    "\"PayloadSchemaVersion\":\"1.0\","
    "\"Category\":\"Periodic\","
    "\"EventType\":\"Security\","
    "\"TimestampLocal\":\"2012-12-12T14:12:12\","
    "\"TimestampUTC\":\"2012-12-12T12:12:12\","
    "\"Payload\":[],"
    "\"IsEmpty\":true"
"}";

static IOTSECURITY_RESULT _collector_internal_init(collector_internal_t* collector_internal_ptr) {
    return collector_heartbeat_init(collector_internal_ptr);
}

static void collector_heartbeat_ut_init_deinit(void** state) {
    collector_t* collector_ptr = *state;

    assert_non_null(collector_ptr);
}



static void collector_heartbeat_ut_collect_and_peek_single_event(void** state) {
    // arrange
    collector_t* collector_ptr = *state;
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    event_t* event_ptr = NULL;
    char actual[ASC_EVENT_MAX_SIZE] = { 0 };

    assert_non_null(collector_ptr);

    // act
    {
        result = collector_collect(collector_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = collector_peek_event(collector_ptr, &event_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
    }

    // assert
    {
        assert_non_null(event_ptr);

        result = event_get_data(event_ptr, actual, ASC_EVENT_MAX_SIZE);
        assert_non_null(actual);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        assert_string_equal(EXPECTED, actual);
    }
}

static int collector_heartbeat_ut_setup(void** state) {
    collector_t* collector_ptr = collector_init(_collector_internal_init);

    *state = collector_ptr;
    return 0;
}

static int collector_heartbeat_ut_teardown(void** state) {
    collector_t* collector_ptr = *state;

    if (collector_ptr != NULL) {
        collector_deinit(collector_ptr);
        *state = NULL;
    }

    return 0;
}

int main (void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            collector_heartbeat_ut_init_deinit,
            collector_heartbeat_ut_setup,
            collector_heartbeat_ut_teardown
        ),
        cmocka_unit_test_setup_teardown(
            collector_heartbeat_ut_collect_and_peek_single_event,
            collector_heartbeat_ut_setup,
            collector_heartbeat_ut_teardown
        ),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}