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

#include <math.h>

#include "asc_security_core/configuration.h"
#include "asc_security_core/message_schema_consts.h"
#include "asc_security_core/model/message.h"

#define TEST_EMPTY_MESSAGE 81

static void message_ut_get_create_empty_message(void** state) {
    // arrange
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    char expected[ASC_MESSAGE_MAX_SIZE] = "{"
        "\"AgentVersion\":\"1\","
        "\"AgentId\":\"abcdefg\","
        "\"MessageSchemaVersion\":\"1.0\","
        "\"Events\":[]"
    "}";

    char actual[ASC_MESSAGE_MAX_SIZE] = { 0 };

    message_t* message_ptr = NULL;

    // act
    {
        message_ptr = message_init("abcdefg", "1");
        assert_non_null(message_ptr);
    }

    // assert
    {
        assert_false(message_has_events(message_ptr));

        result = message_to_json(message_ptr, actual, ASC_MESSAGE_MAX_SIZE);
        assert_string_equal(expected, actual);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        assert_int_equal(message_get_length(message_ptr), TEST_EMPTY_MESSAGE);
    }

    // cleanup
    {
        message_deinit(message_ptr);
        message_ptr = NULL;
    }
}

static void message_ut_get_cappend_simple_message(void** state) {
    // arrange
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    message_t* message_ptr = NULL;
    event_t* event_ptr = NULL;

    char expected[ASC_MESSAGE_MAX_SIZE] = "{"
        "\"AgentVersion\":\"1\","
        "\"AgentId\":\"abcdefg\","
        "\"MessageSchemaVersion\":\"1.0\","
        "\"Events\":["
            "{"
                "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
                "\"Name\":\"SystemInformation\","
                "\"PayloadSchemaVersion\":\"1.0\","
                "\"Category\":\"Periodic\","
                "\"EventType\":\"Security\","
                "\"TimestampLocal\":\"2012-12-12T14:12:12\","
                "\"TimestampUTC\":\"2012-12-12T12:12:12\","
                "\"Payload\":[],"
                "\"IsEmpty\":true"
            "}"
        "]"
    "}";

    char actual[ASC_MESSAGE_MAX_SIZE] = { 0 };

    // act
    {
        message_ptr = message_init("abcdefg", "1");
        assert_non_null(message_ptr);

        assert_false(message_has_events(message_ptr));

        event_ptr = event_init(SYSTEM_INFORMATION_PAYLOAD_SCHEMA_VERSION, SYSTEM_INFORMATION_NAME, EVENT_PERIODIC_CATEGORY, EVENT_TYPE_SECURITY_VALUE, 0);
        assert_non_null(event_ptr);

        result = message_append(message_ptr, event_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        assert_true(message_has_events(message_ptr));
    }

    // assert
    {
        result = message_to_json(message_ptr, actual, ASC_MESSAGE_MAX_SIZE);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        assert_string_equal(expected, actual);
    }


    // cleanup
    {
        event_deinit(event_ptr);
        event_ptr = NULL;

        message_deinit(message_ptr);
        message_ptr = NULL;
    }

}

static void message_ut_init_bad_arguments(void** state) {
    message_t* message_ptr = NULL;

    message_ptr = message_init("bob", "");
    assert_null(message_ptr);

    message_ptr = message_init("", "bob");
    assert_null(message_ptr);
}

static void message_ut_append_huge_message_fails(void** state) {
    // arrange
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    message_t* message_ptr = NULL;
    event_t* event_ptr = NULL;

    message_ptr = message_init("abcdefg", "1");
    assert_non_null(message_ptr);

    event_ptr = event_init(SYSTEM_INFORMATION_PAYLOAD_SCHEMA_VERSION, SYSTEM_INFORMATION_NAME, EVENT_PERIODIC_CATEGORY, EVENT_TYPE_SECURITY_VALUE, 0);
    assert_non_null(event_ptr);

    event_build(event_ptr);

    {
        // add events to fill message capacity
        size_t message_build_suffix_length = 3; // "]}\0"
        size_t message_available_space = (message_get_capacity(message_ptr) - message_get_length(message_ptr) - message_build_suffix_length);
        size_t num_of_events_in_message_available_space = message_available_space / event_get_length(event_ptr);
        size_t num_of_commas_between_events = num_of_events_in_message_available_space - 1;
        size_t num_of_events_to_add = (message_available_space - num_of_commas_between_events) / event_get_length(event_ptr);

        for (uint32_t i = 0; i < num_of_events_to_add; i++) {
            result = message_append(message_ptr, event_ptr);
            assert_int_equal(IOTSECURITY_RESULT_OK, result);
        }
    }

    // act
    {
        result = message_append(message_ptr, event_ptr);
    }

    // assert
    {
        assert_int_equal(IOTSECURITY_RESULT_EXCEPTION, result);

        assert_false(message_can_append(message_ptr, event_ptr));
    }

    // cleanup
    {
        event_deinit(event_ptr);
        event_ptr = NULL;

        message_deinit(message_ptr);
        message_ptr = NULL;
    }
}

static int message_ut_setup(void** state) {
    return 0;
}

static int message_ut_teardown(void** state) {
    return 0;
}

int main (void) {
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(message_ut_get_create_empty_message, message_ut_setup, message_ut_teardown),
    cmocka_unit_test_setup_teardown(message_ut_get_cappend_simple_message, message_ut_setup, message_ut_teardown),
    cmocka_unit_test_setup_teardown(message_ut_init_bad_arguments, message_ut_setup, message_ut_teardown),
    cmocka_unit_test_setup_teardown(message_ut_append_huge_message_fails, message_ut_setup, message_ut_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
