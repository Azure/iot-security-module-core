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
#include "../mocks/inc/collector_mock.h"
#include "asc_security_core/configuration.h"
#include "asc_security_core/model/collector.h"

static const char EXPECTED[ASC_EVENT_MAX_SIZE] = "{"
    "\"Id\":\"42b894a1-0e3f-4962-b79c-7dae124c7269\","
    "\"Name\":\"ListeningPorts\","
    "\"PayloadSchemaVersion\":\"1.0\","
    "\"Category\":\"Periodic\","
    "\"EventType\":\"Security\","
    "\"TimestampLocal\":\"2012-12-12T14:12:12\","
    "\"TimestampUTC\":\"2012-12-12T12:12:12\","
    "\"Payload\":[],"
    "\"IsEmpty\":true"
"}";

static IOTSECURITY_RESULT _collector_internal_init(collector_internal_t* collector_internal_ptr) {
    return collector_mock_init(collector_internal_ptr);
}

static void collector_ut_collect_event_from_single_collector(void** state) {
    collector_t* collector_ptr = *state;

    assert_non_null(collector_ptr);
}

static void collector_ut_peek_uninitialized(void** state) {
    collector_t* collector_ptr = NULL;
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    event_t* event_ptr = NULL;

    result = collector_peek_event(collector_ptr, &event_ptr);
    assert_int_equal(IOTSECURITY_RESULT_BAD_ARGUMENT, result);
    assert_null(event_ptr);
}

static void collector_ut_pop_uninitialized(void** state) {
    collector_t* collector_ptr = NULL;
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    event_t* event_ptr = NULL;

    result = collector_pop_event(collector_ptr, &event_ptr);
    assert_int_equal(IOTSECURITY_RESULT_BAD_ARGUMENT, result);
    assert_null(event_ptr);
}

static void collector_ut_collector_uninitialized(void** state) {
    collector_t* collector_ptr = NULL;
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;

    result = collector_collect(collector_ptr);
    assert_int_equal(IOTSECURITY_RESULT_BAD_ARGUMENT, result);
}

static void collector_ut_peek_no_events_in_queue(void** state) {
    collector_t* collector_ptr = *state;
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    event_t* event_ptr = NULL;

    assert_non_null(collector_ptr);

    result = collector_peek_event(collector_ptr, &event_ptr);
    assert_int_equal(IOTSECURITY_RESULT_EMPTY, result);
    assert_null(event_ptr);
}

static void collector_ut_pop_no_events_in_queue(void** state) {
    collector_t* collector_ptr = *state;
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    event_t* event_ptr = NULL;

    assert_non_null(collector_ptr);

    result = collector_pop_event(collector_ptr, &event_ptr);
    assert_int_equal(IOTSECURITY_RESULT_EMPTY, result);
    assert_null(event_ptr);
}

static void collector_ut_collect_and_peek_no_event_in_queue(void** state) {
    collector_t* collector_ptr = *state;
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    event_t* event_ptr = NULL;

    assert_non_null(collector_ptr);

    result = collector_collect(collector_ptr);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = collector_peek_event(collector_ptr, &event_ptr);
    assert_int_equal(IOTSECURITY_RESULT_EMPTY, result);
    assert_null(event_ptr);
}

static void collector_ut_collect_and_pop_no_event_in_queue(void** state) {
    collector_t* collector_ptr = *state;
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    event_t* event_ptr = NULL;

    assert_non_null(collector_ptr);

    result = collector_collect(collector_ptr);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = collector_pop_event(collector_ptr, &event_ptr);
    assert_int_equal(IOTSECURITY_RESULT_EMPTY, result);
    assert_null(event_ptr);
}

static void collector_ut_collect_and_peek_single_event(void** state) {
    // arrange
    collector_t* collector_ptr = *state;
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    event_t* event_ptr = NULL;
    char actual[ASC_EVENT_MAX_SIZE] = { 0 };

    assert_non_null(collector_ptr);

    result = collector_mock_add_event_to_queue(&collector_ptr->internal, "ListeningPorts");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

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

static void collector_ut_collect_and_pop_single_event(void** state) {
    // arrange
    collector_t* collector_ptr = *state;
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    event_t* event_ptr = NULL;

    char actual[ASC_EVENT_MAX_SIZE] = { 0 };

    assert_non_null(collector_ptr);

    result = collector_mock_add_event_to_queue(&collector_ptr->internal , "ListeningPorts");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    // act
    {
        result = collector_collect(collector_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = collector_pop_event(collector_ptr, &event_ptr);
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

    // cleanup
    {
        event_deinit(event_ptr);
        event_ptr = NULL;
    }
}

static void collector_ut_collect_and_pop_single_event_and_empty(void** state) {
    // arrange
    collector_t* collector_ptr = *state;
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    event_t* event_ptr1 = NULL;
    event_t* event_ptr2 = NULL;
    char actual[ASC_EVENT_MAX_SIZE] = { 0 };

    assert_non_null(collector_ptr);

    result = collector_mock_add_event_to_queue(&collector_ptr->internal , "ListeningPorts");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    // act
    {
        result = collector_collect(collector_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = collector_pop_event(collector_ptr, &event_ptr1);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = collector_pop_event(collector_ptr, &event_ptr2);
        assert_int_equal(IOTSECURITY_RESULT_EMPTY, result);
    }

    // assert
    {
        assert_non_null(event_ptr1);
        result = event_get_data(event_ptr1, actual, ASC_EVENT_MAX_SIZE);
        assert_non_null(actual);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
        assert_string_equal(EXPECTED, actual);

        assert_null(event_ptr2);
    }

    // cleanup
    {
        event_deinit(event_ptr1);
        event_ptr1 = NULL;
    }
}

static void collector_ut_collect_and_pop_single_event_collect_pop(void** state) {
    // arrange
    collector_t* collector_ptr = *state;
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    event_t* event_ptr1 = NULL;
    event_t* event_ptr2 = NULL;
    char actual[ASC_EVENT_MAX_SIZE] = { 0 };

    assert_non_null(collector_ptr);

    result = collector_mock_add_event_to_queue(&collector_ptr->internal , "ListeningPorts");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    // act
    {
        result = collector_collect(collector_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = collector_pop_event(collector_ptr, &event_ptr1);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = collector_collect(collector_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = collector_pop_event(collector_ptr, &event_ptr2);
        assert_int_equal(IOTSECURITY_RESULT_EMPTY, result);
    }

    // assert
    {
        assert_non_null(event_ptr1);
        result = event_get_data(event_ptr1, actual, ASC_EVENT_MAX_SIZE);
        assert_non_null(actual);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
        assert_string_equal(EXPECTED, actual);

        assert_null(event_ptr2);
    }

    // cleanup
    {
        event_deinit(event_ptr1);
        event_ptr1 = NULL;
    }
}

static void collector_ut_collect_and_peek_single_event_collect(void** state) {
    // arrange
    collector_t* collector_ptr = *state;
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    event_t* event_ptr1 = NULL;
    event_t* event_ptr2 = NULL;
    char actual1[ASC_EVENT_MAX_SIZE] = { 0 };
    char actual2[ASC_EVENT_MAX_SIZE] = { 0 };

    assert_non_null(collector_ptr);

    result = collector_mock_add_event_to_queue(&collector_ptr->internal , "ListeningPorts");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    result = collector_mock_add_event_to_queue(&collector_ptr->internal , "ListeningPorts");
    assert_int_equal(IOTSECURITY_RESULT_OK, result);

    // act
    {
        result = collector_collect(collector_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = collector_peek_event(collector_ptr, &event_ptr1);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
        assert_non_null(event_ptr1);

        result = collector_collect(collector_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);

        result = collector_pop_event(collector_ptr, &event_ptr2);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
    }

    // assert
    {
        assert_non_null(event_ptr1);
        result = event_get_data(event_ptr1, actual1, ASC_EVENT_MAX_SIZE);
        assert_non_null(actual1);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
        assert_string_equal(EXPECTED, actual1);

        assert_non_null(event_ptr2);
        result = event_get_data(event_ptr2, actual2, ASC_EVENT_MAX_SIZE);
        assert_non_null(actual2);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
        assert_string_equal(EXPECTED, actual2);
    }

    // cleanup
    {
        event_deinit(event_ptr1);
        event_ptr1 = NULL;
    }
}

static int collector_ut_setup(void** state) {
    collector_t* collector_ptr = collector_init(_collector_internal_init);

    *state = collector_ptr;
    return 0;
}

static int collector_ut_teardown(void** state) {
    collector_t* collector_ptr = *state;

    if (collector_ptr != NULL) {
        collector_deinit(collector_ptr);
        *state = NULL;
    }

    return 0;
}

int main (void) {
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(collector_ut_collect_event_from_single_collector, collector_ut_setup, collector_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_ut_peek_uninitialized, collector_ut_setup, collector_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_ut_pop_uninitialized, collector_ut_setup, collector_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_ut_collector_uninitialized, collector_ut_setup, collector_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_ut_peek_no_events_in_queue, collector_ut_setup, collector_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_ut_pop_no_events_in_queue, collector_ut_setup, collector_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_ut_collect_and_peek_no_event_in_queue, collector_ut_setup, collector_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_ut_collect_and_pop_no_event_in_queue, collector_ut_setup, collector_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_ut_collect_and_peek_single_event, collector_ut_setup, collector_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_ut_collect_and_pop_single_event, collector_ut_setup, collector_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_ut_collect_and_pop_single_event_and_empty, collector_ut_setup, collector_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_ut_collect_and_pop_single_event_collect_pop, collector_ut_setup, collector_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_ut_collect_and_peek_single_event_collect, collector_ut_setup, collector_ut_teardown),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}