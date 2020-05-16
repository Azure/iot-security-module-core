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

#include "asc_security_core/collector_collection.h"

#include "../mocks/inc/collector_mock.h"
#include "../mocks/inc/collector_collection_factory.h"

const char* Mock_os_utils_get_security_module_id();

const char* Mock_os_utils_get_security_module_id() {
    return "machine-id";
}

static void collector_collection_ut_collect_events(collector_t* collector_ptr, void *context) {
    collector_collect(collector_ptr);
}

static void collector_collection_ut_create_and_destroy(void** state) {
    collector_collection_t* collector_collection_ptr = collector_collection_init();

    collector_collection_deinit(collector_collection_ptr);
}

static void collector_collection_ut_get_all_collections(void** state) {
    COLLECTOR_PRIORITY priority;
    uint32_t interval;
    linked_list_collector_t_handle priority_collection_list;
    linked_list_iterator_collector_t local_message_iterator = {0};
    linked_list_iterator_collector_t_handle iterator = &local_message_iterator;
    collector_collection_factory_init_test_data(2/*h1*/, 2/*h2*/, 2/*h3*/, 1/*m1*/, 2/*m2*/, 10/*l1*/);
    collector_collection_t* collector_collection_ptr = collector_collection_init();

    // events have to be collected so we could fetch empty & non-empty collectors (otherwise all collectors are empty)
    collector_collection_foreach(collector_collection_ptr, collector_collection_ut_collect_events, NULL);

    PRIORITY_COLLECTORS_HANDLE priority_collection = collector_collection_get_head_priority(collector_collection_ptr);
    assert_non_null(priority_collection);
    interval = priority_collectors_get_interval(priority_collection);
    assert_int_equal(ASC_HIGH_PRIORITY_INTERVAL, interval);

    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(3, linked_list_collector_t_get_size(priority_collection_list));

    linked_list_iterator_collector_t_init(iterator, priority_collection_list);
    assert_string_equal("h1", collector_get_name(linked_list_iterator_collector_t_next(iterator)));
    assert_string_equal("h2", collector_get_name(linked_list_iterator_collector_t_next(iterator)));
    assert_string_equal("h3", collector_get_name(linked_list_iterator_collector_t_next(iterator)));
    assert_null(linked_list_iterator_collector_t_next(iterator));

    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_HIGH, priority);

    priority_collection = collector_collection_get_next_priority(collector_collection_ptr, priority_collection);
    assert_non_null(priority_collection);

    interval = priority_collectors_get_interval(priority_collection);
    assert_int_equal(ASC_MEDIUM_PRIORITY_INTERVAL, interval);

    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(2, linked_list_collector_t_get_size(priority_collection_list));

    linked_list_iterator_collector_t_init(iterator, priority_collection_list);
    assert_string_equal("m1", collector_get_name(linked_list_iterator_collector_t_next(iterator)));
    assert_string_equal("m2", collector_get_name(linked_list_iterator_collector_t_next(iterator)));
    assert_null(linked_list_iterator_collector_t_next(iterator));

    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_MEDIUM, priority);

    priority_collection = collector_collection_get_next_priority(collector_collection_ptr, priority_collection);
    assert_non_null(priority_collection);

    interval = priority_collectors_get_interval(priority_collection);
    assert_int_equal(ASC_LOW_PRIORITY_INTERVAL, interval);

    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(1, linked_list_collector_t_get_size(priority_collection_list));

    linked_list_iterator_collector_t_init(iterator, priority_collection_list);
    assert_string_equal("l1", collector_get_name(linked_list_iterator_collector_t_next(iterator)));
    assert_null(linked_list_iterator_collector_t_next(iterator));

    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_LOW, priority);

    priority_collection = collector_collection_get_next_priority(collector_collection_ptr, priority_collection);
    assert_null(priority_collection);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_HIGH);
    assert_non_null(priority_collection);
    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_HIGH, priority);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_MEDIUM);
    assert_non_null(priority_collection);
    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_MEDIUM, priority);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_LOW);
    assert_non_null(priority_collection);
    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_LOW, priority);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_COUNT);
    assert_null(priority_collection);

    collector_collection_deinit(collector_collection_ptr);
}

static void collector_collection_ut_get_all_collections_no_medium(void** state) {
    COLLECTOR_PRIORITY priority;
    uint32_t interval;
    linked_list_collector_t_handle priority_collection_list;
    linked_list_iterator_collector_t local_message_iterator = {0};
    linked_list_iterator_collector_t_handle iterator = &local_message_iterator;
    mock_collector_collection_init_array = MOCK_COLLECTOR_COLLECTION_FACTORY_NO_MEDIUM;
    collector_collection_factory_init_test_data(2/*h1*/, 2/*h2*/, 2/*h3*/, 0/*m1*/, 0/*m2*/, 10/*l1*/);
    collector_collection_t* collector_collection_ptr = collector_collection_init();

    PRIORITY_COLLECTORS_HANDLE priority_collection = collector_collection_get_head_priority(collector_collection_ptr);
    assert_non_null(priority_collection);

    interval = priority_collectors_get_interval(priority_collection);
    assert_int_equal(ASC_HIGH_PRIORITY_INTERVAL, interval);

    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(3, linked_list_collector_t_get_size(priority_collection_list));

    linked_list_iterator_collector_t_init(iterator, priority_collection_list);
    assert_string_equal("h1", collector_get_name(linked_list_iterator_collector_t_next(iterator)));
    assert_string_equal("h2", collector_get_name(linked_list_iterator_collector_t_next(iterator)));
    assert_string_equal("h3", collector_get_name(linked_list_iterator_collector_t_next(iterator)));
    assert_null(linked_list_iterator_collector_t_next(iterator));

    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_HIGH, priority);

    priority_collection = collector_collection_get_next_priority(collector_collection_ptr, priority_collection);
    assert_non_null(priority_collection);

    interval = priority_collectors_get_interval(priority_collection);
    assert_int_equal(ASC_MEDIUM_PRIORITY_INTERVAL, interval);

    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(0, linked_list_collector_t_get_size(priority_collection_list));

    assert_null(linked_list_collector_t_get_first(priority_collection_list));

    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_MEDIUM, priority);

    priority_collection = collector_collection_get_next_priority(collector_collection_ptr, priority_collection);
    assert_non_null(priority_collection);

    interval = priority_collectors_get_interval(priority_collection);
    assert_int_equal(ASC_LOW_PRIORITY_INTERVAL, interval);

    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(1, linked_list_collector_t_get_size(priority_collection_list));

    linked_list_iterator_collector_t_init(iterator, priority_collection_list);
    assert_string_equal("l1", collector_get_name(linked_list_iterator_collector_t_next(iterator)));
    assert_null(linked_list_iterator_collector_t_next(iterator));

    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_LOW, priority);

    priority_collection = collector_collection_get_next_priority(collector_collection_ptr, priority_collection);
    assert_null(priority_collection);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_HIGH);
    assert_non_null(priority_collection);
    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_HIGH, priority);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_MEDIUM);
    assert_non_null(priority_collection);
    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_MEDIUM, priority);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_LOW);
    assert_non_null(priority_collection);
    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_LOW, priority);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_COUNT);
    assert_null(priority_collection);

    collector_collection_deinit(collector_collection_ptr);
}

static void collector_collection_ut_get_all_collections_medium(void** state) {
    COLLECTOR_PRIORITY priority;
    uint32_t interval;
    linked_list_collector_t_handle priority_collection_list;
    linked_list_iterator_collector_t local_message_iterator = {0};
    linked_list_iterator_collector_t_handle iterator = &local_message_iterator;
    mock_collector_collection_init_array = MOCK_COLLECTOR_COLLECTION_FACTORY_MEDIUM;
    collector_collection_factory_init_test_data(2/*h1*/, 2/*h2*/, 2/*h3*/, 0/*m1*/, 0/*m2*/, 10/*l1*/);
    collector_collection_t* collector_collection_ptr = collector_collection_init();

    PRIORITY_COLLECTORS_HANDLE priority_collection = collector_collection_get_head_priority(collector_collection_ptr);
    assert_non_null(priority_collection);

    interval = priority_collectors_get_interval(priority_collection);
    assert_int_equal(ASC_HIGH_PRIORITY_INTERVAL, interval);

    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(0, linked_list_collector_t_get_size(priority_collection_list));
    assert_null(linked_list_collector_t_get_first(priority_collection_list));

    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_HIGH, priority);

    priority_collection = collector_collection_get_next_priority(collector_collection_ptr, priority_collection);
    assert_non_null(priority_collection);

    interval = priority_collectors_get_interval(priority_collection);
    assert_int_equal(ASC_MEDIUM_PRIORITY_INTERVAL, interval);

    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(2, linked_list_collector_t_get_size(priority_collection_list));

    linked_list_iterator_collector_t_init(iterator, priority_collection_list);
    assert_string_equal("m1", collector_get_name(linked_list_iterator_collector_t_next(iterator)));
    assert_string_equal("m2", collector_get_name(linked_list_iterator_collector_t_next(iterator)));
    assert_null(linked_list_iterator_collector_t_next(iterator));

    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_MEDIUM, priority);

    priority_collection = collector_collection_get_next_priority(collector_collection_ptr, priority_collection);
    assert_non_null(priority_collection);

    interval = priority_collectors_get_interval(priority_collection);
    assert_int_equal(ASC_LOW_PRIORITY_INTERVAL, interval);

    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(0, linked_list_collector_t_get_size(priority_collection_list));

    assert_null(linked_list_collector_t_get_first(priority_collection_list));

    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_LOW, priority);

    priority_collection = collector_collection_get_next_priority(collector_collection_ptr, priority_collection);
    assert_null(priority_collection);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_HIGH);
    assert_non_null(priority_collection);
    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_HIGH, priority);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_MEDIUM);
    assert_non_null(priority_collection);
    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_MEDIUM, priority);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_LOW);
    assert_non_null(priority_collection);
    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_LOW, priority);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_COUNT);
    assert_null(priority_collection);

    collector_collection_deinit(collector_collection_ptr);
}

static void collector_collection_ut_get_all_collections_empty(void** state) {
    COLLECTOR_PRIORITY priority;
    uint32_t interval;
    linked_list_collector_t_handle priority_collection_list;

    mock_collector_collection_init_array = MOCK_COLLECTOR_COLLECTION_FACTORY_EMPTY;
    collector_collection_factory_init_test_data(2/*h1*/, 2/*h2*/, 2/*h3*/, 0/*m1*/, 0/*m2*/, 10/*l1*/);
    collector_collection_t* collector_collection_ptr = collector_collection_init();
    PRIORITY_COLLECTORS_HANDLE priority_collection = collector_collection_get_head_priority(collector_collection_ptr);

    assert_non_null(priority_collection);

    interval = priority_collectors_get_interval(priority_collection);
    assert_int_equal(ASC_HIGH_PRIORITY_INTERVAL, interval);

    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(0, linked_list_collector_t_get_size(priority_collection_list));
    assert_null(linked_list_collector_t_get_first(priority_collection_list));

    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_HIGH, priority);

    priority_collection = collector_collection_get_next_priority(collector_collection_ptr, priority_collection);
    assert_non_null(priority_collection);

    interval = priority_collectors_get_interval(priority_collection);
    assert_int_equal(ASC_MEDIUM_PRIORITY_INTERVAL, interval);

    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(0, linked_list_collector_t_get_size(priority_collection_list));

    assert_null(linked_list_collector_t_get_first(priority_collection_list));

    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_MEDIUM, priority);

    priority_collection = collector_collection_get_next_priority(collector_collection_ptr, priority_collection);
    assert_non_null(priority_collection);

    interval = priority_collectors_get_interval(priority_collection);
    assert_int_equal(ASC_LOW_PRIORITY_INTERVAL, interval);

    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(0, linked_list_collector_t_get_size(priority_collection_list));
    assert_null(linked_list_collector_t_get_first(priority_collection_list));

    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_LOW, priority);

    priority_collection = collector_collection_get_next_priority(collector_collection_ptr, priority_collection);
    assert_null(priority_collection);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_HIGH);
    assert_non_null(priority_collection);
    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_HIGH, priority);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_MEDIUM);
    assert_non_null(priority_collection);
    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_MEDIUM, priority);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_LOW);
    assert_non_null(priority_collection);
    priority = priority_collectors_get_priority(priority_collection);
    assert_int_equal(COLLECTOR_PRIORITY_LOW, priority);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_COUNT);
    assert_null(priority_collection);

    collector_collection_deinit(collector_collection_ptr);
}

static void collector_collection_ut_collector_iterator(void** state) {
    mock_collector_collection_init_array = MOCK_COLLECTOR_COLLECTION_FACTORY_MEDIUM;
    collector_t* collector_ptr;
    PRIORITY_COLLECTORS_HANDLE priority_collection;
    collector_collection_factory_init_test_data(2/*h1*/, 2/*h2*/, 2/*h3*/, 3/*m1*/, 3/*m2*/, 10/*l1*/);
    collector_collection_t* collector_collection_ptr = collector_collection_init();

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_MEDIUM);
    assert_non_null(priority_collection);

    collector_ptr = priority_collectors_get_current_collector(priority_collection);
    assert_string_equal("m1", collector_get_name(collector_ptr));

    collector_ptr = priority_collectors_get_next_cyclic_collector(priority_collection);
    assert_string_equal("m2", collector_get_name(collector_ptr));

    priority_collectors_set_current_collector(priority_collection, collector_ptr);
    collector_ptr = priority_collectors_get_current_collector(priority_collection);
    assert_string_equal("m2", collector_get_name(collector_ptr));
    collector_ptr = priority_collectors_get_next_cyclic_collector(priority_collection);
    assert_string_equal("m1", collector_get_name(collector_ptr));

    collector_collection_deinit(collector_collection_ptr);
}

static void collector_collection_ut_collector_iterator_empty_priority(void** state) {
    mock_collector_collection_init_array = MOCK_COLLECTOR_COLLECTION_FACTORY_NO_MEDIUM;
    collector_t* collector_ptr;
    PRIORITY_COLLECTORS_HANDLE priority_collection;
    collector_collection_factory_init_test_data(2/*h1*/, 2/*h2*/, 2/*h3*/, 3/*m1*/, 3/*m2*/, 10/*l1*/);
    collector_collection_t* collector_collection_ptr = collector_collection_init();

    // validate NULL return valus in case of an empty list
    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_MEDIUM);
    assert_non_null(priority_collection);

    priority_collectors_get_current_non_empty_collector(priority_collection, &collector_ptr);
    assert_null(collector_ptr);

    priority_collectors_get_next_non_empty_collector(priority_collection, &collector_ptr);
    assert_null(collector_ptr);

    collector_collection_deinit(collector_collection_ptr);
}

static void collector_collection_ut_collector_iterator_increment_when_empty(void** state) {
    event_t* popped_event_ptr = NULL;
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    mock_collector_collection_init_array = MOCK_COLLECTOR_COLLECTION_FACTORY_NO_MEDIUM;
    collector_t* collector_ptr;
    PRIORITY_COLLECTORS_HANDLE priority_collection;
    collector_collection_factory_init_test_data(2/*h1*/, 1/*h2*/, 0/*h3*/, 3/*m1*/, 3/*m2*/, 10/*l1*/);
    collector_collection_t* collector_collection_ptr = collector_collection_init();

    collector_collection_foreach(collector_collection_ptr, collector_collection_ut_collect_events, NULL);

    priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_HIGH);
    assert_non_null(priority_collection);

    priority_collectors_get_current_non_empty_collector(priority_collection, &collector_ptr);
    assert_non_null(collector_ptr);
    assert_string_equal("h1", collector_get_name(collector_ptr));
    result = collector_pop_event(collector_ptr, &popped_event_ptr);
    event_deinit(popped_event_ptr);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);
    priority_collectors_get_current_non_empty_collector(priority_collection, &collector_ptr);
    assert_non_null(collector_ptr);
    assert_string_equal("h1", collector_get_name(collector_ptr));
    result = collector_pop_event(collector_ptr, &popped_event_ptr);
    event_deinit(popped_event_ptr);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);
    priority_collectors_get_current_non_empty_collector(priority_collection, &collector_ptr);
    assert_non_null(collector_ptr);
    assert_string_equal("h2", collector_get_name(collector_ptr));
    result = collector_pop_event(collector_ptr, &popped_event_ptr);
    event_deinit(popped_event_ptr);
    assert_int_equal(IOTSECURITY_RESULT_OK, result);
    priority_collectors_get_current_non_empty_collector(priority_collection, &collector_ptr);
    assert_null(collector_ptr);

    collector_collection_deinit(collector_collection_ptr);
}

static void collector_collection_ut_collector_iterator_cyclic(void** state) {
    // arrange
    event_t* popped_event_ptr = NULL;
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    mock_collector_collection_init_array = MOCK_COLLECTOR_COLLECTION_FACTORY_NO_MEDIUM;
    collector_t* collector_ptr;
    PRIORITY_COLLECTORS_HANDLE priority_collection;

    collector_collection_factory_init_test_data(2/*h1*/, 1/*h2*/, 2/*h3*/, 3/*m1*/, 3/*m2*/, 10/*l1*/);

    collector_collection_t* collector_collection_ptr = collector_collection_init();
    collector_collection_foreach(collector_collection_ptr, collector_collection_ut_collect_events, NULL);

    // act
    {
        priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_HIGH);
        assert_non_null(priority_collection);

        priority_collectors_get_current_non_empty_collector(priority_collection, &collector_ptr);
        assert_non_null(collector_ptr);
        assert_string_equal("h1", collector_get_name(collector_ptr));

        priority_collectors_get_next_non_empty_collector(priority_collection, &collector_ptr);
        assert_non_null(collector_ptr);
        assert_string_equal("h2", collector_get_name(collector_ptr));

        result = collector_pop_event(collector_ptr, &popped_event_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
        event_deinit(popped_event_ptr);
        popped_event_ptr = NULL;

        priority_collectors_get_next_non_empty_collector(priority_collection, &collector_ptr);
        assert_non_null(collector_ptr);
        assert_string_equal("h3", collector_get_name(collector_ptr));

        priority_collectors_get_next_non_empty_collector(priority_collection, &collector_ptr);
        assert_non_null(collector_ptr);
        assert_string_equal("h1", collector_get_name(collector_ptr));

        priority_collectors_get_next_non_empty_collector(priority_collection, &collector_ptr);
        assert_non_null(collector_ptr);
        assert_string_equal("h3", collector_get_name(collector_ptr));

        // validate NULL on empty collectors
        result = collector_pop_event(collector_ptr, &popped_event_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
        event_deinit(popped_event_ptr);
        popped_event_ptr = NULL;

        result = collector_pop_event(collector_ptr, &popped_event_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
        event_deinit(popped_event_ptr);
        popped_event_ptr = NULL;

        priority_collectors_get_next_non_empty_collector(priority_collection, &collector_ptr);
        assert_non_null(collector_ptr);
        assert_string_equal("h1", collector_get_name(collector_ptr));

        result = collector_pop_event(collector_ptr, &popped_event_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
        event_deinit(popped_event_ptr);
        popped_event_ptr = NULL;

        result = collector_pop_event(collector_ptr, &popped_event_ptr);
        assert_int_equal(IOTSECURITY_RESULT_OK, result);
        event_deinit(popped_event_ptr);
        popped_event_ptr = NULL;
    }

    // assert
    {
        priority_collectors_get_next_non_empty_collector(priority_collection, &collector_ptr);
        assert_null(collector_ptr);
    }

    // cleanup
    {
        collector_collection_deinit(collector_collection_ptr);
    }
}

static int collector_collection_ut_setup(void** state) {
    collector_collection_factory_init();
    return 0;
}

static int collector_collection_ut_teardown(void** state) {
    return 0;
}

int main (void) {
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(collector_collection_ut_create_and_destroy, collector_collection_ut_setup, collector_collection_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_collection_ut_get_all_collections, collector_collection_ut_setup, collector_collection_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_collection_ut_get_all_collections_no_medium, collector_collection_ut_setup, collector_collection_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_collection_ut_get_all_collections_medium, collector_collection_ut_setup, collector_collection_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_collection_ut_get_all_collections_empty, collector_collection_ut_setup, collector_collection_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_collection_ut_collector_iterator, collector_collection_ut_setup, collector_collection_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_collection_ut_collector_iterator_empty_priority, collector_collection_ut_setup, collector_collection_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_collection_ut_collector_iterator_increment_when_empty, collector_collection_ut_setup, collector_collection_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_collection_ut_collector_iterator_cyclic, collector_collection_ut_setup, collector_collection_ut_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
