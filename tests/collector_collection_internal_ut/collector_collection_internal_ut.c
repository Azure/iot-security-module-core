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
#include "asc_security_core/collector_collection_internal.h"

#include "../mocks/inc/collector_mock.h"
#include "../mocks/inc/collector_collection_factory.h"
#include "../mocks/inc/utils/itime.h"
#include "../mocks/inc/utils/irand.h"


static void collector_collection_internal_ut_init_startup_time_random(void** state) {
    linked_list_collector_t_handle priority_collection_list;
    linked_list_iterator_collector_t local_message_iterator = {0};
    linked_list_iterator_collector_t_handle iterator = &local_message_iterator;
    collector_t* collector_ptr;
    collector_collection_factory_init_test_data(0/*h1*/, 0/*h2*/, 0/*h3*/, 0/*m1*/, 0/*m2*/, 0/*l1*/);
    collector_collection_t* collector_collection_ptr = collector_collection_init();

    // init will generate the call to set startup time
    PRIORITY_COLLECTORS_HANDLE priority_collection = collector_collection_get_head_priority(collector_collection_ptr);
    assert_non_null(priority_collection);

    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(3, linked_list_collector_t_get_size(priority_collection_list));
    linked_list_iterator_collector_t_init(iterator, priority_collection_list);

    collector_ptr = linked_list_iterator_collector_t_next(iterator);
    assert_string_equal("h1", collector_get_name(collector_ptr));
    assert_int_equal(ASC_HIGH_PRIORITY_INTERVAL, (int)itime_difftime(TEST_TIME_T, collector_ptr->last_collected_timestamp));

    collector_ptr = linked_list_iterator_collector_t_next(iterator);
    assert_string_equal("h2", collector_get_name(collector_ptr));
    assert_int_equal(ASC_HIGH_PRIORITY_INTERVAL, (int)itime_difftime(TEST_TIME_T, collector_ptr->last_collected_timestamp));

    collector_ptr = linked_list_iterator_collector_t_next(iterator);
    assert_string_equal("h3", collector_get_name(collector_ptr));
    assert_int_equal(ASC_HIGH_PRIORITY_INTERVAL, (int)itime_difftime(TEST_TIME_T, collector_ptr->last_collected_timestamp));

    assert_null(linked_list_iterator_collector_t_next(iterator));

    priority_collection = collector_collection_get_next_priority(collector_collection_ptr, priority_collection);
    assert_non_null(priority_collection);

    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(2, linked_list_collector_t_get_size(priority_collection_list));
    linked_list_iterator_collector_t_init(iterator, priority_collection_list);

    collector_ptr = linked_list_iterator_collector_t_next(iterator);
    assert_string_equal("m1", collector_get_name(collector_ptr));
    assert_int_equal(ASC_MEDIUM_PRIORITY_INTERVAL, (int)itime_difftime(TEST_TIME_T, collector_ptr->last_collected_timestamp));

    collector_ptr = linked_list_iterator_collector_t_next(iterator);
    assert_string_equal("m2", collector_get_name(collector_ptr));
    assert_int_equal(ASC_MEDIUM_PRIORITY_INTERVAL, (int)itime_difftime(TEST_TIME_T, collector_ptr->last_collected_timestamp));

    assert_null(linked_list_iterator_collector_t_next(iterator));

    priority_collection = collector_collection_get_next_priority(collector_collection_ptr, priority_collection);
    assert_non_null(priority_collection);

    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(1, linked_list_collector_t_get_size(priority_collection_list));
    linked_list_iterator_collector_t_init(iterator, priority_collection_list);

    collector_ptr = linked_list_iterator_collector_t_next(iterator);
    assert_string_equal("l1", collector_get_name(collector_ptr));
    assert_int_equal(ASC_LOW_PRIORITY_INTERVAL, (int)itime_difftime(TEST_TIME_T, collector_ptr->last_collected_timestamp));

    assert_null(linked_list_iterator_collector_t_next(iterator));


    priority_collection = collector_collection_get_next_priority(collector_collection_ptr, priority_collection);
    assert_null(priority_collection);

    collector_collection_deinit(collector_collection_ptr);
}

static void collector_collection_internal_ut_init_startup_time_random_no_collectors(void** state) {
    collector_collection_factory_init_test_data(0/*h1*/, 0/*h2*/, 0/*h3*/, 0/*m1*/, 0/*m2*/, 0/*l1*/);
    mock_collector_collection_init_array = MOCK_COLLECTOR_COLLECTION_FACTORY_EMPTY;
    collector_collection_t* collector_collection_ptr = collector_collection_init();
    collector_collection_deinit(collector_collection_ptr);
}

static void collector_collection_internal_ut_init_startup_time_random_medium(void** state) {
    collector_collection_factory_init_test_data(0/*h1*/, 0/*h2*/, 0/*h3*/, 0/*m1*/, 0/*m2*/, 0/*l1*/);
    mock_collector_collection_init_array = MOCK_COLLECTOR_COLLECTION_FACTORY_MEDIUM;
    collector_collection_t* collector_collection_ptr = collector_collection_init();
    collector_collection_deinit(collector_collection_ptr);
}

static void collector_collection_internal_ut_init_startup_time_random_no_medium(void** state) {
    collector_collection_factory_init_test_data(0/*h1*/, 0/*h2*/, 0/*h3*/, 0/*m1*/, 0/*m2*/, 0/*l1*/);
    mock_collector_collection_init_array = MOCK_COLLECTOR_COLLECTION_FACTORY_NO_MEDIUM;
    collector_collection_t* collector_collection_ptr = collector_collection_init();
    collector_collection_deinit(collector_collection_ptr);
}

static void collector_collection_internal_ut_init_startup_time_random_bigger_than_interval(void** state) {
    linked_list_collector_t_handle priority_collection_list;
    linked_list_iterator_collector_t local_message_iterator = {0};
    linked_list_iterator_collector_t_handle iterator = &local_message_iterator;
    collector_t* collector_ptr;
    collector_collection_factory_init_test_data(0/*h1*/, 0/*h2*/, 0/*h3*/, 0/*m1*/, 0/*m2*/, 0/*l1*/);
    mock_rand_int_set_value(2 * ASC_MEDIUM_PRIORITY_INTERVAL);

    mock_collector_collection_init_array = MOCK_COLLECTOR_COLLECTION_FACTORY_MEDIUM;
    collector_collection_t* collector_collection_ptr = collector_collection_init();

    PRIORITY_COLLECTORS_HANDLE priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_MEDIUM);
    assert_non_null(priority_collection);
    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(2, linked_list_collector_t_get_size(priority_collection_list));
    linked_list_iterator_collector_t_init(iterator, priority_collection_list);

    collector_ptr = linked_list_iterator_collector_t_next(iterator);
    assert_string_equal("m1", collector_get_name(collector_ptr));
    assert_int_equal(ASC_MEDIUM_PRIORITY_INTERVAL, (int)itime_difftime(TEST_TIME_T, collector_ptr->last_collected_timestamp));

    collector_ptr = linked_list_iterator_collector_t_next(iterator);
    assert_string_equal("m2", collector_get_name(collector_ptr));
    assert_int_equal(ASC_MEDIUM_PRIORITY_INTERVAL, (int)itime_difftime(TEST_TIME_T, collector_ptr->last_collected_timestamp));

    assert_null(linked_list_iterator_collector_t_next(iterator));

    collector_collection_deinit(collector_collection_ptr);
}

static void collector_collection_internal_ut_init_startup_time_random_two_times_bigger_than_interval(void** state) {
    linked_list_collector_t_handle priority_collection_list;
    linked_list_iterator_collector_t local_message_iterator = {0};
    linked_list_iterator_collector_t_handle iterator = &local_message_iterator;
    collector_t* collector_ptr;

    collector_collection_factory_init_test_data(0/*h1*/, 0/*h2*/, 0/*h3*/, 0/*m1*/, 0/*m2*/, 0/*l1*/);
    mock_rand_int_set_value(ASC_MEDIUM_PRIORITY_INTERVAL);

    mock_collector_collection_init_array = MOCK_COLLECTOR_COLLECTION_FACTORY_MEDIUM;
    collector_collection_t* collector_collection_ptr = collector_collection_init();

    PRIORITY_COLLECTORS_HANDLE priority_collection = collector_collection_get_by_priority(collector_collection_ptr, COLLECTOR_PRIORITY_MEDIUM);
    assert_non_null(priority_collection);
    priority_collection_list = priority_collectors_get_list(priority_collection);
    assert_non_null(priority_collection_list);
    assert_int_equal(2, linked_list_collector_t_get_size(priority_collection_list));
    linked_list_iterator_collector_t_init(iterator, priority_collection_list);

    collector_ptr = linked_list_iterator_collector_t_next(iterator);
    assert_string_equal("m1", collector_get_name(collector_ptr));
    assert_int_equal(2 * ASC_MEDIUM_PRIORITY_INTERVAL, (int)itime_difftime(TEST_TIME_T, collector_ptr->last_collected_timestamp));

    collector_ptr = linked_list_iterator_collector_t_next(iterator);
    assert_string_equal("m2", collector_get_name(collector_ptr));
    assert_int_equal(2 * ASC_MEDIUM_PRIORITY_INTERVAL, (int)itime_difftime(TEST_TIME_T, collector_ptr->last_collected_timestamp));

    assert_null(linked_list_iterator_collector_t_next(iterator));

    collector_collection_deinit(collector_collection_ptr);
}


static int collector_collection_internal_ut_setup(void** state) {
    mock_collector_collection_init_array = MOCK_COLLECTOR_COLLECTION_FACTORY_ALL;
    mock_rand_int_set_value(0);

    return 0;
}

static int collector_collection_internal_ut_teardown(void** state) {
    return 0;
}

int main (void) {
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(collector_collection_internal_ut_init_startup_time_random, collector_collection_internal_ut_setup, collector_collection_internal_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_collection_internal_ut_init_startup_time_random_no_collectors, collector_collection_internal_ut_setup, collector_collection_internal_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_collection_internal_ut_init_startup_time_random_medium, collector_collection_internal_ut_setup, collector_collection_internal_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_collection_internal_ut_init_startup_time_random_no_medium, collector_collection_internal_ut_setup, collector_collection_internal_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_collection_internal_ut_init_startup_time_random_bigger_than_interval, collector_collection_internal_ut_setup, collector_collection_internal_ut_teardown),
    cmocka_unit_test_setup_teardown(collector_collection_internal_ut_init_startup_time_random_two_times_bigger_than_interval, collector_collection_internal_ut_setup, collector_collection_internal_ut_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}