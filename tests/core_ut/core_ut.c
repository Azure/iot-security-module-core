
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

#include "asc_security_core/core.h"

#include "../mocks/inc/collector_mock.h"
#include "../mocks/inc/collector_collection_factory.h"
#include "../mocks/inc/utils/itime.h"

typedef struct message {
    COLLECTION_INTERFACE(struct message);

    char data[100];
    uint32_t num_append;
} message_t;

OBJECT_POOL_DECLARATIONS(message_t, MESSAGE_OBJECT_POOL_COUNT);
OBJECT_POOL_DEFINITIONS(message_t, MESSAGE_OBJECT_POOL_COUNT);

const char* __wrap_os_utils_get_security_module_id();
message_t* __wrap_message_init();
void __wrap_message_deinit(message_t* handle);
IOTSECURITY_RESULT __wrap_message_to_json(message_t* message_ptr, char* buffer, size_t size);
IOTSECURITY_RESULT __wrap_message_append(message_t* message_ptr, event_t* event_ptr);
bool __wrap_message_has_events(message_t* message_ptr);
bool __wrap_message_can_append(message_t* message_ptr, event_t* event_ptr);

const char* __wrap_os_utils_get_security_module_id() {
    return "machine-id";
}

#define MAX_EVENT_NAME 10
typedef struct event_name_tag {
    COLLECTION_INTERFACE(struct event_name_tag);
    char data[MAX_EVENT_NAME];
} event_name;
typedef event_name* event_name_handle;
LINKED_LIST_DECLARATIONS(event_name);
LINKED_LIST_DEFINITIONS(event_name);

static linked_list_event_name max_message_counter_event_list;
static linked_list_event_name_handle max_message_counter_event_list_handle;
static bool max_find_message(event_name_handle item, void* match_context) {
    return (strcmp((char*)match_context, item->data) == 0);
}

message_t* __wrap_message_init() {
    message_t* handle = object_pool_get(message_t);
    memset(handle, 0, sizeof(message_t));
    handle->num_append = 0;
    return handle;
}

void __wrap_message_deinit(message_t* handle) {
    if (handle != NULL) {
        object_pool_free(message_t, handle);
    }
}

IOTSECURITY_RESULT __wrap_message_to_json(message_t* message_ptr, char* buffer, size_t size) {
    snprintf(buffer, sizeof(message_ptr->data)+2, "<%s>", message_ptr->data);
    return IOTSECURITY_RESULT_OK;
}

IOTSECURITY_RESULT __wrap_message_append(message_t* message_ptr, event_t* event_ptr) {
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    message_ptr->num_append++;

    if (message_ptr->num_append > 1) {
        strcat(message_ptr->data, "-");
    }
    char event_data[ASC_EVENT_MAX_SIZE];
    (void)memset(event_data, 0, ASC_EVENT_MAX_SIZE);
    result = event_get_data(event_ptr, event_data, ASC_EVENT_MAX_SIZE);
    if (result != IOTSECURITY_RESULT_OK) {
        return result;
    }

    strcat(message_ptr->data, event_data);

    return IOTSECURITY_RESULT_OK;
}

bool __wrap_message_has_events(message_t* message_ptr) {
    return message_ptr->num_append > 0;
}

static void core_ut_destroy_max_message_list() {
    linked_list_event_name_deinit(max_message_counter_event_list_handle);
}

bool __wrap_message_can_append(message_t* message_ptr, event_t* event_ptr) {
    IOTSECURITY_RESULT result = IOTSECURITY_RESULT_OK;
    char event_data[ASC_EVENT_MAX_SIZE];
    (void)memset(event_data, 0, ASC_EVENT_MAX_SIZE);
    result = event_get_data(event_ptr, event_data, ASC_EVENT_MAX_SIZE);
    if (result != IOTSECURITY_RESULT_OK) {
        return false;
    }

    event_name_handle max_message = linked_list_event_name_find(max_message_counter_event_list_handle, max_find_message, event_data);
    if (max_message != NULL) {
        linked_list_event_name_remove(max_message_counter_event_list_handle, max_message);
        return false;
    }
    return true;
}

static bool is_collected(collector_t* collector_ptr, uint32_t position) {
    if (collector_ptr == NULL)
        return false;

    return collector_ptr->last_collected_timestamp > mock_collector_collection_factory_test_data[position].initial_time && collector_ptr->last_collected_timestamp == test_time;
}

static bool validate_collected(collector_collection_t* collector_collection_ptr, bool h1, bool h2, bool h3, bool m1, bool m2, bool l1) {
    bool result = true;
    result &= is_collected(collector_collection_get_collector_by_priority(collector_collection_ptr, "h1"), COLLECTOR_H1) == h1;
    result &= is_collected(collector_collection_get_collector_by_priority(collector_collection_ptr, "h2"), COLLECTOR_H2) == h2;
    result &= is_collected(collector_collection_get_collector_by_priority(collector_collection_ptr, "h3"), COLLECTOR_H3) == h3;
    result &= is_collected(collector_collection_get_collector_by_priority(collector_collection_ptr, "m1"), COLLECTOR_M1) == m1;
    result &= is_collected(collector_collection_get_collector_by_priority(collector_collection_ptr, "m2"), COLLECTOR_M2) == m2;
    result &= is_collected(collector_collection_get_collector_by_priority(collector_collection_ptr, "l1"), COLLECTOR_L1) == l1;
    return result;
}

static void core_ut_create_and_destroy(void** state) {
    core_t* core_ptr = core_init();

    core_deinit(core_ptr);
}

static void core_ut_create_message_with_round_robin(void** state) {
    IOTSECURITY_RESULT expected_result = IOTSECURITY_RESULT_OK;
    collector_collection_factory_init_test_data(2/*h1*/, 2/*h2*/, 2/*h3*/, 1/*m1*/, 2/*m2*/, 10/*l1*/);
    linked_list_security_message_t _local_message_list;
    linked_list_security_message_t* message_list = &_local_message_list;
    linked_list_security_message_t_init(message_list, object_pool_security_message_t_free);

    core_t* core_ptr = core_init();
    assert_non_null(core_ptr);

    IOTSECURITY_RESULT result = core_collect(core_ptr);
    assert_int_equal((uint32_t)result, (uint32_t)IOTSECURITY_RESULT_OK);

    result = core_get(core_ptr, message_list);

    // check for size and equality
    char* message = linked_list_security_message_t_get_first(message_list)->data;
    assert_string_equal("<h10-h20-h30-h11-h21-h31-m10-m20-m21-l10-l11-l12-l13-l14-l15-l16-l17-l18-l19>", message);

    assert_int_equal(1, linked_list_security_message_t_get_size(message_list));

    assert_int_equal((uint32_t)result, (uint32_t)expected_result);
    core_deinit(core_ptr);

    linked_list_security_message_t_deinit(message_list);
}

static void core_ut_split_message_into_three(void** state) {
    IOTSECURITY_RESULT expected_result = IOTSECURITY_RESULT_OK;

    collector_collection_factory_init_test_data(1/*h1*/, 3/*h2*/, 3/*h3*/, 1/*m1*/, 5/*m2*/, 1/*l1*/);
    event_name max_reached_at_event_first =  { .data = "h20" };
    event_name max_reached_at_event_second =  { .data = "m10" };
    event_name max_reached_at_event_third =  { .data = "m23" };
    linked_list_event_name_add_last(max_message_counter_event_list_handle, &max_reached_at_event_first);
    linked_list_event_name_add_last(max_message_counter_event_list_handle, &max_reached_at_event_second);
    linked_list_event_name_add_last(max_message_counter_event_list_handle, &max_reached_at_event_third);

    linked_list_security_message_t _local_message_list;
    linked_list_security_message_t* message_list = &_local_message_list;
    linked_list_security_message_t_init(message_list, object_pool_security_message_t_free);
    linked_list_iterator_security_message_t local_message_iterator = {0};
    linked_list_iterator_security_message_t* iterator = &local_message_iterator;
    core_t* core_ptr = core_init();
    assert_non_null(core_ptr);

    IOTSECURITY_RESULT result = core_collect(core_ptr);
    assert_int_equal((uint32_t)result, (uint32_t)IOTSECURITY_RESULT_OK);

    result = core_get(core_ptr, message_list);

    linked_list_iterator_security_message_t_init(iterator, message_list);
    assert_string_equal("<h10>", linked_list_iterator_security_message_t_next(iterator)->data);

    assert_string_equal("<h20-h30-h21-h31-h22-h32>", linked_list_iterator_security_message_t_next(iterator)->data);

    assert_string_equal("<m10-m20-m21-m22>", linked_list_iterator_security_message_t_next(iterator)->data);

    assert_null(linked_list_iterator_security_message_t_next(iterator));

    linked_list_security_message_t_deinit(message_list);

    result = core_get(core_ptr, message_list);
    linked_list_iterator_security_message_t_init(iterator, message_list);
    assert_string_equal("<m23-m24-l10>", linked_list_iterator_security_message_t_next(iterator)->data);

    assert_null(linked_list_iterator_security_message_t_next(iterator));
    linked_list_security_message_t_deinit(message_list);

    assert_int_equal((uint32_t)result, (uint32_t)expected_result);
    core_deinit(core_ptr);
}

static void core_ut_continue_from_next_collector(void** state) {
    IOTSECURITY_RESULT expected_result = IOTSECURITY_RESULT_OK;

    collector_collection_factory_init_test_data(3/*h1*/, 3/*h2*/, 3/*h3*/, 1/*m1*/, 5/*m2*/, 1/*l1*/);
    event_name max_reached_at_event_first = { .data = "h20" };
    event_name max_reached_at_event_second = { .data = "h30" };
    event_name max_reached_at_event_third = { .data = "h21" };
    linked_list_event_name_add_last(max_message_counter_event_list_handle, &max_reached_at_event_first);
    linked_list_event_name_add_last(max_message_counter_event_list_handle, &max_reached_at_event_second);
    linked_list_event_name_add_last(max_message_counter_event_list_handle, &max_reached_at_event_third);

    linked_list_security_message_t _local_message_list;
    linked_list_security_message_t* message_list = &_local_message_list;
    linked_list_security_message_t_init(message_list, object_pool_security_message_t_free);
    linked_list_iterator_security_message_t local_message_iterator = {0};
    linked_list_iterator_security_message_t* iterator = &local_message_iterator;
    core_t* core_ptr = core_init();
    assert_non_null(core_ptr);

    IOTSECURITY_RESULT result = core_collect(core_ptr);
    assert_int_equal((uint32_t)result, (uint32_t)IOTSECURITY_RESULT_OK);

    result = core_get(core_ptr, message_list);

    linked_list_iterator_security_message_t_init(iterator, message_list);
    assert_string_equal("<h10>", linked_list_iterator_security_message_t_next(iterator)->data);

    assert_string_equal("<h20>", linked_list_iterator_security_message_t_next(iterator)->data);

    assert_string_equal("<h30-h11>", linked_list_iterator_security_message_t_next(iterator)->data);

    assert_null(linked_list_iterator_security_message_t_next(iterator));

    linked_list_security_message_t_deinit(message_list);

    result = core_get(core_ptr, message_list);

    linked_list_iterator_security_message_t_init(iterator, message_list);
    assert_string_equal("<h21-h31-h12-h22-h32-m10-m20-m21-m22-m23-m24-l10>", linked_list_iterator_security_message_t_next(iterator)->data);

    assert_null(linked_list_iterator_security_message_t_next(iterator));
    linked_list_security_message_t_deinit(message_list);

    assert_int_equal((uint32_t)result, (uint32_t)expected_result);
    core_deinit(core_ptr);
}

static void core_ut_ignore_huge_event_and_continue(void** state) {
    IOTSECURITY_RESULT expected_result = IOTSECURITY_RESULT_OK;

    collector_collection_factory_init_test_data(3/*h1*/, 3/*h2*/, 3/*h3*/, 1/*m1*/, 5/*m2*/, 1/*l1*/);

    event_name max_reached_at_event_first = { .data = "h10" };
    linked_list_event_name_add_last(max_message_counter_event_list_handle, &max_reached_at_event_first);

    linked_list_security_message_t _local_message_list;
    linked_list_security_message_t* message_list = &_local_message_list;
    linked_list_security_message_t_init(message_list, object_pool_security_message_t_free);
    core_t* core_ptr = core_init();
    assert_non_null(core_ptr);

    IOTSECURITY_RESULT result = core_collect(core_ptr);
    assert_int_equal((uint32_t)result, (uint32_t)IOTSECURITY_RESULT_OK);

    result = core_get(core_ptr, message_list);

    assert_string_equal("<h11-h20-h30-h12-h21-h31-h22-h32-m10-m20-m21-m22-m23-m24-l10>", linked_list_security_message_t_get_first(message_list)->data);

    assert_int_equal(1, linked_list_security_message_t_get_size(message_list));
    linked_list_security_message_t_deinit(message_list);

    assert_int_equal((uint32_t)result, (uint32_t)expected_result);
    core_deinit(core_ptr);
}

static void core_ut_empty_message_on_no_events(void** state) {
    IOTSECURITY_RESULT expected_result = IOTSECURITY_RESULT_EMPTY;

    linked_list_security_message_t* message_list = NULL;
    core_t* core_ptr = core_init();
    assert_non_null(core_ptr);

    IOTSECURITY_RESULT result = core_collect(core_ptr);
    assert_int_equal((uint32_t)result, (uint32_t)IOTSECURITY_RESULT_OK);

    result = core_get(core_ptr, message_list);

    assert_null(message_list);

    assert_int_equal((uint32_t)result, (uint32_t)expected_result);
    core_deinit(core_ptr);
}

static void core_ut_event_collections(void** state) {
    IOTSECURITY_RESULT expected_result = IOTSECURITY_RESULT_OK;

    core_t* core_ptr = core_init();
    assert_non_null(core_ptr);

    IOTSECURITY_RESULT result = core_collect(core_ptr);
    assert_int_equal((uint32_t)result, (uint32_t)IOTSECURITY_RESULT_OK);

    result = core_collect(core_ptr);

    // validate all collectors are called at first
    assert_true(validate_collected(core_get_collector_collection(core_ptr), true/*h1*/, true/*h2*/, true/*h3*/, true/*m1*/, true/*m2*/, true/*l1*/));
    assert_int_equal((uint32_t)result, (uint32_t)expected_result);

    test_time += ASC_HIGH_PRIORITY_INTERVAL;
    result = core_collect(core_ptr);
    assert_true(validate_collected(core_get_collector_collection(core_ptr), true/*h1*/, true/*h2*/, true/*h3*/, false/*m1*/, false/*m2*/, false/*l1*/));
    assert_int_equal((uint32_t)result, (uint32_t)expected_result);

    test_time += ASC_MEDIUM_PRIORITY_INTERVAL;
    result = core_collect(core_ptr);
    assert_true(validate_collected(core_get_collector_collection(core_ptr), true/*h1*/, true/*h2*/, true/*h3*/, true/*m1*/, true/*m2*/, false/*l1*/));
    assert_int_equal((uint32_t)result, (uint32_t)expected_result);

    test_time += ASC_LOW_PRIORITY_INTERVAL;
    result = core_collect(core_ptr);
    assert_true(validate_collected(core_get_collector_collection(core_ptr), true/*h1*/, true/*h2*/, true/*h3*/, true/*m1*/, true/*m2*/, true/*l1*/));
    assert_int_equal((uint32_t)result, (uint32_t)expected_result);

    core_deinit(core_ptr);
}

static void core_ut_event_collection_different_distribution(void** state) {
    IOTSECURITY_RESULT expected_result = IOTSECURITY_RESULT_OK;
    mock_collector_collection_factory_test_data[COLLECTOR_H2].initial_time = itime_time(NULL);
    mock_collector_collection_factory_test_data[COLLECTOR_H3].initial_time = itime_time(NULL);
    mock_collector_collection_factory_test_data[COLLECTOR_M1].initial_time = itime_time(NULL);

    core_t* core_ptr = core_init();
    assert_non_null(core_ptr);

    IOTSECURITY_RESULT result = core_collect(core_ptr);
    assert_int_equal((uint32_t)result, (uint32_t)IOTSECURITY_RESULT_OK);

    assert_true(validate_collected(core_get_collector_collection(core_ptr), true/*h1*/, false/*h2*/, false/*h3*/, false/*m1*/, true/*m2*/, true/*l1*/));
    assert_int_equal((uint32_t)result, (uint32_t)expected_result);

    test_time += ASC_HIGH_PRIORITY_INTERVAL;
    result = core_collect(core_ptr);
    assert_true(validate_collected(core_get_collector_collection(core_ptr), true/*h1*/, true/*h2*/, true/*h3*/, false/*m1*/, false/*m2*/, false/*l1*/));
    assert_int_equal((uint32_t)result, (uint32_t)expected_result);

    test_time += ASC_HIGH_PRIORITY_INTERVAL;
    result = core_collect(core_ptr);
    assert_true(validate_collected(core_get_collector_collection(core_ptr), true/*h1*/, true/*h2*/, true/*h3*/, false/*m1*/, false/*m2*/, false/*l1*/));
    assert_int_equal((uint32_t)result, (uint32_t)expected_result);

    test_time += ASC_HIGH_PRIORITY_INTERVAL;
    result = core_collect(core_ptr);
    assert_true(validate_collected(core_get_collector_collection(core_ptr), true/*h1*/, true/*h2*/, true/*h3*/, true/*m1*/, true/*m2*/, false/*l1*/));
    assert_int_equal((uint32_t)result, (uint32_t)expected_result);

    test_time += ASC_LOW_PRIORITY_INTERVAL;
    result = core_collect(core_ptr);
    assert_true(validate_collected(core_get_collector_collection(core_ptr), true/*h1*/, true/*h2*/, true/*h3*/, true/*m1*/, true/*m2*/, true/*l1*/));
    assert_int_equal((uint32_t)result, (uint32_t)expected_result);

    core_deinit(core_ptr);
}

static void core_ut_create_message_from_single_collector(void** state) {
    mock_collector_collection_init_array = MOCK_COLLECTOR_COLLECTION_FACTORY_MEDIUM;

    IOTSECURITY_RESULT expected_result = IOTSECURITY_RESULT_OK;

    mock_collector_collection_factory_test_data[COLLECTOR_M2].num_of_events = 4;

    linked_list_security_message_t _local_message_list;
    linked_list_security_message_t* message_list = &_local_message_list;
    linked_list_security_message_t_init(message_list, object_pool_security_message_t_free);
    core_t* core_ptr = core_init();
    assert_non_null(core_ptr);

    IOTSECURITY_RESULT result = core_collect(core_ptr);
    assert_int_equal((uint32_t)result, (uint32_t)IOTSECURITY_RESULT_OK);

    result = core_get(core_ptr, message_list);

    assert_string_equal("<m20-m21-m22-m23>", linked_list_security_message_t_get_first(message_list)->data);

    assert_int_equal(1, linked_list_security_message_t_get_size(message_list));
    linked_list_security_message_t_deinit(message_list);

    assert_int_equal((uint32_t)result, (uint32_t)expected_result);

    core_deinit(core_ptr);
}

static void core_ut_collect_event_from_single_collector(void** state) {
    mock_collector_collection_init_array = MOCK_COLLECTOR_COLLECTION_FACTORY_MEDIUM;

    IOTSECURITY_RESULT expected_result = IOTSECURITY_RESULT_OK;

    // the problem here is that deinit doesn't free all resources
    mock_collector_collection_factory_test_data[COLLECTOR_M2].num_of_events = 4;

    core_t* core_ptr = core_init();
    assert_non_null(core_ptr);

    IOTSECURITY_RESULT result = core_collect(core_ptr);

    assert_true(validate_collected(core_get_collector_collection(core_ptr), false/*h1*/, false/*h2*/, false/*h3*/, true/*m1*/, true/*m2*/, false/*l1*/));
    assert_int_equal((uint32_t)result, (uint32_t)expected_result);

    core_deinit(core_ptr);
}

static int core_ut_setup(void** state) {
    max_message_counter_event_list_handle = &max_message_counter_event_list;
    linked_list_event_name_init(max_message_counter_event_list_handle, NULL);
    mock_itime_reset();
    collector_collection_factory_init();
    return 0;
}

static int core_ut_teardown(void** state) {
    core_ut_destroy_max_message_list();
    return 0;
}

int main (void) {
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(core_ut_create_and_destroy, core_ut_setup, core_ut_teardown),
    cmocka_unit_test_setup_teardown(core_ut_create_message_with_round_robin, core_ut_setup, core_ut_teardown),
    cmocka_unit_test_setup_teardown(core_ut_split_message_into_three , core_ut_setup, core_ut_teardown),
    cmocka_unit_test_setup_teardown(core_ut_continue_from_next_collector, core_ut_setup, core_ut_teardown),
    cmocka_unit_test_setup_teardown(core_ut_ignore_huge_event_and_continue, core_ut_setup, core_ut_teardown),
    cmocka_unit_test_setup_teardown(core_ut_empty_message_on_no_events, core_ut_setup, core_ut_teardown),
    cmocka_unit_test_setup_teardown(core_ut_event_collections, core_ut_setup, core_ut_teardown),
    cmocka_unit_test_setup_teardown(core_ut_event_collection_different_distribution, core_ut_setup, core_ut_teardown),
    cmocka_unit_test_setup_teardown(core_ut_create_message_from_single_collector, core_ut_setup, core_ut_teardown),
    cmocka_unit_test_setup_teardown(core_ut_collect_event_from_single_collector, core_ut_setup, core_ut_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}