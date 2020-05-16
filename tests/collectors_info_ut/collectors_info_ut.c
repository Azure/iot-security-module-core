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

#include "asc_security_core/collectors/system_information.h"
#include "asc_security_core/collectors/collectors_information.h"
#include "asc_security_core/model/collector_enums.h"
#include "asc_security_core/model/event.h"
#include "asc_security_core/model/schema/schema_system_information.h"
#include "asc_security_core/utils/notifier.h"
#include "../mocks/inc/utils/utils.h"

static void collectors_info_init_deinit(void** state) {
    collectors_info_handle info_handle = (collectors_info_handle)*state;

    assert_non_null(info_handle);
}

static void collectors_info_gathering_info(void** state) {
    collectors_info_handle info_handle = (collectors_info_handle)*state;
    collector_internal_t collector;
    char expected[SCHEMA_EXTRA_DETAILS_BUFFER_MAX_SIZE] = {0};
    asc_pair extra_details[SYSTEM_INFORMATION_SCHEMA_EXTRA_DETAILS_ENTRIES] = {
        asc_pair_from_str("Preset", "1"),
        ASC_PAIR_NULL
    };
    asc_pair entry;
    int i = 0;

    assert_non_null(info_handle);

    collector.type = COLLECTOR_TYPE_SYSTEM_INFORMATION;
    collector.priority = COLLECTOR_PRIORITY_LOW;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, &collector);

    collector.type = COLLECTOR_TYPE_CONNECTION_CREATE;
    collector.priority = COLLECTOR_PRIORITY_HIGH;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, &collector);

    collector.type = COLLECTOR_TYPE_LISTENING_PORTS;
    collector.priority = COLLECTOR_PRIORITY_MEDIUM;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, &collector);

    collector.type = COLLECTOR_TYPE_HEARTBEAT;
    collector.priority = COLLECTOR_PRIORITY_HIGH;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, &collector);

    collector.type = COLLECTOR_TYPE_TEST;
    collector.priority = COLLECTOR_PRIORITY_LOW;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, &collector);

    collectors_info_append(info_handle, extra_details, SYSTEM_INFORMATION_SCHEMA_EXTRA_DETAILS_ENTRIES);

    entry = extra_details[i++];
    assert_asc_span_equal(entry.key, "Preset");
    assert_asc_span_equal(entry.value, "1");

    entry = extra_details[i++];
    sprintf(expected, "%d", g_collector_collections_intervals[COLLECTOR_PRIORITY_LOW]);
    assert_asc_span_equal(entry.key, g_collector_names[COLLECTOR_TYPE_SYSTEM_INFORMATION]);
    assert_asc_span_equal(entry.value, expected);

    entry = extra_details[i++];
    sprintf(expected, "%d", g_collector_collections_intervals[COLLECTOR_PRIORITY_HIGH]);
    assert_asc_span_equal(entry.key, g_collector_names[COLLECTOR_TYPE_CONNECTION_CREATE]);
    assert_asc_span_equal(entry.value, expected);

    entry = extra_details[i++];
    sprintf(expected, "%d", g_collector_collections_intervals[COLLECTOR_PRIORITY_MEDIUM]);
    assert_asc_span_equal(entry.key, g_collector_names[COLLECTOR_TYPE_LISTENING_PORTS]);
    assert_asc_span_equal(entry.value, expected);

    entry = extra_details[i++];
    sprintf(expected, "%d", g_collector_collections_intervals[COLLECTOR_PRIORITY_HIGH]);
    assert_asc_span_equal(entry.key, g_collector_names[COLLECTOR_TYPE_HEARTBEAT]);
    assert_asc_span_equal(entry.value, expected);

    entry = extra_details[i++];
    sprintf(expected, "%d", g_collector_collections_intervals[COLLECTOR_PRIORITY_LOW]);
    assert_asc_span_equal(entry.key, g_collector_names[COLLECTOR_TYPE_TEST]);
    assert_asc_span_equal(entry.value, expected);
}

static void collectors_info_update_info(void** state) {
    collectors_info_handle info_handle = (collectors_info_handle)*state;
    collector_internal_t collector;
    char expected[SCHEMA_EXTRA_DETAILS_BUFFER_MAX_SIZE] = {0};
    asc_pair extra_details[SYSTEM_INFORMATION_SCHEMA_EXTRA_DETAILS_ENTRIES] = { ASC_PAIR_NULL };
    asc_pair entry;

    assert_non_null(info_handle);

    collector.type = COLLECTOR_TYPE_SYSTEM_INFORMATION;
    collector.priority = COLLECTOR_PRIORITY_LOW;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, &collector);
    collectors_info_append(info_handle, extra_details, SYSTEM_INFORMATION_SCHEMA_EXTRA_DETAILS_ENTRIES);
    entry = extra_details[0];
    sprintf(expected, "%d", g_collector_collections_intervals[COLLECTOR_PRIORITY_LOW]);
    assert_asc_span_equal(entry.key, g_collector_names[COLLECTOR_TYPE_SYSTEM_INFORMATION]);
    assert_asc_span_equal(entry.value, expected);

    extra_details[0] = ASC_PAIR_NULL;

    collector.type = COLLECTOR_TYPE_SYSTEM_INFORMATION;
    collector.priority = COLLECTOR_PRIORITY_MEDIUM;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, &collector);
    collectors_info_append(info_handle, extra_details, SYSTEM_INFORMATION_SCHEMA_EXTRA_DETAILS_ENTRIES);
    entry = extra_details[0];
    sprintf(expected, "%d", g_collector_collections_intervals[COLLECTOR_PRIORITY_MEDIUM]);
    assert_asc_span_equal(entry.key, g_collector_names[COLLECTOR_TYPE_SYSTEM_INFORMATION]);
    assert_asc_span_equal(entry.value, expected);
}

static void collectors_info_negative(void** state) {
    collectors_info_handle info_handle = (collectors_info_handle)*state;
    collectors_info_handle second_handle;
    collector_internal_t collector;
    asc_pair extra_details[SYSTEM_INFORMATION_SCHEMA_EXTRA_DETAILS_ENTRIES] = { ASC_PAIR_NULL };
    asc_pair entry;

    assert_non_null(info_handle);

    /* Init multiple instances of collectors_info */
    second_handle = collectors_info_init();
    if (second_handle != (collectors_info_handle)NULL) {
        collectors_info_deinit(second_handle);
    }
    assert_null(second_handle);

    /* Notify with wrong parameters */
    collector.type = COLLECTOR_TYPE_COUNT;
    collector.priority = COLLECTOR_PRIORITY_MEDIUM;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, &collector);
    collectors_info_append(info_handle, extra_details, SYSTEM_INFORMATION_SCHEMA_EXTRA_DETAILS_ENTRIES);
    entry = extra_details[0];
    assert_int_equal(0, asc_span_length(entry.key));
    assert_int_equal(0, asc_span_length(entry.value));

    collector.type = -1;
    collector.priority = COLLECTOR_PRIORITY_MEDIUM;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, &collector);
    collectors_info_append(info_handle, extra_details, SYSTEM_INFORMATION_SCHEMA_EXTRA_DETAILS_ENTRIES);
    entry = extra_details[0];
    assert_int_equal(0, asc_span_length(entry.key));
    assert_int_equal(0, asc_span_length(entry.value));

    collector.type = COLLECTOR_TYPE_SYSTEM_INFORMATION;
    collector.priority = COLLECTOR_PRIORITY_COUNT;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, &collector);
    collectors_info_append(info_handle, extra_details, SYSTEM_INFORMATION_SCHEMA_EXTRA_DETAILS_ENTRIES);
    entry = extra_details[0];
    assert_int_equal(0, asc_span_length(entry.key));
    assert_int_equal(0, asc_span_length(entry.value));

    collector.type = COLLECTOR_TYPE_SYSTEM_INFORMATION;
    collector.priority = -1;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, &collector);
    collectors_info_append(info_handle, extra_details, SYSTEM_INFORMATION_SCHEMA_EXTRA_DETAILS_ENTRIES);
    entry = extra_details[0];
    assert_int_equal(0, asc_span_length(entry.key));
    assert_int_equal(0, asc_span_length(entry.value));

    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, NULL);
    collectors_info_append(info_handle, extra_details, SYSTEM_INFORMATION_SCHEMA_EXTRA_DETAILS_ENTRIES);
    entry = extra_details[0];
    assert_int_equal(0, asc_span_length(entry.key));
    assert_int_equal(0, asc_span_length(entry.value));
}

static void collectors_info_overflow_info(void** state) {
    collectors_info_handle info_handle = (collectors_info_handle)*state;
    collector_internal_t collector;
    char expected[SCHEMA_EXTRA_DETAILS_BUFFER_MAX_SIZE] = {0};
    asc_pair extra_details[SYSTEM_INFORMATION_SCHEMA_EXTRA_DETAILS_ENTRIES] = {
        asc_pair_from_str("Preset1", "1"),
        asc_pair_from_str("Preset2", "2"),
        ASC_PAIR_NULL
    };
    asc_pair entry;
    int i = 0;

    assert_non_null(info_handle);

    collector.type = COLLECTOR_TYPE_SYSTEM_INFORMATION;
    collector.priority = COLLECTOR_PRIORITY_LOW;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, &collector);

    collector.type = COLLECTOR_TYPE_CONNECTION_CREATE;
    collector.priority = COLLECTOR_PRIORITY_HIGH;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, &collector);

    collector.type = COLLECTOR_TYPE_LISTENING_PORTS;
    collector.priority = COLLECTOR_PRIORITY_MEDIUM;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, &collector);

    collector.type = COLLECTOR_TYPE_HEARTBEAT;
    collector.priority = COLLECTOR_PRIORITY_HIGH;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, &collector);

    collector.type = COLLECTOR_TYPE_TEST;
    collector.priority = COLLECTOR_PRIORITY_LOW;
    notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, &collector);

    collectors_info_append(info_handle, extra_details, SYSTEM_INFORMATION_SCHEMA_EXTRA_DETAILS_ENTRIES);

    entry = extra_details[i++];
    assert_asc_span_equal(entry.key, "Preset1");
    assert_asc_span_equal(entry.value, "1");

    entry = extra_details[i++];
    assert_asc_span_equal(entry.key, "Preset2");
    assert_asc_span_equal(entry.value, "2");

    entry = extra_details[i++];
    sprintf(expected, "%d", g_collector_collections_intervals[COLLECTOR_PRIORITY_LOW]);
    assert_asc_span_equal(entry.key, g_collector_names[COLLECTOR_TYPE_SYSTEM_INFORMATION]);
    assert_asc_span_equal(entry.value, expected);

    entry = extra_details[i++];
    sprintf(expected, "%d", g_collector_collections_intervals[COLLECTOR_PRIORITY_HIGH]);
    assert_asc_span_equal(entry.key, g_collector_names[COLLECTOR_TYPE_CONNECTION_CREATE]);
    assert_asc_span_equal(entry.value, expected);

    entry = extra_details[i++];
    sprintf(expected, "%d", g_collector_collections_intervals[COLLECTOR_PRIORITY_MEDIUM]);
    assert_asc_span_equal(entry.key, g_collector_names[COLLECTOR_TYPE_LISTENING_PORTS]);
    assert_asc_span_equal(entry.value, expected);

    entry = extra_details[i++];
    sprintf(expected, "%d", g_collector_collections_intervals[COLLECTOR_PRIORITY_HIGH]);
    assert_asc_span_equal(entry.key, g_collector_names[COLLECTOR_TYPE_HEARTBEAT]);
    assert_asc_span_equal(entry.value, expected);

    assert_int_equal(SYSTEM_INFORMATION_SCHEMA_EXTRA_DETAILS_ENTRIES, i);
}
int g_flag = 0;

static int collectors_info_ut_setup(void** state) {
    collectors_info_handle info_handle = collectors_info_init();

    *state = (void *)info_handle;
    return 0;
}

static int collectors_info_ut_teardown(void** state) {
    collectors_info_handle info_handle = (collectors_info_handle)*state;

    if (info_handle != (collectors_info_handle)NULL) {
        collectors_info_deinit(info_handle);
        *state = NULL;
    }

    return 0;
}

int main (void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(collectors_info_init_deinit, collectors_info_ut_setup, collectors_info_ut_teardown),
        cmocka_unit_test_setup_teardown(collectors_info_gathering_info, collectors_info_ut_setup, collectors_info_ut_teardown),
        cmocka_unit_test_setup_teardown(collectors_info_update_info, collectors_info_ut_setup, collectors_info_ut_teardown),
        cmocka_unit_test_setup_teardown(collectors_info_negative, collectors_info_ut_setup, collectors_info_ut_teardown),
        cmocka_unit_test_setup_teardown(collectors_info_overflow_info, collectors_info_ut_setup, collectors_info_ut_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
