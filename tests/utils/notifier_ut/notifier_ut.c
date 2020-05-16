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

#include "asc_security_core/iotsecurity_result.h"
#include "asc_security_core/utils/containerof.h"
#include "asc_security_core/utils/notifier.h"

typedef struct main_ctx_t {
	notifier_t system_notify;
} main_ctx_t;

static main_ctx_t g_main_ctx;
static notifier_t system_notify;

static bool g_CB = false;
static bool g_CB_ctx = false;

static void _reset_results() {
    g_CB = false;
    g_CB_ctx = false;
}

static void _cb(notifier_t *notifier, int msg, void *payload) {
    g_CB = true;
}

static void _cb_ctx(notifier_t *notifier, int msg, void *payload) {
	/* We are in subscriber area - so we know if notifier is defined under it's context */
	main_ctx_t *d = containerof(notifier, main_ctx_t, system_notify);

    if (d == &g_main_ctx) {
        g_CB_ctx = true;
    } else {
        g_CB_ctx = false;
    }
}

static int notifier_ut_setup(void** state) {
    assert_int_equal(IOTSECURITY_RESULT_OK, notifier_deinit(NOTIFY_TOPIC_SYSTEM));
    return 0;
}

static int notifier_ut_teardown(void** state) {
    assert_int_equal(IOTSECURITY_RESULT_OK, notifier_deinit(NOTIFY_TOPIC_SYSTEM));
    return 0;
}

static void notifiers_subscribe_notify_unsubscribe(void** state) {
    /* Subscribe notifier without context */
    system_notify.notify = _cb;
    assert_int_equal(IOTSECURITY_RESULT_OK, notifier_subscribe(NOTIFY_TOPIC_SYSTEM, &system_notify));

    /* Subscribe notifier with context - as part of g_main_ctx - it MUST be NOT pointer inside parent struct to take containerof */
    g_main_ctx.system_notify.notify = _cb_ctx;
    assert_int_equal(IOTSECURITY_RESULT_OK, notifier_subscribe(NOTIFY_TOPIC_SYSTEM, &g_main_ctx.system_notify));

    /* Notify - both subscribers will be called - count = 2 */
    _reset_results();
    assert_int_equal(2, notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, NULL));
    /* Both CBs were called */
    assert_true(g_CB);
    assert_true(g_CB_ctx);

    /* Unsubscribe no ctx notifier */
    assert_int_equal(IOTSECURITY_RESULT_OK, notifier_unsubscribe(NOTIFY_TOPIC_SYSTEM, &system_notify));
    _reset_results();
    /* Notify - only one subscriber will be called - count = 1 */
    assert_int_equal(1, notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, NULL));
    /* Only on cb was called */
    assert_false(g_CB);
    assert_true(g_CB_ctx);

    /* Unsubscribe ctx notifier */
    assert_int_equal(IOTSECURITY_RESULT_OK, notifier_unsubscribe(NOTIFY_TOPIC_SYSTEM, &g_main_ctx.system_notify));
    _reset_results();
    /* Notify - none will be called - count = 0 */
    assert_int_equal(0, notifier_notify(NOTIFY_TOPIC_SYSTEM, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, NULL));
    /* Both CBs were not called */
    assert_false(g_CB);
    assert_false(g_CB_ctx);
}

static void notifiers_negative(void** state) {
    int i;

    /* Subscribe, unsubscribe and notify notifier with wrong topic */
    assert_int_equal(IOTSECURITY_RESULT_BAD_ARGUMENT, notifier_subscribe(NOTIFY_TOPICS_NUMBER, &system_notify));
    assert_int_equal(IOTSECURITY_RESULT_BAD_ARGUMENT, notifier_unsubscribe(NOTIFY_TOPICS_NUMBER, &g_main_ctx.system_notify));
    assert_int_equal(-1, notifier_notify(NOTIFY_TOPICS_NUMBER, NOTIFY_MESSAGE_SYSTEM_CONFIGURATION, NULL));
    assert_int_equal(IOTSECURITY_RESULT_BAD_ARGUMENT, notifier_deinit(NOTIFY_TOPICS_NUMBER));

    /* Unsubscribe non-exists notifier */
    assert_int_equal(IOTSECURITY_RESULT_BAD_ARGUMENT, notifier_unsubscribe(NOTIFY_TOPIC_SYSTEM, NULL));

    /* Subscribe notifier with over pull - NOTIFIERS_POOL_ENTRIES is ok */
    for (i = 0; i < NOTIFIERS_POOL_ENTRIES; i++) {
        assert_int_equal(IOTSECURITY_RESULT_OK, notifier_subscribe(NOTIFY_TOPIC_SYSTEM, &system_notify));
    }
    assert_int_equal(IOTSECURITY_RESULT_MEMORY_EXCEPTION, notifier_subscribe(NOTIFY_TOPIC_SYSTEM, &system_notify));
    assert_int_equal(IOTSECURITY_RESULT_OK, notifier_deinit(NOTIFY_TOPIC_SYSTEM));
}

int main (void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(notifiers_subscribe_notify_unsubscribe, notifier_ut_setup, notifier_ut_teardown),
        cmocka_unit_test_setup_teardown(notifiers_negative, notifier_ut_setup, notifier_ut_teardown),
        };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
