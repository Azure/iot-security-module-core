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

#ifndef MOCK_COLLECTOR_INTERNAL_H
#define MOCK_COLLECTOR_INTERNAL_H

#include <stdbool.h>
#include "asc_security_core/object_pool.h"
#include "asc_security_core/model/collector.h"

/**
 * @brief Initialize collector internal
 *
 * @param name                  The collector name
 * @param type                  The collector type
 * @param priority              The collector priority
 * @param event_queue_max_size  The event queue max capacity
 *
 * @return A handle to the collector internal
 */
IOTSECURITY_RESULT collector_mock_init_with_params(collector_internal_t* collector_internal_ptr, const char* name, COLLECTOR_TYPE type, COLLECTOR_PRIORITY priority);

/**
 * @brief Initialize collector internal
 *
 * @return A handle to the collector internal
 */
IOTSECURITY_RESULT collector_mock_init(collector_internal_t* collector_internal_ptr);

/**
 * @brief Get events from the collector internal
 *
 * @param collector_internal_t*   The collector internal handle.
 * @param events   A list to which the Event[s] should be added.
 *
 * @return   IOTSECURITY_RESULT_OK on success
 *           IOTSECURITY_RESULT_EMPTY when there are no events. In that case, @events will be null.
 *           IOTSECURITY_RESULT_EXCEPTION otherwise
 */
IOTSECURITY_RESULT collector_mock_get_events(collector_internal_t* collector_internal_ptr, linked_list_event_t_handle events);

/**
 * @brief Function which used in order to free a specific collector internal handle.
 *
 * @param collector_internal_t*   Collector to be freed.
 */
void collector_mock_deinit(collector_internal_t* collector_internal_ptr);

/**
 * @brief Add a single event to the collector internal queue
 *
 * @param collector_internal_t*   The collector internal handle.
 * @param event_name   The event name.
 *
 * @return   IOTSECURITY_RESULT_OK on success
 *           IOTSECURITY_RESULT_EXCEPTION otherwise
 */
IOTSECURITY_RESULT collector_mock_add_event_to_queue(collector_internal_t* collector_internal, const char* event_name);

struct collector_state_tag {
    COLLECTION_INTERFACE(struct collector_state_tag);
    linked_list_event_t event_queue;
};

typedef struct collector_state_tag collector_state;
typedef struct collector_state_tag* collector_state_handle;

#endif /* MOCK_COLLECTOR_INTERNAL_H */