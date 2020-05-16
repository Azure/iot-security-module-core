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

#ifndef MOCK_COLLECTOR_COLLECTION_FACTORY_H
#define MOCK_COLLECTOR_COLLECTION_FACTORY_H

#include "asc_security_core/model/collector.h"
#include "asc_security_core/collector_collection.h"

struct INIT_DATA_TAG {
    time_t initial_time;
    time_t num_of_events;
};
typedef struct INIT_DATA_TAG* TEST_DATA_HANDLE;

typedef enum MOCK_COLLECTOR_COLLECTION_FACTORY_TAG {
    MOCK_COLLECTOR_COLLECTION_FACTORY_ALL = 0,
    MOCK_COLLECTOR_COLLECTION_FACTORY_MEDIUM = 1,
    MOCK_COLLECTOR_COLLECTION_FACTORY_NO_MEDIUM = 2,
    MOCK_COLLECTOR_COLLECTION_FACTORY_EMPTY = 3
} MOCK_COLLECTOR_COLLECTION_FACTORY;

struct INIT_DATA_TAG mock_collector_collection_factory_test_data[6];

#define COLLECTOR_H1 0
#define COLLECTOR_H2 1
#define COLLECTOR_H3 2
#define COLLECTOR_M1 3
#define COLLECTOR_M2 4
#define COLLECTOR_L1 5

MOCK_COLLECTOR_COLLECTION_FACTORY mock_collector_collection_init_array;

void collector_collection_factory_init();

void collector_collection_factory_init_test_data(uint32_t h1, uint32_t h2, uint32_t h3, uint32_t m1, uint32_t m2, uint32_t l1);

#endif /* MOCK_COLLECTOR_COLLECTION_FACTORY_H */