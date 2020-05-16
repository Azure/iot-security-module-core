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

#ifndef MOCK_IRAND_H
#define MOCK_IRAND_H

#include <stdlib.h>
#include <stdint.h>

void mock_rand_int_set_value(uint32_t value);

uint32_t __wrap_irand_int(void);

#endif /* MOCK_IRAND_H */