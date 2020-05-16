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

#ifndef _MOCK_UTILS_H
#define _MOCK_UTILS_H

#include "asc_security_core/asc/asc_span.h"

void assert_asc_span_equal(asc_span exp, const char *value);

#endif /* _MOCK_UTILS_H */