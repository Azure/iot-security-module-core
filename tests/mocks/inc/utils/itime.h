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

#ifndef MOCK_ITIME_H
#define MOCK_ITIME_H

#include <time.h>

#define TEST_TIME_T ((time_t)3600)
time_t test_time;

void mock_itime_reset();

time_t __wrap_itime_time(time_t* timer);
struct tm* __wrap_itime_utcnow(time_t* timer, struct tm* buf);
struct tm* __wrap_itime_localtime(time_t* timer, struct tm* buf);
size_t __wrap_itime_iso8601(const struct tm* tp, char* s);
double __wrap_itime_difftime(time_t time1, time_t time0);
double __wrap_itime_difftime(time_t stopTime, time_t startTime);

#endif /* MOCK_ITIME_H */