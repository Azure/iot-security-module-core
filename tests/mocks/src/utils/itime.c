#include <string.h>
#include <time.h>
#include "../../inc/utils/itime.h"

time_t test_time = TEST_TIME_T;


void mock_itime_reset() {
    test_time = TEST_TIME_T;
}


time_t __wrap_itime_time(time_t* p) {
    return test_time;
}


struct tm* __wrap_itime_utcnow(time_t* timer, struct tm* buf) {
    // buf->__tm_zone = "GMT";
    // buf->__tm_gmtoff = 0;
    buf->tm_sec = 12;
    buf->tm_min = 12;
    buf->tm_hour= 12;
    buf->tm_mday = 12;
    buf->tm_mon = 11;
    buf->tm_year = 112;
    buf->tm_wday = 3;
    buf->tm_yday = 346;
    buf->tm_isdst = 0;
    return buf;
}


struct tm* __wrap_itime_localtime(time_t* timer, struct tm* buf) {
    // buf->__tm_zone = "IST";
    // buf->__tm_gmtoff = 7200;
    buf->tm_sec = 12;
    buf->tm_min = 12;
    buf->tm_hour= 14;
    buf->tm_mday = 12;
    buf->tm_mon = 11;
    buf->tm_year = 112;
    buf->tm_wday = 3;
    buf->tm_yday = 346;
    buf->tm_isdst = 0;
    return buf;
}


size_t __wrap_itime_iso8601(const struct tm* tp, char* s) {

    if (tp->tm_hour == 12) {
        strcpy(s, "2012-12-12T12:12:12");
    } else if (tp->tm_hour == 14) {
        strcpy(s, "2012-12-12T14:12:12");
    }

    return sizeof(s);
}


double __wrap_itime_difftime(time_t time1, time_t time0) {
    return (double)(time1 - time0);
}
