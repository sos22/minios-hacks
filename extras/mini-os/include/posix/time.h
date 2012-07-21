#ifndef _POSIX_TIME_H
#define _POSIX_TIME_H

#include <sys/time.h>
#define CLOCK_MONOTONIC	2

int nanosleep(const struct timespec *req, struct timespec *rem);
int clock_gettime(clockid_t clock_id, struct timespec *tp);

#endif /* _POSIX_TIME_H */
