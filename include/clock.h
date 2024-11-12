#ifndef PKTGEN_SRC_CLOCK_H_
#define PKTGEN_SRC_CLOCK_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "pktgen.h"

typedef uint64_t ticks_t;

ticks_t now();
uint64_t clock_scale();

void sleep_ms(time_ms_t time);
void sleep_s(time_s_t time);

#ifdef __cplusplus
}
#endif

#endif  // PKTGEN_SRC_CLOCK_H_
