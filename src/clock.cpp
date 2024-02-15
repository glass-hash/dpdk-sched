//--------------------------------------------------------------------------
// Copyright (C) 2016-2018 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// tsc_clock.cc author Russ Combs <rucombs@cisco.com>

// the STL chrono clocks are kinda heavy so we use the time stamp counter
// where available (x86 with rdtsc support).  this wasn't always a good
// choice on multi-core systems but most now have rdtscp, constant_tsc,
// tsc_reliable, and nonstop_tsc.  note that we don't worry about exact
// instruction sequencing.
//
// references:
// http://stackoverflow.com/questions/275004/timer-function-to-provide-time-in-nano-seconds-using-c
// http://stackoverflow.com/questions/7935518/is-clock-gettime-adequate-for-submicrosecond-timing
//
// this clock stores ticks, not actual time values.  use ticks during runtime
// convert from/to usecs at startup/shutdown.  see clock_defs.h.

#include "clock.h"

#include <chrono>
#include <ctime>
#include <thread>

struct TscClock {
  typedef uint64_t duration;
  typedef uint64_t time_point;

  static const bool is_steady = true;

  static uint64_t counter() {
#if defined(__aarch64__)
    uint64_t ticks;

    asm volatile("mrs %0, CNTVCT_EL0" : "=r"(ticks));
    return ticks;
#else
    // Default to x86, other archs will compile error anyway
    uint32_t lo, hi;
    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#endif
  }

  static time_point now() noexcept { return time_point(duration(counter())); }
};

uint64_t clock_scale() {
  static thread_local uint64_t tpus = 0;  // ticks / usec

  if (!tpus) {
    struct timespec one_sec = {1, 0};
    uint64_t start = TscClock::counter();
    nanosleep(&one_sec, nullptr);
    uint64_t end = TscClock::counter();
    tpus = (uint64_t)((end - start) / 1e6);
  }

  return tpus;
}

ticks_t now() { return TscClock::now(); }

void sleep_ms(time_ms_t time) {
  std::this_thread::sleep_for(std::chrono::milliseconds(time));
}

void sleep_s(time_s_t time) {
  std::this_thread::sleep_for(std::chrono::seconds(time));
}
