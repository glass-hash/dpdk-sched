#pragma once

#include <stdio.h>

#ifdef NDEBUG
#define LOG_DEBUG(...)
#else
#define LOG_DEBUG(fmt, ...)                   \
  {                                           \
    fprintf(stderr, fmt "\n", ##__VA_ARGS__); \
    fflush(stderr);                           \
  }
#endif

#define LOG(fmt, ...)                \
  {                                  \
    printf(fmt "\n", ##__VA_ARGS__); \
    fflush(stdout);                  \
  }

#define WARNING(fmt, ...)                        \
  {                                              \
    printf("WARNING: " fmt "\n", ##__VA_ARGS__); \
    fflush(stdout);                              \
  }
