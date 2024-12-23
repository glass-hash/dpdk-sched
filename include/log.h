#pragma once

#include <iostream>

#define LOG(line)                   \
  do {                              \
    std::cout << line << std::endl; \
  } while (0);

#define WARNING(line)               \
  do {                              \
    std::cerr << line << std::endl; \
  } while (0);
