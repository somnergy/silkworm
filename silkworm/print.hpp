
#pragma once
#ifdef SP1
#include "sp1_syscalls.hpp"
#else
inline void sys_println(const char* msg) {
    std::cout << "stdout: " << msg << std::endl;
}
inline void sys_print(const char* msg) {
    std::cout << "stdout: " << msg;
}
#endif
