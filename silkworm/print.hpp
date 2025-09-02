
#pragma once
#ifdef SP1
#include "sp1_syscalls.hpp"
#else
inline void sys_println(std::string_view msg) {
    std::cout << "stdout: " << msg << std::endl;
}
#endif
