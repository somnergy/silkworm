# riscv32im-toolchain.cmake
set(CMAKE_SYSTEM_NAME Generic)        # No OS (bare-metal target)
set(CMAKE_SYSTEM_PROCESSOR riscv32)   # Target CPU architecture

# Cross-compiler executables
set(CMAKE_C_COMPILER   riscv-none-elf-gcc)
set(CMAKE_CXX_COMPILER riscv-none-elf-g++)
set(CMAKE_ASM_COMPILER riscv-none-elf-gcc)

# Specify the architecture and ABI (RV32IM, 32-bit ILP32 ABI)
set(common_flags "-march=rv32im -mabi=ilp32 -mcmodel=medany -ffunction-sections -fdata-sections")
set(CMAKE_C_FLAGS_INIT   "${common_flags}")
set(CMAKE_CXX_FLAGS_INIT "${common_flags} -fno-exceptions -fno-rtti") # tweak if you need exceptions/RTTI

# Optionally, specify linker script and flags:
# Here we assume QEMU virt machine, load address 0x80000000
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Tvirt.ld -nostartfiles")
