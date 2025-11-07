[settings]
os=baremetal
arch=riscv64
compiler=gcc
compiler.version=14
# compiler.libcxx=libstdc++11
compiler.cppstd=gnu20
build_type=Release

[conf]
tools.build:compiler_executables={"c": "riscv-none-elf-gcc","cpp": "riscv-none-elf-g++", "ar":"riscv-none-elf-ar"}
tools.build:cflags=["-march=rv64im","-mabi=lp64","-mcmodel=medany"]
tools.build:cxxflags=["-march=rv64im","-mabi=lp64","-mcmodel=medany"]
tools.build:sharedlinkflags=["-march=rv64im","-mabi=lp64","-mcmodel=medany","-nostdlib","-Wl,--gc-sections"]

[buildenv]
CC=riscv-none-elf-gcc
CXX=riscv-none-elf-g++