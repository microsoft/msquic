set(GCC_COMPILER_VERSION "" CACHE STRING "GCC Compiler version")
set(GNU_MACHINE "aarch64-linux-gnu" CACHE STRING "GNU compiler triplet")

if(COMMAND toolchain_save_config)
  return() # prevent recursive call
endif()

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_VERSION 1)
if(NOT DEFINED CMAKE_SYSTEM_PROCESSOR)
  set(CMAKE_SYSTEM_PROCESSOR aarch64)
else()
  #message("CMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/gnu.toolchain.cmake")

if(CMAKE_SYSTEM_PROCESSOR STREQUAL arm AND NOT ARM_IGNORE_FP)
  set(FLOAT_ABI_SUFFIX "")
  if(NOT SOFTFP)
    set(FLOAT_ABI_SUFFIX "hf")
  endif()
endif()

if(NOT "x${GCC_COMPILER_VERSION}" STREQUAL "x")
  set(__GCC_VER_SUFFIX "-${GCC_COMPILER_VERSION}")
endif()

find_program(CMAKE_C_COMPILER NAMES ${GNU_MACHINE}${FLOAT_ABI_SUFFIX}-gcc${__GCC_VER_SUFFIX})
if (NOT CMAKE_C_COMPILER)
  message(FATAL_ERROR "${GNU_MACHINE}${FLOAT_ABI_SUFFIX}-gcc${__GCC_VER_SUFFIX} not found")
endif()

find_program(CMAKE_CXX_COMPILER NAMES ${GNU_MACHINE}${FLOAT_ABI_SUFFIX}-g++${__GCC_VER_SUFFIX})
if (NOT CMAKE_CXX_COMPILER)
  message(FATAL_ERROR "${GNU_MACHINE}${FLOAT_ABI_SUFFIX}-g++${__GCC_VER_SUFFIX} not found")
endif()

find_program(CMAKE_LINKER NAMES ${GNU_MACHINE}${FLOAT_ABI_SUFFIX}-ld${__GCC_VER_SUFFIX} ${GNU_MACHINE}${FLOAT_ABI_SUFFIX}-ld)
if(NOT CMAKE_LINKER)
  message(FATAL_ERROR "CMAKE_LINKER=${CMAKE_LINKER} is defined")
endif()

find_program(CMAKE_AR NAMES ${GNU_MACHINE}${FLOAT_ABI_SUFFIX}-ar${__GCC_VER_SUFFIX} ${GNU_MACHINE}${FLOAT_ABI_SUFFIX}-ar)
if(NOT CMAKE_AR)
  message(FATAL_ERROR "CMAKE_AR=${CMAKE_AR} is defined")
endif()

if(NOT DEFINED ARM_LINUX_SYSROOT AND DEFINED GNU_MACHINE)
  set(ARM_LINUX_SYSROOT /usr/${GNU_MACHINE}${FLOAT_ABI_SUFFIX})
endif()

if(USE_NEON)
  message(WARNING "You use obsolete variable USE_NEON to enable NEON instruction set. Use -DENABLE_NEON=ON instead." )
  set(ENABLE_NEON TRUE)
elseif(USE_VFPV3)
  message(WARNING "You use obsolete variable USE_VFPV3 to enable VFPV3 instruction set. Use -DENABLE_VFPV3=ON instead." )
  set(ENABLE_VFPV3 TRUE)
endif()

set(CMAKE_FIND_ROOT_PATH ${CMAKE_FIND_ROOT_PATH} ${ARM_LINUX_SYSROOT})

set(TOOLCHAIN_CONFIG_VARS ${TOOLCHAIN_CONFIG_VARS}
    ARM_LINUX_SYSROOT
    ENABLE_NEON
    ENABLE_VFPV3
)
toolchain_save_config()