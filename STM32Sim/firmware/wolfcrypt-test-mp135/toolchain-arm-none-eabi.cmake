set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_CXX_COMPILER arm-none-eabi-g++)
set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)

set(CMAKE_AR arm-none-eabi-ar)
set(CMAKE_RANLIB arm-none-eabi-ranlib)

set(CMAKE_C_STANDARD 11)

# Cortex-A7 in ARM mode (not Thumb). NEON/VFPv4 hardfloat matches the
# MP135 reference SDK build. -Os keeps the test binary down so it fits
# in the 16 MiB DDR window the simulator maps.
set(CPU_FLAGS "-mcpu=cortex-a7 -marm -mfpu=neon-vfpv4 -mfloat-abi=hard")
set(OPT_FLAGS "-Os -ffunction-sections -fdata-sections")
# CORE_CA7 is what gates the Cortex-A7 device-header selection in the
# MP13 CMSIS device header. Both this firmware and the wolfSSL static
# library need it set; passing via the toolchain catches both.
set(CMAKE_C_FLAGS_INIT "${CPU_FLAGS} ${OPT_FLAGS} -DSTM32MP135Fxx -DCORE_CA7")
set(CMAKE_CXX_FLAGS_INIT "${CPU_FLAGS} ${OPT_FLAGS} -DSTM32MP135Fxx -DCORE_CA7")
set(CMAKE_ASM_FLAGS_INIT "${CPU_FLAGS}")

set(CMAKE_EXE_LINKER_FLAGS_INIT "-Wl,--gc-sections -static")
