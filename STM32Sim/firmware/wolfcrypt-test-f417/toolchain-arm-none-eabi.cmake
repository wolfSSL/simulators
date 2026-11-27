# arm-none-eabi toolchain for the STM32F417 wolfCrypt firmware.
#
# ST/ARM vendor trees (cmsis-device-f4, stm32f4xx-hal-driver, CMSIS_5) are
# expected under /opt, as the Docker image lays them out. Set the
# STM32SIM_VENDOR_DIR environment variable to build against another root.

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_CXX_COMPILER arm-none-eabi-g++)
set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)

set(CMAKE_AR arm-none-eabi-ar)
set(CMAKE_RANLIB arm-none-eabi-ranlib)

set(CMAKE_C_STANDARD 11)

if(DEFINED ENV{STM32SIM_VENDOR_DIR})
    set(STM32SIM_VENDOR_DIR "$ENV{STM32SIM_VENDOR_DIR}")
else()
    set(STM32SIM_VENDOR_DIR "/opt")
endif()

set(CPU_FLAGS "-mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard")
set(OPT_FLAGS "-Os -ffunction-sections -fdata-sections")
set(CMSIS_INCLUDES "-I${STM32SIM_VENDOR_DIR}/cmsis-device-f4/Include -I${STM32SIM_VENDOR_DIR}/CMSIS_5/CMSIS/Core/Include -I${CMAKE_CURRENT_LIST_DIR}")

set(CMAKE_C_FLAGS_INIT "${CPU_FLAGS} ${OPT_FLAGS} ${CMSIS_INCLUDES} -DSTM32F417xx")
set(CMAKE_CXX_FLAGS_INIT "${CPU_FLAGS} ${OPT_FLAGS} ${CMSIS_INCLUDES} -DSTM32F417xx")
set(CMAKE_ASM_FLAGS_INIT "${CPU_FLAGS}")

set(CMAKE_EXE_LINKER_FLAGS_INIT "-Wl,--gc-sections -static")
