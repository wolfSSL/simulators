cmake_minimum_required(VERSION 3.18)
project(wolfcrypt_stm32f417 LANGUAGES C ASM)

# WOLFSSL_ROOT is the path to a wolfSSL source tree. The Docker entrypoint
# mounts the user's wolfSSL into /opt/wolfssl by default.
set(WOLFSSL_ROOT "/opt/wolfssl" CACHE PATH "wolfSSL source")

# ST/ARM vendor trees; see toolchain-arm-none-eabi.cmake.
if(NOT DEFINED STM32SIM_VENDOR_DIR)
    if(DEFINED ENV{STM32SIM_VENDOR_DIR})
        set(STM32SIM_VENDOR_DIR "$ENV{STM32SIM_VENDOR_DIR}")
    else()
        set(STM32SIM_VENDOR_DIR "/opt")
    endif()
endif()
set(CMSIS_CORE_INC   ${STM32SIM_VENDOR_DIR}/CMSIS_5/CMSIS/Core/Include)
set(CMSIS_DEVICE_INC ${STM32SIM_VENDOR_DIR}/cmsis-device-f4/Include)
set(HAL_DIR          ${STM32SIM_VENDOR_DIR}/stm32f4xx-hal-driver)

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
enable_language(ASM)

# Order matters: this directory first (user_settings.h and
# stm32f4xx_hal_conf.h), then CMSIS core, device CMSIS, and the HAL.
include_directories(BEFORE
    ${CMAKE_SOURCE_DIR}
    ${CMSIS_CORE_INC}
    ${CMSIS_DEVICE_INC}
    ${HAL_DIR}/Inc/Legacy
    ${HAL_DIR}/Inc
)

set(HAL_SRC_DIR ${HAL_DIR}/Src)
if(EXISTS ${HAL_SRC_DIR})
    set(HAL_SOURCES
        ${HAL_SRC_DIR}/stm32f4xx_hal.c
        ${HAL_SRC_DIR}/stm32f4xx_hal_rcc.c
        ${HAL_SRC_DIR}/stm32f4xx_hal_rcc_ex.c
        ${HAL_SRC_DIR}/stm32f4xx_hal_cortex.c
        ${HAL_SRC_DIR}/stm32f4xx_hal_dma.c
        ${HAL_SRC_DIR}/stm32f4xx_hal_dma_ex.c
        ${HAL_SRC_DIR}/stm32f4xx_hal_rng.c
        ${HAL_SRC_DIR}/stm32f4xx_hal_cryp.c
        ${HAL_SRC_DIR}/stm32f4xx_hal_cryp_ex.c
        ${HAL_SRC_DIR}/stm32f4xx_hal_hash.c
        ${HAL_SRC_DIR}/stm32f4xx_hal_hash_ex.c
    )
else()
    message(FATAL_ERROR "STM32F4 HAL source directory not found: ${HAL_SRC_DIR}")
endif()

# wolfSSL build options
set(WOLFSSL_USER_SETTINGS ON CACHE BOOL "Use user_settings.h")
set(WOLFSSL_CRYPT_TESTS OFF CACHE BOOL "")
set(WOLFSSL_EXAMPLES OFF CACHE BOOL "")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "")

add_subdirectory(${WOLFSSL_ROOT} ${CMAKE_BINARY_DIR}/wolfssl-build EXCLUDE_FROM_ALL)
target_include_directories(wolfssl PRIVATE
    ${CMSIS_CORE_INC}
    ${CMSIS_DEVICE_INC}
    ${HAL_DIR}/Inc/Legacy
    ${HAL_DIR}/Inc
    ${CMAKE_SOURCE_DIR}
)
target_compile_definitions(wolfssl PRIVATE STM32F417xx USE_HAL_DRIVER)
target_compile_options(wolfssl PRIVATE -Wno-cpp)

# wolfSSL STM32 port driving the CRYP (through the HAL) and HASH.
set(WOLFSSL_STM32_PORT_SRC ${WOLFSSL_ROOT}/wolfcrypt/src/port/st/stm32.c)

add_executable(wolfcrypt_test.elf
    startup_stm32f417.c
    main.c
    ${WOLFSSL_ROOT}/wolfcrypt/test/test.c
    ${HAL_SOURCES}
    ${WOLFSSL_STM32_PORT_SRC}
)

target_include_directories(wolfcrypt_test.elf PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${WOLFSSL_ROOT}
)

target_compile_definitions(wolfcrypt_test.elf PRIVATE
    WOLFSSL_USER_SETTINGS
    STM32F417xx
    USE_HAL_DRIVER
)

set_source_files_properties(${HAL_SOURCES} PROPERTIES
    COMPILE_FLAGS "-mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard -ffunction-sections -fdata-sections -Os -include stdint.h -w"
)

target_compile_options(wolfcrypt_test.elf PRIVATE
    -mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard
    -ffunction-sections -fdata-sections -Os
)

target_link_options(wolfcrypt_test.elf PRIVATE
    -T${CMAKE_SOURCE_DIR}/stm32f417.ld
    -Wl,--gc-sections
    -nostartfiles
    -specs=nano.specs
    -specs=nosys.specs
)

target_link_libraries(wolfcrypt_test.elf PRIVATE wolfssl m c gcc nosys)
