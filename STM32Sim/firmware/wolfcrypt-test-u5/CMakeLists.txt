cmake_minimum_required(VERSION 3.18)
project(wolfcrypt_stm32u585 LANGUAGES C ASM)

set(WOLFSSL_ROOT "/opt/wolfssl-build-tree" CACHE PATH "wolfSSL source")

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
enable_language(ASM)

include_directories(BEFORE
    ${CMAKE_SOURCE_DIR}
    /opt/CMSIS_5/CMSIS/Core/Include
    /opt/cmsis-device-u5/Include
    /opt/STM32CubeU5/Drivers/STM32U5xx_HAL_Driver/Inc/Legacy
    /opt/STM32CubeU5/Drivers/STM32U5xx_HAL_Driver/Inc
)

set(HAL_SRC_DIR /opt/STM32CubeU5/Drivers/STM32U5xx_HAL_Driver/Src)

if(EXISTS ${HAL_SRC_DIR})
    set(HAL_SOURCES
        ${HAL_SRC_DIR}/stm32u5xx_hal.c
        ${HAL_SRC_DIR}/stm32u5xx_hal_rcc.c
        ${HAL_SRC_DIR}/stm32u5xx_hal_rcc_ex.c
        ${HAL_SRC_DIR}/stm32u5xx_hal_cortex.c
        ${HAL_SRC_DIR}/stm32u5xx_hal_dma.c
        ${HAL_SRC_DIR}/stm32u5xx_hal_dma_ex.c
        ${HAL_SRC_DIR}/stm32u5xx_hal_rng.c
        ${HAL_SRC_DIR}/stm32u5xx_hal_rng_ex.c
        ${HAL_SRC_DIR}/stm32u5xx_hal_cryp.c
        ${HAL_SRC_DIR}/stm32u5xx_hal_cryp_ex.c
        ${HAL_SRC_DIR}/stm32u5xx_hal_hash.c
        ${HAL_SRC_DIR}/stm32u5xx_hal_pka.c
        ${HAL_SRC_DIR}/stm32u5xx_hal_pwr.c
        ${HAL_SRC_DIR}/stm32u5xx_hal_pwr_ex.c
        ${HAL_SRC_DIR}/stm32u5xx_hal_flash.c
        ${HAL_SRC_DIR}/stm32u5xx_hal_flash_ex.c
        ${HAL_SRC_DIR}/stm32u5xx_hal_gpio.c
    )
else()
    message(WARNING "HAL source directory not found: ${HAL_SRC_DIR}")
    set(HAL_SOURCES "")
endif()

set(WOLFSSL_USER_SETTINGS ON CACHE BOOL "Use user_settings.h")
set(WOLFSSL_CRYPT_TESTS OFF CACHE BOOL "")
set(WOLFSSL_EXAMPLES OFF CACHE BOOL "")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "")

add_subdirectory(${WOLFSSL_ROOT} ${CMAKE_BINARY_DIR}/wolfssl-build EXCLUDE_FROM_ALL)
target_include_directories(wolfssl PRIVATE
    /opt/CMSIS_5/CMSIS/Core/Include
    /opt/cmsis-device-u5/Include
    /opt/STM32CubeU5/Drivers/STM32U5xx_HAL_Driver/Inc/Legacy
    /opt/STM32CubeU5/Drivers/STM32U5xx_HAL_Driver/Inc
    ${CMAKE_SOURCE_DIR}
)
target_compile_options(wolfssl PRIVATE -Wno-cpp)

set(WOLFSSL_STM32_PORT_SRC ${WOLFSSL_ROOT}/wolfcrypt/src/port/st/stm32.c)

add_executable(wolfcrypt_test.elf
    startup_stm32u585.c
    main.c
    ${WOLFSSL_ROOT}/wolfcrypt/test/test.c
    ${HAL_SOURCES}
    ${WOLFSSL_STM32_PORT_SRC}
)

target_include_directories(wolfcrypt_test.elf PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${WOLFSSL_ROOT}
    /opt/STM32CubeU5/Drivers/STM32U5xx_HAL_Driver/Inc
    /opt/STM32CubeU5/Drivers/STM32U5xx_HAL_Driver/Inc/Legacy
)

target_compile_definitions(wolfcrypt_test.elf PRIVATE
    WOLFSSL_USER_SETTINGS
    STM32U585xx
    USE_HAL_DRIVER
    USE_HAL_CONF
)

set_source_files_properties(${HAL_SOURCES} PROPERTIES
    COMPILE_FLAGS "-mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard -ffunction-sections -fdata-sections -Os -include stdint.h -w"
)

target_compile_options(wolfcrypt_test.elf PRIVATE
    -mcpu=cortex-m33 -mthumb -mfpu=fpv5-sp-d16 -mfloat-abi=hard
    -ffunction-sections -fdata-sections -Os
)

target_link_options(wolfcrypt_test.elf PRIVATE
    -T${CMAKE_SOURCE_DIR}/stm32u585.ld
    -Wl,--gc-sections
    -nostartfiles
    -specs=nano.specs
    -specs=nosys.specs
)

target_link_libraries(wolfcrypt_test.elf PRIVATE wolfssl m c gcc nosys)
