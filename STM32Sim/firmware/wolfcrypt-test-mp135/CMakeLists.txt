cmake_minimum_required(VERSION 3.18)
project(wolfcrypt_stm32mp135 LANGUAGES C ASM)

set(WOLFSSL_ROOT "/opt/wolfssl-build-tree" CACHE PATH "wolfSSL source")
set(STM32CUBE_MP13_ROOT "/opt/STM32CubeMP13" CACHE PATH "STM32CubeMP13 SDK")

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
enable_language(ASM)

include_directories(BEFORE
    ${CMAKE_SOURCE_DIR}
    ${STM32CUBE_MP13_ROOT}/Drivers/CMSIS/Core_A/Include
    ${STM32CUBE_MP13_ROOT}/Drivers/CMSIS/Device/ST/STM32MP13xx/Include
    ${STM32CUBE_MP13_ROOT}/Drivers/STM32MP13xx_HAL_Driver/Inc/Legacy
    ${STM32CUBE_MP13_ROOT}/Drivers/STM32MP13xx_HAL_Driver/Inc
)

set(HAL_SRC_DIR ${STM32CUBE_MP13_ROOT}/Drivers/STM32MP13xx_HAL_Driver/Src)

if(EXISTS ${HAL_SRC_DIR})
    # Note: the MP13 HAL has no stm32mp13xx_hal_cortex.c - the Cortex
    # helpers (NVIC, MPU) only exist on the M-class HALs. On A-class
    # the equivalent functions live in CMSIS Core_A (irq_ctrl.h, GIC).
    # wolfSSL's STM32 port does not call HAL_NVIC_* on this target.
    set(HAL_SOURCES
        ${HAL_SRC_DIR}/stm32mp13xx_hal.c
        ${HAL_SRC_DIR}/stm32mp13xx_hal_rcc.c
        ${HAL_SRC_DIR}/stm32mp13xx_hal_rcc_ex.c
        ${HAL_SRC_DIR}/stm32mp13xx_hal_dma.c
        ${HAL_SRC_DIR}/stm32mp13xx_hal_dma_ex.c
        ${HAL_SRC_DIR}/stm32mp13xx_hal_mdma.c
        ${HAL_SRC_DIR}/stm32mp13xx_hal_rng.c
        ${HAL_SRC_DIR}/stm32mp13xx_hal_rng_ex.c
        ${HAL_SRC_DIR}/stm32mp13xx_hal_cryp.c
        ${HAL_SRC_DIR}/stm32mp13xx_hal_cryp_ex.c
        ${HAL_SRC_DIR}/stm32mp13xx_hal_hash.c
        ${HAL_SRC_DIR}/stm32mp13xx_hal_hash_ex.c
        ${HAL_SRC_DIR}/stm32mp13xx_hal_pka.c
        ${HAL_SRC_DIR}/stm32mp13xx_hal_pwr.c
        ${HAL_SRC_DIR}/stm32mp13xx_hal_pwr_ex.c
        ${HAL_SRC_DIR}/stm32mp13xx_hal_gpio.c
    )
else()
    message(WARNING "MP13 HAL source directory not found: ${HAL_SRC_DIR}")
    set(HAL_SOURCES "")
endif()

set(WOLFSSL_USER_SETTINGS ON CACHE BOOL "Use user_settings.h")
set(WOLFSSL_CRYPT_TESTS OFF CACHE BOOL "")
set(WOLFSSL_EXAMPLES OFF CACHE BOOL "")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "")

add_subdirectory(${WOLFSSL_ROOT} ${CMAKE_BINARY_DIR}/wolfssl-build EXCLUDE_FROM_ALL)
target_include_directories(wolfssl PRIVATE
    ${STM32CUBE_MP13_ROOT}/Drivers/CMSIS/Core_A/Include
    ${STM32CUBE_MP13_ROOT}/Drivers/CMSIS/Device/ST/STM32MP13xx/Include
    ${STM32CUBE_MP13_ROOT}/Drivers/STM32MP13xx_HAL_Driver/Inc/Legacy
    ${STM32CUBE_MP13_ROOT}/Drivers/STM32MP13xx_HAL_Driver/Inc
    ${CMAKE_SOURCE_DIR}
)
target_compile_options(wolfssl PRIVATE -Wno-cpp)

set(WOLFSSL_STM32_PORT_SRC ${WOLFSSL_ROOT}/wolfcrypt/src/port/st/stm32.c)

add_executable(wolfcrypt_test.elf
    startup.S
    mmu.c
    main.c
    ${WOLFSSL_ROOT}/wolfcrypt/test/test.c
    ${HAL_SOURCES}
    ${WOLFSSL_STM32_PORT_SRC}
)

target_include_directories(wolfcrypt_test.elf PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${WOLFSSL_ROOT}
    ${STM32CUBE_MP13_ROOT}/Drivers/STM32MP13xx_HAL_Driver/Inc
    ${STM32CUBE_MP13_ROOT}/Drivers/STM32MP13xx_HAL_Driver/Inc/Legacy
)

target_compile_definitions(wolfcrypt_test.elf PRIVATE
    WOLFSSL_USER_SETTINGS
    STM32MP135Fxx
    CORE_CA7
    USE_HAL_DRIVER
    USE_HAL_CONF
)

# HAL needs CORE_CA7 (selects A-class CMSIS) and the same -mcpu /
# -mfpu we use everywhere else.
set_source_files_properties(${HAL_SOURCES} PROPERTIES
    COMPILE_FLAGS "-mcpu=cortex-a7 -marm -mfpu=neon-vfpv4 -mfloat-abi=hard -ffunction-sections -fdata-sections -Os -include stdint.h -w -DCORE_CA7"
)

target_compile_options(wolfcrypt_test.elf PRIVATE
    -mcpu=cortex-a7 -marm -mfpu=neon-vfpv4 -mfloat-abi=hard
    -ffunction-sections -fdata-sections -Os
)

target_link_options(wolfcrypt_test.elf PRIVATE
    -T${CMAKE_SOURCE_DIR}/stm32mp135.ld
    -Wl,--gc-sections
    -nostartfiles
    -specs=nano.specs
    -specs=nosys.specs
)

target_link_libraries(wolfcrypt_test.elf PRIVATE wolfssl m c gcc nosys)
