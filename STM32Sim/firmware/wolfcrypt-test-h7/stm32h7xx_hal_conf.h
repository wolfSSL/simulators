/* stm32h7xx_hal_conf.h - HAL configuration for STM32H753 wolfCrypt
 * build under stm32-sim.
 *
 * Originally derived from wolfssl/.github/renode-test/stm32h753/.
 * HAL_HASH is left disabled to match the conservative Renode-era
 * configuration; the simulator can model HASH but the HAL_HASH
 * register-sequence bridge needs debugging (an end-to-end MD5 round
 * via wolfssl's HAL path currently mismatches expected output). The
 * peripheral itself is KAT-validated standalone; see
 * docs/wolfssl-broader-coverage.diff for the trial config to use
 * once that bridge is fixed.
 */

#ifndef STM32H7xx_HAL_CONF_H
#define STM32H7xx_HAL_CONF_H

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------  Module Selection  ----------------------------- */
#define HAL_MODULE_ENABLED
#define HAL_CORTEX_MODULE_ENABLED
#define HAL_RCC_MODULE_ENABLED
#define HAL_GPIO_MODULE_ENABLED
#define HAL_RNG_MODULE_ENABLED
#define HAL_CRYP_MODULE_ENABLED
#define HAL_HASH_MODULE_ENABLED
#define HAL_DMA_MODULE_ENABLED
#define HAL_FLASH_MODULE_ENABLED
#define HAL_PWR_MODULE_ENABLED
#define HAL_EXTI_MODULE_ENABLED

/* -------------------------  Oscillator Values  ---------------------------- */
#if !defined(HSE_VALUE)
#define HSE_VALUE    25000000UL
#endif

#if !defined(HSE_STARTUP_TIMEOUT)
#define HSE_STARTUP_TIMEOUT  100UL
#endif

#if !defined(CSI_VALUE)
#define CSI_VALUE    4000000UL
#endif

#if !defined(HSI_VALUE)
#define HSI_VALUE    64000000UL
#endif

#if !defined(HSI48_VALUE)
#define HSI48_VALUE  48000000UL
#endif

#if !defined(LSE_VALUE)
#define LSE_VALUE    32768UL
#endif

#if !defined(LSE_STARTUP_TIMEOUT)
#define LSE_STARTUP_TIMEOUT  5000UL
#endif

#if !defined(LSI_VALUE)
#define LSI_VALUE    32000UL
#endif

#if !defined(EXTERNAL_CLOCK_VALUE)
#define EXTERNAL_CLOCK_VALUE    12288000UL
#endif

#if !defined(VDD_VALUE)
#define VDD_VALUE    3300UL
#endif

#if !defined(TICK_INT_PRIORITY)
#define TICK_INT_PRIORITY    0x0FUL
#endif

#define USE_RTOS                     0U
#define PREFETCH_ENABLE              0U
#define USE_SPI_CRC                  0U

#define USE_HAL_ADC_REGISTER_CALLBACKS         0U
#define USE_HAL_CEC_REGISTER_CALLBACKS         0U
#define USE_HAL_COMP_REGISTER_CALLBACKS        0U
#define USE_HAL_CRYP_REGISTER_CALLBACKS        0U
#define USE_HAL_DAC_REGISTER_CALLBACKS         0U
#define USE_HAL_DCMI_REGISTER_CALLBACKS        0U
#define USE_HAL_DFSDM_REGISTER_CALLBACKS       0U
#define USE_HAL_DSI_REGISTER_CALLBACKS         0U
#define USE_HAL_DMA2D_REGISTER_CALLBACKS       0U
#define USE_HAL_ETH_REGISTER_CALLBACKS         0U
#define USE_HAL_FDCAN_REGISTER_CALLBACKS       0U
#define USE_HAL_NAND_REGISTER_CALLBACKS        0U
#define USE_HAL_NOR_REGISTER_CALLBACKS         0U
#define USE_HAL_HASH_REGISTER_CALLBACKS        0U
#define USE_HAL_HCD_REGISTER_CALLBACKS         0U
#define USE_HAL_HRTIM_REGISTER_CALLBACKS       0U
#define USE_HAL_I2C_REGISTER_CALLBACKS         0U
#define USE_HAL_I2S_REGISTER_CALLBACKS         0U
#define USE_HAL_JPEG_REGISTER_CALLBACKS        0U
#define USE_HAL_LPTIM_REGISTER_CALLBACKS       0U
#define USE_HAL_LTDC_REGISTER_CALLBACKS        0U
#define USE_HAL_MDIOS_REGISTER_CALLBACKS       0U
#define USE_HAL_MMC_REGISTER_CALLBACKS         0U
#define USE_HAL_OPAMP_REGISTER_CALLBACKS       0U
#define USE_HAL_PCD_REGISTER_CALLBACKS         0U
#define USE_HAL_QSPI_REGISTER_CALLBACKS        0U
#define USE_HAL_OSPI_REGISTER_CALLBACKS        0U
#define USE_HAL_RAMECC_REGISTER_CALLBACKS      0U
#define USE_HAL_RNG_REGISTER_CALLBACKS         0U
#define USE_HAL_RTC_REGISTER_CALLBACKS         0U
#define USE_HAL_SAI_REGISTER_CALLBACKS         0U
#define USE_HAL_SD_REGISTER_CALLBACKS          0U
#define USE_HAL_SDRAM_REGISTER_CALLBACKS       0U
#define USE_HAL_SRAM_REGISTER_CALLBACKS        0U
#define USE_HAL_SPDIFRX_REGISTER_CALLBACKS     0U
#define USE_HAL_SMBUS_REGISTER_CALLBACKS       0U
#define USE_HAL_SPI_REGISTER_CALLBACKS         0U
#define USE_HAL_SWPMI_REGISTER_CALLBACKS       0U
#define USE_HAL_TIM_REGISTER_CALLBACKS         0U
#define USE_HAL_UART_REGISTER_CALLBACKS        0U
#define USE_HAL_USART_REGISTER_CALLBACKS       0U
#define USE_HAL_IRDA_REGISTER_CALLBACKS        0U
#define USE_HAL_SMARTCARD_REGISTER_CALLBACKS   0U
#define USE_HAL_WWDG_REGISTER_CALLBACKS        0U

/* ----------------------- Module HAL Headers  ------------------------------ */
#ifdef HAL_RCC_MODULE_ENABLED
#include "stm32h7xx_hal_rcc.h"
#endif

#ifdef HAL_GPIO_MODULE_ENABLED
#include "stm32h7xx_hal_gpio.h"
#endif

#ifdef HAL_DMA_MODULE_ENABLED
#include "stm32h7xx_hal_dma.h"
#endif

#ifdef HAL_CORTEX_MODULE_ENABLED
#include "stm32h7xx_hal_cortex.h"
#endif

#ifdef HAL_FLASH_MODULE_ENABLED
#include "stm32h7xx_hal_flash.h"
#endif

#ifdef HAL_PWR_MODULE_ENABLED
#include "stm32h7xx_hal_pwr.h"
#endif

#ifdef HAL_RNG_MODULE_ENABLED
#include "stm32h7xx_hal_rng.h"
#endif

#ifdef HAL_CRYP_MODULE_ENABLED
#include "stm32h7xx_hal_cryp.h"
#endif

#ifdef HAL_HASH_MODULE_ENABLED
#include "stm32h7xx_hal_hash.h"
#endif

#ifdef HAL_EXTI_MODULE_ENABLED
#include "stm32h7xx_hal_exti.h"
#endif

#ifdef USE_FULL_ASSERT
#define assert_param(expr) ((expr) ? (void)0U : assert_failed((uint8_t *)__FILE__, __LINE__))
void assert_failed(uint8_t *file, uint32_t line);
#else
#define assert_param(expr) ((void)0U)
#endif

#ifdef __cplusplus
}
#endif

#endif /* STM32H7xx_HAL_CONF_H */
