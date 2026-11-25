# STM32F4 RNG fault test for wolfSSL's wc_GenerateSeed().
#
#   make [TARGET=sim|board] [ARM=stdperiph|nolib]
#
# TARGET=sim   (default) STM32F417 under stm32-sim; the RNG fault comes from
#              the simulator's --rng-fault option.
# TARGET=board STM32F407 (STM32F4DISCOVERY) silicon; the firmware stops the
#              RNG kernel clock itself mid-fill. `make TARGET=board flash`
#              programs it with OpenOCD.
# ARM=stdperiph (default) selects the Standard Peripheral Library arm of
#              wc_GenerateSeed(); ARM=nolib selects WOLFSSL_STM32_RNG_NOLIB.

WOLFSSL_ROOT ?= /opt/wolfssl
CMSIS_CORE   ?= /opt/CMSIS_5/CMSIS/Core/Include
CMSIS_DEVICE ?= /opt/cmsis-device-f4/Include
TARGET       ?= sim
ARM          ?= stdperiph

CC = arm-none-eabi-gcc

ifeq ($(TARGET),board)
DEVICE ?= STM32F407xx
DEFS   += -DRNG_FAULT_BOARD
else ifeq ($(TARGET),sim)
DEVICE ?= STM32F417xx
else
$(error TARGET must be sim or board)
endif

ifeq ($(ARM),nolib)
DEFS += -DRNG_ARM_NOLIB
else ifneq ($(ARM),stdperiph)
$(error ARM must be stdperiph or nolib)
endif

# TARGET=board only: GLITCH_MS=<n> restores the RNG clock n ms after
# removing it (a transient clock glitch rather than a dead clock).
ifneq ($(GLITCH_MS),)
DEFS   += -DRNG_FAULT_GLITCH_MS=$(GLITCH_MS)
SUFFIX  = -glitch$(GLITCH_MS)
endif

BUILD = build/$(ARM)-$(TARGET)$(SUFFIX)
ELF   = rng-fault-$(ARM)-$(TARGET)$(SUFFIX).elf

WOLFCRYPT_SRCS = \
	$(WOLFSSL_ROOT)/wolfcrypt/src/random.c \
	$(WOLFSSL_ROOT)/wolfcrypt/src/sha256.c \
	$(WOLFSSL_ROOT)/wolfcrypt/src/memory.c \
	$(WOLFSSL_ROOT)/wolfcrypt/src/wc_port.c \
	$(WOLFSSL_ROOT)/wolfcrypt/src/logging.c \
	$(WOLFSSL_ROOT)/wolfcrypt/src/error.c

LOCAL_SRCS = main.c startup_stm32f4.c stdperiph_shim.c
HEADERS    = user_settings.h stdperiph/stm32f4xx.h stdperiph/stdperiph_shim.h

OBJS = $(addprefix $(BUILD)/,$(LOCAL_SRCS:.c=.o)) \
       $(addprefix $(BUILD)/wolfcrypt/,$(notdir $(WOLFCRYPT_SRCS:.c=.o)))

ARCH     = -mcpu=cortex-m4 -mthumb -mfloat-abi=soft
# stdperiph/ comes before the CMSIS device directory so its StdPeriph-style
# stm32f4xx.h wrapper shadows the CMSIS one (and #include_next's it).
CPPFLAGS = -DWOLFSSL_USER_SETTINGS -D$(DEVICE) $(DEFS) \
           -I. -Istdperiph -I$(CMSIS_DEVICE) -I$(CMSIS_CORE) -I$(WOLFSSL_ROOT)
CFLAGS   = $(ARCH) -Os -g -ffunction-sections -fdata-sections -Wall
LDFLAGS  = $(ARCH) -Tstm32f4.ld -nostartfiles -Wl,--gc-sections \
           -specs=nano.specs -specs=nosys.specs -Wl,-Map=$(BUILD)/rng-fault.map

all: $(ELF)

$(ELF): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(BUILD)/%.o: %.c $(HEADERS)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILD)/wolfcrypt/%.o: $(WOLFSSL_ROOT)/wolfcrypt/src/%.c $(HEADERS)
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

flash: $(ELF)
	openocd -f interface/stlink.cfg -f target/stm32f4x.cfg \
		-c "program $(ELF) verify reset exit"

clean:
	rm -rf build rng-fault-*.elf

.PHONY: all flash clean
