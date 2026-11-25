#!/bin/sh
# Program an STM32F4DISCOVERY with a TARGET=board build of this firmware,
# let it run, then halt it and print the test's diagnostic variables, the
# PC (with the function it is in) and the RNG / RCC registers.
#
#   ./board-run.sh rng-fault-stdperiph-board.elf [seconds]
set -eu

ELF=${1:?usage: board-run.sh <elf> [seconds]}
SECS=${2:-8}

sym() {
    arm-none-eabi-nm "$ELF" | awk -v s="$1" '$3 == s { print "0x" $1 }'
}

CMDS="program $ELF verify; reset run; sleep $((SECS * 1000)); halt;"
for v in g_stage g_sanity_ret g_fault_ret g_tick g_fault_tick \
         g_fault_fired_tick g_rng_sr_after_fault g_return_tick g_hung \
         g_hw_mutex_depth g_hw_mutex_errors \
         test_complete test_result; do
    a=$(sym "$v")
    CMDS="$CMDS echo \"$v [read_memory $a 32 1]\";"
done
CMDS="$CMDS echo \"RNG_CR_SR [read_memory 0x50060800 32 2]\";"
CMDS="$CMDS echo \"RCC_CR [read_memory 0x40023800 32 1]\";"
CMDS="$CMDS echo \"PC [lindex [reg pc] 2]\"; shutdown"

OUT=$(openocd -f interface/stlink.cfg -f target/stm32f4x.cfg -c "$CMDS" 2>&1)
echo "$OUT" | grep -v -E '^(Info|Open On-Chip|Licensed|For bug|\s+http|Warn : Unable to match)' || true

PC=$(echo "$OUT" | awk '$1 == "PC" { print $2 }')
if [ -n "$PC" ]; then
    echo "PC $PC is in: $(arm-none-eabi-addr2line -f -e "$ELF" "$PC" | head -1)"
fi
