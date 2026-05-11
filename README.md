# wolfSSL Simulators

These are simulators for silicon so that wolfSSL can easily regression test for
issues with integrations.

## SE050Sim

The [SE050Sim](SE050Sim/) is a simulators for the SE050 which covers basic ECC
and RSA functionality.

## ATECC608Sim

The [ATECC608Sim](ATECC608Sim/) is a simulator for the Microchip ATECC608A
that covers the wolfSSL-required ATCA command subset: P-256 ECDSA, ECDH,
SHA-256, RNG, and Config/OTP/Data zone state. It plugs into cryptoauthlib
via a custom TCP HAL.

## STSAFEA120Sim

The [STSAFEA120Sim](STSAFEA120Sim/) is a simulator for the STMicroelectronics
STSAFE-A120 that covers the wolfSSL-required STSAFE-A command subset: P-256
ECDSA, ECDH, RNG, and a slot/zone store with a default device certificate.
It plugs into ST's open-source STSELib middleware via a custom Linux PAL
that pipes the I2C transport over TCP.

## TROPIC01Sim

The [TROPIC01Sim](TROPIC01Sim/) is a simulator for the Tropic Square TROPIC01
secure element. It speaks libtropic's "TROPIC01 Model" wire protocol over
TCP and performs the full Noise_KK1_25519_AESGCM_SHA256 secure-channel
handshake, then answers the L3 commands the wolfSSL TROPIC01 port exercises:
RNG, ECC keygen/read for P-256 + Ed25519, R-memory read/write, and the
pairing-key surface. The simulator is consumed unmodified by libtropic via
its `hal/posix/tcp/` HAL.

## STM32Sim

The [STM32Sim](STM32Sim/) is a Unicorn-Engine-based simulator for STM32
microcontrollers focused on the on-chip cryptographic accelerators
(CRYP/AES, HASH, RNG, PKA) that wolfSSL uses. It is intended to replace
the Renode-based CI flow for wolfSSL on STM32 targets and to close the
gaps Renode has in hardware-crypto modelling (HASH peripheral, full AES
mode set, PKA).

## License

All simulators in this repository are licensed under the GNU General Public
License v3.0 or later. See [LICENSE](LICENSE) for the full text.

