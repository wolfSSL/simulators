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
