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
