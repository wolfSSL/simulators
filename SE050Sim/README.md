# SE050 Simulator

A software simulator for the NXP SE050 secure element, implementing the full I2C / T=1 / APDU protocol stack. Designed as a drop-in replacement for real SE050 hardware in development and testing environments.

## Features

### Cryptographic Operations
- **ECC**: Key generation, ECDSA sign/verify for NIST P-224, P-256, P-384 curves
- **EdDSA**: Ed25519 key generation, sign/verify
- **X25519**: Curve25519 key generation, ECDH shared secret
- **RSA**: 1024–4096 bit key generation, PKCS1v1.5 and PSS sign/verify, PKCS1v1.5 and OAEP encrypt/decrypt
- **AES**: Key write/generate, AES-CBC encrypt/decrypt (oneshot and multi-step)
- **ECDH**: Diffie-Hellman shared secret for P-224, P-256, P-384, Curve25519
- **Digest**: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 (oneshot and multi-step)
- **RNG**: Hardware-quality random number generation

### Object Management
- Persistent object store (JSON file on disk)
- WriteBinary, ReadObject, CheckObjectExists, DeleteSecureObject
- ReadIDList, ReadType, ReadSize
- UserID, Counter objects
- Crypto object lifecycle (Create, List, Delete)
- EC public key import and verification
- ReadECCurveList with full NIST curve inventory

### Protocol Stack
- **T=1 protocol** (ISO 7816-3): Frame parsing/building, CRC-16 X25, S-frames (InterfaceSoftReset, GetATR, Resync), I-frame sequencing, multi-frame chaining
- **APDU** (ISO 7816-4): Full command/response parsing with TLV encoding
- **Transport**: In-process mock I2C (for Rust driver tests) and TCP server (for C/SDK integration)

## Quick Start

### Run the Rust integration tests

```bash
docker build -t se050-sim .
docker run se050-sim
```

This builds the simulator and runs 23 tests (9 unit + 14 integration) against the [nxp-se050](https://github.com/imrank03/nxp-se050) Rust driver.

### Run the SDK test suite (OpenSSL cross-verification)

```bash
docker build -f Dockerfile.sdk-test -t se050-sim-sdk-test .
docker run se050-sim-sdk-test
```

This tests the simulator through the NXP Plug&Trust SDK's SSS API, with independent verification using OpenSSL. **All 18 tests pass.** See [SDK Test Suite](#sdk-test-suite) for details.

### Run the wolfCrypt test suite

```bash
docker build -f Dockerfile.wolfcrypt -t se050-sim-wolfcrypt .
docker run se050-sim-wolfcrypt
```

This builds a full integration with wolfSSL and the NXP Plug&Trust SDK, then runs the wolfCrypt cryptographic test suite against the simulator. **All 46 tests pass.** See [wolfCrypt Integration](#wolfcrypt-integration) for details.

## Architecture

```
┌─────────────────────────────────────┐
│  Application / Test Suite           │
│  (Rust driver, SDK+OpenSSL, or     │
│   C SDK + wolfSSL)                  │
└────────────┬────────────────────────┘
             │  I2C or TCP
┌────────────▼────────────────────────┐
│  T=1 Responder (t1.rs)             │
│  Frame parsing, CRC-16, S-frames   │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│  APDU Dispatch (dispatch.rs)        │
│  Routes (CLA, INS, P1, P2)         │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│  Handlers                           │
│  session, management, ec, rsa,      │
│  aes, digest, object_mgmt,         │
│  crypto_obj                         │
└────────────┬────────────────────────┘
             │
┌────────────▼────────────────────────┐
│  Object Store (JSON persistence)    │
└─────────────────────────────────────┘
```

### Two transport modes

1. **In-process mock I2C** (`Se050Simulator` struct) — implements `embedded_hal::blocking::i2c::{Read, Write}` for direct use with the Rust `nxp-se050` driver
2. **TCP server** (`tcp_server` binary) — multi-threaded, listens on port 8050, serves T=1 frames over TCP for use with the NXP Plug&Trust C SDK

## Project Structure

```
SE050Sim/
├── Dockerfile                 Rust driver integration tests
├── Dockerfile.sdk-test        SDK test suite (OpenSSL verification)
├── Dockerfile.wolfcrypt       wolfCrypt test suite integration
├── se050-sim/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs
│   │   ├── transport.rs       Mock I2C (embedded_hal traits)
│   │   ├── t1.rs              T=1 protocol responder
│   │   ├── apdu.rs            APDU parser + response builder
│   │   ├── tlv.rs             TLV encoder/decoder
│   │   ├── dispatch.rs        Command routing
│   │   ├── bin/
│   │   │   └── tcp_server.rs  TCP server binary
│   │   ├── handlers/
│   │   │   ├── session.rs     SELECT applet
│   │   │   ├── management.rs  GetVersion, GetRandom, etc.
│   │   │   ├── object_mgmt.rs Object CRUD operations
│   │   │   ├── crypto_obj.rs  Crypto object lifecycle
│   │   │   ├── ec.rs          ECC operations (P-224/256/384, Ed25519, X25519)
│   │   │   ├── rsa.rs         RSA operations
│   │   │   ├── aes.rs         AES operations
│   │   │   └── digest.rs      Hash operations
│   │   └── object_store/
│   │       ├── mod.rs          HashMap + JSON persistence
│   │       └── types.rs        SecureObject enum
│   └── tests/
│       └── integration.rs     Tests using the nxp-se050 driver
├── sdk-test/
│   ├── test_se050.c            SDK test suite (SSS API + OpenSSL)
│   ├── test_helpers.h          Test macros (ASSERT_OK, ASSERT_EQ, etc.)
│   └── run_test.sh             Test runner script
└── wolfcrypt-test/
    ├── i2c_a7.c               Custom PAL: TCP socket transport
    ├── se05x_reset.c           No-op reset stub for Docker
    ├── main.c                  wolfCrypt test wrapper with SE050 init
    ├── CMakeLists.txt          SDK library build
    ├── patch_ftr.py            Enable EC curve features in SDK
    └── run_test.sh             Test runner script
```

## SDK Test Suite

The simulator has an independent test suite that uses the NXP Plug&Trust SDK's SSS API with OpenSSL for cross-verification. Each test performs a cryptographic operation via the SE050 simulator and then independently verifies the result using OpenSSL.

### Test results

All 30 tests pass:

| Test | Description |
|------|-------------|
| RNG | Get random bytes, verify non-zero and unique |
| SHA-1/224/256/384/512 | Hash via SE050, compare with OpenSSL `EVP_Digest` |
| ECC-P256-keygen-sign-verify | ECDSA sign via SE050, verify with OpenSSL |
| ECC-P384-keygen-sign-verify | ECDSA sign via SE050, verify with OpenSSL |
| ECDH-P256 | Two SE050 key pairs, verify shared secrets match |
| AES-128-CBC | Encrypt via SE050, decrypt with OpenSSL, compare |
| AES-256-CBC | Encrypt via SE050, decrypt with OpenSSL, compare |
| RSA-2048-sign-verify | RSA PKCS1v1.5-SHA256 sign via SE050, verify with OpenSSL |
| RSA-2048-encrypt-decrypt | OpenSSL encrypts (PKCS1v1.5), SE050 decrypts, compare |
| RSA-2048-sign-SHA384 | RSA PKCS1v1.5-SHA384 sign via SE050, verify with OpenSSL |
| RSA-2048-sign-SHA512 | RSA PKCS1v1.5-SHA512 sign via SE050, verify with OpenSSL |
| RSA-3072-sign-verify | RSA-3072 sign via SE050, verify with OpenSSL |
| RSA-4096-sign-verify | RSA-4096 sign via SE050, verify with OpenSSL |
| RSA-2048-PSS-SHA256 | RSA-PSS sign via SE050, verify with OpenSSL |
| RSA-2048-OAEP-SHA1 | OpenSSL encrypts (OAEP-SHA1), SE050 decrypts, compare |
| RSA-2048-SE050-self-verify | Sign via SE050, verify via SE050, assert bit-flipped sig rejected |
| RSA-2048-import-sign-verify | OpenSSL generates key, import PKCS#1 `RSAPrivateKey` DER (~1190 B) to SE050, sign, verify with OpenSSL (exercises per-component `WriteRSAKey` path) |
| RSA-2048-import-sign-verify-pkcs8 | Same but imports PKCS#8 `PrivateKeyInfo` DER (~1218 B) — confirms the host parser accepts both wrappings |
| RSA-2048-sign-NO_HASH | Sign raw SHA-256 digest via `PKCS1_V1_5_NO_HASH` (SDK pads host-side then does `RSADecrypt(NO_PAD)`); verify by raw-decrypting sig and checking PKCS#1 block structure |
| RSA-2048-import-sign-NO_HASH | End-to-end wolfCrypt-equivalent flow: OpenSSL-generated PKCS#1 key → `sss_key_store_set_key` → `PKCS1_V1_5_NO_HASH` sign → validate padded block |
| RSA-2048-import-client-key-NO_HASH | Same flow, but imports the exact `wolfssl/certs/client-key.der` byte sequence (the 1192 B DER that wolfCrypt's `rsa_test` uses). Rules out byte-level DER incompatibility as a cause for wolfCrypt-SE050 import failures |
| X25519-ECDH | Two SE050 key pairs, verify shared secrets match |
| Ed25519-sign-verify | Sign via SE050, verify with both SE050 and OpenSSL |
| Ed25519-test-vector | Import RFC 8032 key, sign, compare to known signature |
| Object-write-read | Write binary, read back, compare |
| Object-delete | Write, verify exists, delete, verify gone |

## wolfCrypt Integration

The simulator can run the [wolfSSL](https://www.wolfssl.com/) wolfCrypt test suite, validating SE050 crypto operations through the full NXP Plug&Trust middleware stack.

### How it works

```
wolfCrypt test → SSS API → Se05x APDU layer → smCom → T1oI2C → PAL I2C
                                                                    │
                                                            TCP socket
                                                                    │
                                                          se050-sim-server
```

A custom `i2c_a7.c` replaces the NXP SDK's I2C platform layer with TCP socket calls. The simulator's TCP server (`tcp_server`) accepts connections on port 8050 and processes T=1 frames identically to how it handles the Rust driver.

### HostCrypto backend

The NXP SDK requires a host-side crypto provider for operations like the PKCS#1 v1.5 padding inside `sss_se05x_asymmetric_sign_digest`. We build the SDK with `PTMW_HostCrypto=WOLFSSL` via wolfSSL's middleware patch at [wolfSSL/osp/nxp-se05x-middleware](https://github.com/wolfSSL/osp/tree/master/nxp-se05x-middleware). This mirrors a real wolfSSL+SE050 deployment and avoids the header clashes that `HostCrypto=OPENSSL` causes when coexisting with wolfSSL's own OpenSSL compatibility layer.

The SDK is pinned to NXP tag [`v04.07.01`](https://github.com/NXP/plug-and-trust/releases/tag/v04.07.01) to match the patch's target version.

Build order is a three-pass bootstrap (required because wolfSSL-with-SE050 links against the SDK and the SDK links against wolfSSL):

1. **Pass-A**: wolfSSL without `--with-se050` (provides `libwolfssl` for the SDK to link against).
2. **SDK**: patched, `HostCrypto=WOLFSSL`, links against Pass-A wolfSSL.
3. **Pass-B**: wolfSSL rebuilt with `--with-se050`, links against the patched SDK; overwrites the Pass-A install.
4. **Test**: `gcc main.o test.o` + final libs.

### Test results

All wolfCrypt subsystems pass, including RSA and Ed25519:

| Category | Tests | Status |
|----------|-------|--------|
| macro, error, MEMORY, base64, asn | 5 | Pass |
| SHA (1/224/256/384/512), SHA-3 | 6 | Pass |
| RANDOM, SHAKE128/256, Hash | 4 | Pass |
| HMAC (SHA/224/256/384/512/SHA3) | 6 | Pass |
| HMAC-KDF, PRF, TLSv1.3 KDF | 3 | Pass |
| GMAC, Chacha, POLY1305, ChaPoly | 4 | Pass |
| AES, AES192, AES256, AES-CBC, AES-GCM | 5 | Pass |
| RSA | 1 | Pass |
| DH, PWDBASED | 2 | Pass |
| ECC, CURVE25519, ED25519 | 3 | Pass |
| MLKEM, CMAC | 2 | Pass |
| logging, time, mutex, memcb, crypto callback | 5 | Pass |

### Building manually

If you want to build outside Docker:

1. **Build the simulator TCP server:**
   ```bash
   cd se050-sim
   cargo build --release --bin tcp_server
   ```

2. **Clone and patch the NXP Plug&Trust SDK (v04.07.01 + wolfSSL HostCrypto patch):**
   ```bash
   git clone --branch v04.07.01 --depth 1 https://github.com/NXP/plug-and-trust.git simw-top
   # Apply wolfSSL OSP middleware patch (adds PTMW_HostCrypto=WOLFSSL)
   curl -fsSL https://raw.githubusercontent.com/wolfSSL/osp/master/nxp-se05x-middleware/simw-top-v040701.patch \
     | (cd simw-top && patch -p1 -l --forward --fuzz=3)
   # Replace PAL I2C with TCP transport
   cp wolfcrypt-test/i2c_a7.c simw-top/hostlib/hostLib/platform/linux/i2c_a7.c
   cp wolfcrypt-test/se05x_reset.c simw-top/hostlib/hostLib/platform/rsp/se05x_reset.c
   # Enable EC curves the SDK disables by default
   python3 wolfcrypt-test/patch_ftr.py simw-top/fsl_sss_ftr.h
   # Overlay our CMakeLists (builds the six static libs wolfSSL expects)
   cp wolfcrypt-test/CMakeLists.txt simw-top/CMakeLists.txt
   ```

3. **Pass-A: build wolfSSL without SE050 support** (the patched SDK links against this):
   ```bash
   git clone --depth 1 https://github.com/wolfSSL/wolfssl.git
   cd wolfssl && ./autogen.sh
   ./configure --enable-keygen --enable-cmac \
     CFLAGS="-DWOLFSSL_SE050_NO_TRNG -DSIZEOF_LONG_LONG=8"
   make -j$(nproc) && sudo make install && sudo ldconfig
   cd ..
   ```

4. **Build the patched SDK with `HostCrypto=WOLFSSL`:**
   ```bash
   cd simw-top && mkdir build && cd build
   cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-fPIC" \
     -DPTMW_Applet=SE05X_C -DPTMW_SE05X_Auth=None \
     -DPTMW_SMCOM=T1oI2C -DPTMW_HostCrypto=WOLFSSL -DPTMW_Host=LinuxLike
   cmake --build . -j$(nproc)
   cd ../..
   ```

5. **Pass-B: rebuild wolfSSL with `--with-se050`:**
   ```bash
   cd wolfssl
   make clean
   ./configure --with-se050=$PWD/../simw-top \
     --enable-keygen --enable-cmac --enable-cryptocb --enable-ecc \
     --enable-ed25519 --enable-curve25519 \
     --enable-sha224 --enable-sha384 --enable-sha512 \
     --disable-examples --enable-crypttests \
     CFLAGS="-DWOLFSSL_SE050_INIT -DWOLFSSL_SE050_NO_TRNG -DSIZEOF_LONG_LONG=8 \
             -DECC_USER_CURVES -DHAVE_ECC224 -DHAVE_ECC256 -DHAVE_ECC384" \
     LDFLAGS="-L$PWD/../simw-top/build"
   make -j$(nproc) && sudo make install && sudo ldconfig
   ```

6. **Run:**
   ```bash
   # Terminal 1: start the simulator
   ./se050-sim/target/release/tcp_server

   # Terminal 2: run tests
   export SE050_SIM_HOST=127.0.0.1
   export SE050_SIM_PORT=8050
   ./wolfcrypt_se050_test
   ```

## NXP Driver Fork

The upstream [imrank03/nxp-se050](https://github.com/imrank03/nxp-se050) Rust driver has several bugs that blocked integration testing. Fixes live on the [`sim-compat`](https://github.com/LinuxJedi/nxp-se050/tree/sim-compat) branch of our fork, which the Dockerfiles clone directly:

| Bug | Fix |
|-----|-----|
| `embedded-hal = "*"` resolves to 1.0 (needs 0.2) | Pin to `"0.2"` |
| `CApduByteIterator` panics on empty body deque | Skip body area when empty |
| `CApduByteIterator` panics on empty TLV data | Don't push empty data slices |
| `SimpleTlv` header capacity (3) too small for extended TLV | Increase to 4 |
| Response buffers too small (16 bytes) for hash/RSA | Increase to 260 bytes |

## Known Issues

- **SCP03**: Secure Channel Protocol 03 is not implemented. The simulator operates in plain (unauthenticated) mode only.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
