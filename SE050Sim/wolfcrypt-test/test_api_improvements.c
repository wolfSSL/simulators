/* Focused end-to-end smoke test for the wolfSSL SE05x provisioning APIs. */
#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#define USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_4096
#include <wolfssl/certs_test.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/port/nxp/se050_port.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/wc_port.h>

#define TEST_OBJECT_ID 90U
#define TEST_ECC_ID    91U
#define TEST_RSA_ID    92U
#define TEST_LARGE_ID  93U
#define TEST_RSA4K_ID  94U
#define TEST_ECC_GEN_ID 95U
#define TEST_RSA_GEN_ID 96U
#define TEST_LARGE_SZ  900U

static const byte eccPublicDer[] = {
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE,
    0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
    0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x55, 0xBF, 0xF4,
    0x0F, 0x44, 0x50, 0x9A, 0x3D, 0xCE, 0x9B, 0xB7, 0xF0, 0xC5,
    0x4D, 0xF5, 0x70, 0x7B, 0xD4, 0xEC, 0x24, 0x8E, 0x19, 0x80,
    0xEC, 0x5A, 0x4C, 0xA2, 0x24, 0x03, 0x62, 0x2C, 0x9B, 0xDA,
    0xEF, 0xA2, 0x35, 0x12, 0x43, 0x84, 0x76, 0x16, 0xC6, 0x56,
    0x95, 0x06, 0xCC, 0x01, 0xA9, 0xBD, 0xF6, 0x75, 0x1A, 0x42,
    0xF7, 0xBD, 0xA9, 0xB2, 0x36, 0x22, 0x5F, 0xC7, 0x5D, 0x7F,
    0xB4
};

static const wc_se050_scp03_keys currentKeys = {
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
    {0x67, 0x02, 0xDA, 0xC3, 0x09, 0x42, 0xB2, 0xC8,
     0x5E, 0x7F, 0x47, 0xB4, 0x2C, 0xED, 0x4E, 0x7F}
};

static const wc_se050_scp03_keys explicitKeys = {
    {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
     0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F},
    {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
     0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F},
    {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
     0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F}
};

static int fail(const char* operation, int ret)
{
    fprintf(stderr, "FAIL: %s returned %d\n", operation, ret);
    return 1;
}

#ifdef WOLFSSL_SE050_ONLY_KEY_ID
static int append_bytes(byte* out, word32 outSz, word32* offset,
    const byte* in, word32 inSz)
{
    if ((out == NULL) || (offset == NULL) || (in == NULL) ||
            (*offset > outSz) || (inSz > (outSz - *offset))) {
        return -1;
    }
    memcpy(out + *offset, in, inSz);
    *offset += inSz;
    return 0;
}

static int append_tlv82(byte* out, word32 outSz, word32* offset, byte tag,
    const byte* value, word32 valueSz)
{
    byte header[4];

    header[0] = tag;
    header[1] = 0x82;
    header[2] = (byte)(valueSz >> 8);
    header[3] = (byte)valueSz;
    if (append_bytes(out, outSz, offset, header, sizeof(header)) != 0) {
        return -1;
    }
    return append_bytes(out, outSz, offset, value, valueSz);
}

static int append_short_tlv(byte* out, word32 outSz, word32* offset,
    byte tag, const byte* value, word32 valueSz)
{
    byte header[2];

    if (valueSz > 0x7FU) {
        return -1;
    }
    header[0] = tag;
    header[1] = (byte)valueSz;
    if (append_bytes(out, outSz, offset, header, sizeof(header)) != 0) {
        return -1;
    }
    return append_bytes(out, outSz, offset, value, valueSz);
}

static int test_raw_curve_attestation(word32 cipherType, byte curveOid)
{
    static const byte spkiPrefix[] = {
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x00,
        0x03, 0x21, 0x00
    };
    static const byte objectId[] = {0x00, 0x00, 0x00, 0x31};
    static const byte attestId[] = {0x00, 0x00, 0x00, 0x32};
    static const byte algorithm[] = {0x09};
    wc_se050_attst_result result;
    sss_se05x_attst_comp_data_t* data;
    RsaKey key;
    WC_RNG rng;
    byte component[32];
    byte commandDigest[WC_SHA256_DIGEST_SIZE];
    byte signedData[512];
    byte wrongRandom[16];
    word32 idx = 0;
    word32 cmdOffset = 7U;
    word32 signedOffset = 0U;
    word32 sigSz;
    word32 i;
    int keyInit = 0;
    int rngInit = 0;
    int valid = 0;
    int ret;

    memset(&result, 0, sizeof(result));
    result.hashAlgo = WC_HASH_TYPE_SHA256;
    result.cipherType = cipherType;
    result.raw.valid_number = 1;
    data = &result.raw.data[0];
    for (i = 0U; i < sizeof(result.freshness); i++) {
        result.freshness[i] = (byte)(0xA0U + i);
        component[i] = (byte)(i + 1U);
    }

    memcpy(result.value, spkiPrefix, sizeof(spkiPrefix));
    result.value[8] = curveOid;
    for (i = 0U; i < sizeof(component); i++) {
        result.value[sizeof(spkiPrefix) + i] =
            component[sizeof(component) - 1U - i];
    }
    result.valueSz = sizeof(spkiPrefix) + sizeof(component);

    data->cmd[0] = (byte)kSE05x_CLA;
    data->cmd[1] = (byte)kSE05x_INS_READ_With_Attestation;
    data->cmd[2] = 0;
    data->cmd[3] = 0;
    data->cmd[4] = 0;
    data->cmd[5] = 0;
    if ((append_short_tlv(data->cmd, sizeof(data->cmd), &cmdOffset,
            (byte)kSE05x_TAG_1, objectId, sizeof(objectId)) != 0) ||
            (append_short_tlv(data->cmd, sizeof(data->cmd), &cmdOffset,
            (byte)kSE05x_TAG_5, attestId, sizeof(attestId)) != 0) ||
            (append_short_tlv(data->cmd, sizeof(data->cmd), &cmdOffset,
            (byte)kSE05x_TAG_6, algorithm, sizeof(algorithm)) != 0) ||
            (append_short_tlv(data->cmd, sizeof(data->cmd), &cmdOffset,
            (byte)kSE05x_TAG_7, result.freshness,
            sizeof(result.freshness)) != 0)) {
        return fail("build synthetic attestation command", -1);
    }
    data->cmd[6] = (byte)(cmdOffset - 7U);
    data->cmdLen = cmdOffset;

    data->chipIdLen = 18U;
    data->attributeLen = 15U;
    data->objSizeLen = 2U;
    data->timeStampLen = sizeof(data->timeStamp.ts);
    for (i = 0U; i < data->chipIdLen; i++) {
        data->chipId[i] = (byte)(0x10U + i);
    }
    for (i = 0U; i < data->attributeLen; i++) {
        data->attribute[i] = (byte)(0x30U + i);
    }
    data->objSize[0] = 0;
    data->objSize[1] = sizeof(component);
    for (i = 0U; i < data->timeStampLen; i++) {
        data->timeStamp.ts[i] = (byte)(0x50U + i);
    }

    ret = wc_Hash(WC_HASH_TYPE_SHA256, data->cmd, (word32)data->cmdLen,
        commandDigest, sizeof(commandDigest));
    if ((ret != 0) ||
            (append_bytes(signedData, sizeof(signedData), &signedOffset,
            commandDigest, sizeof(commandDigest)) != 0) ||
            (append_tlv82(signedData, sizeof(signedData), &signedOffset,
            (byte)kSE05x_TAG_1, component, sizeof(component)) != 0) ||
            (append_tlv82(signedData, sizeof(signedData), &signedOffset,
            (byte)kSE05x_TAG_2, data->chipId,
            (word32)data->chipIdLen) != 0) ||
            (append_tlv82(signedData, sizeof(signedData), &signedOffset,
            (byte)kSE05x_TAG_3, data->attribute,
            (word32)data->attributeLen) != 0) ||
            (append_tlv82(signedData, sizeof(signedData), &signedOffset,
            (byte)kSE05x_TAG_4, data->objSize,
            (word32)data->objSizeLen) != 0) ||
            (append_tlv82(signedData, sizeof(signedData), &signedOffset,
            (byte)kSE05x_TAG_TIMESTAMP, data->timeStamp.ts,
            (word32)data->timeStampLen) != 0)) {
        return fail("build synthetic attestation data", ret);
    }

    ret = wc_InitRsaKey(&key, NULL);
    if (ret == 0) {
        keyInit = 1;
        ret = wc_RsaPrivateKeyDecode(client_key_der_2048, &idx, &key,
            sizeof_client_key_der_2048);
    }
    if (ret == 0) {
        ret = wc_InitRng(&rng);
        if (ret == 0) {
            rngInit = 1;
        }
    }
    sigSz = sizeof(data->signature);
    if (ret == 0) {
        ret = wc_SignatureGenerate(WC_HASH_TYPE_SHA256,
            WC_SIGNATURE_TYPE_RSA_W_ENC, signedData, signedOffset,
            data->signature, &sigSz, &key, sizeof(key), &rng);
    }
    data->signatureLen = sigSz;
    if (ret == 0) {
        ret = wc_se050_verify_attestation(&result,
            client_keypub_der_2048, sizeof_client_keypub_der_2048,
            result.freshness, sizeof(result.freshness), &valid);
    }
    if ((ret != 0) || !valid) {
        ret = fail("raw curve attestation verification", ret);
    }

    memcpy(wrongRandom, result.freshness, sizeof(wrongRandom));
    wrongRandom[0] ^= 1U;
    valid = 1;
    if (ret == 0) {
        ret = wc_se050_verify_attestation(&result,
            client_keypub_der_2048, sizeof_client_keypub_der_2048,
            wrongRandom, sizeof(wrongRandom), &valid);
        if ((ret != 0) || valid) {
            ret = fail("replayed attestation accepted", ret);
        }
    }

    if (rngInit) {
        wc_FreeRng(&rng);
    }
    if (keyInit) {
        wc_FreeRsaKey(&key);
    }
    return ret;
}
#endif /* WOLFSSL_SE050_ONLY_KEY_ID */

int main(void)
{
    static const byte seed[] = "SE05x simulator rotation seed";
    static const byte value[] = "policy protected";
    static const byte replacement[] = "replacement";
    wc_se050_scp03_keys recoveredKeys;
    wc_se050_scp03_keys rotatedKeys;
    ecc_key generatedEcc;
    RsaKey generatedRsa;
    sss_session_t* session;
    sss_key_store_t* hostKeyStore;
    sss_key_store_t* keyStore;
    byte attributes[128];
    byte readback[64];
    byte largeValue[TEST_LARGE_SZ];
    byte largeReadback[TEST_LARGE_SZ];
    word32 attributesSz = sizeof(attributes);
    word32 readbackSz = sizeof(readback);
    word32 largeReadbackSz = sizeof(largeReadback);
    word32 generatedKeyId = 0U;
    word32 i;
    int generatedEccInit = 0;
    int generatedRsaInit = 0;
    int ret;

#if !WOLFSSL_CRYPT_HW_MUTEX
    return fail("SE05x hardware mutex is disabled", -1);
#endif

    for (i = 0U; i < sizeof(largeValue); i++) {
        largeValue[i] = (byte)(i ^ (i >> 8));
    }

    ret = wc_se050_scp03_derive_keys_seed(seed,
        (word32)sizeof(seed) - 1U, &recoveredKeys);
    if (ret != 0) {
        return fail("wc_se050_scp03_derive_keys_seed", ret);
    }

    ret = wc_se050_init_ex(NULL, &currentKeys);
    if (ret != 0) {
        return fail("wc_se050_init_ex(current)", ret);
    }
    ret = wolfCrypt_Init();
    if (ret != 0) {
        (void)wc_se050_close();
        return fail("wolfCrypt_Init(after wc_se050_init_ex)", ret);
    }
#ifdef WOLFSSL_SE050_ONLY_KEY_ID
    /* Keep a session open while creating the synthetic RSA signature. The
     * 5.9.1 SE05x port routes host RSA signing through the SE05x, whereas
     * newer ports keep non-resident keys in software in ONLY_KEY_ID mode. */
    ret = test_raw_curve_attestation(
        (word32)kSSS_CipherType_EC_MONTGOMERY, 0x6EU);
    if (ret == 0) {
        ret = test_raw_curve_attestation(
            (word32)kSSS_CipherType_EC_TWISTED_ED, 0x70U);
    }
    if (ret != 0) {
        (void)wolfCrypt_Cleanup();
        return ret;
    }
#ifdef SE050_ATTEST_TEST_ONLY
    ret = wolfCrypt_Cleanup();
    if (ret != 0) {
        return fail("wolfCrypt_Cleanup(attestation only)", ret);
    }
    puts("PASS: raw-curve attestation and freshness verification");
    return 0;
#endif
#endif
    ret = wc_se050_get_config(&session, &hostKeyStore, &keyStore);
    if ((ret != 0) || (session == NULL) || (hostKeyStore == NULL) ||
            (keyStore == NULL) || (wc_se050_get_session() != session) ||
            (wc_se050_get_se05x_session() == NULL)) {
        return fail("session accessors", ret);
    }
    ret = wc_se050_init_ex(NULL, &currentKeys);
    if (ret != BAD_STATE_E) {
        return fail("double initialization was not rejected", ret);
    }
    ret = wc_se050_lock();
    if (ret != 0) {
        return fail("wc_se050_lock", ret);
    }
    wc_se050_unlock();
#ifndef WOLFSSL_SE050_NO_ATTEST
    {
        wc_se050_attst_result attestation;

        ret = wc_se050_attest_object(TEST_OBJECT_ID, TEST_ECC_ID,
            WC_HASH_TYPE_SHA256, NULL, 0, &attestation);
        if (ret != BAD_FUNC_ARG) {
            return fail("attestation accepted no freshness challenge", ret);
        }
    }
#endif

    ret = wc_se050_scp03_rotate_keys(&explicitKeys, 0x0B);
    if (ret != 0) {
        return fail("wc_se050_scp03_rotate_keys", ret);
    }
    ret = wc_se050_close();
    if (ret != 0) {
        return fail("wc_se050_close(explicit rotation)", ret);
    }

    ret = wc_se050_init_ex(NULL, &explicitKeys);
    if (ret != 0) {
        return fail("wc_se050_init_ex(explicit)", ret);
    }

    ret = wc_se050_scp03_rotate_keys_seed(seed, (word32)sizeof(seed) - 1U,
        0x0B, &rotatedKeys);
    if (ret != 0) {
        return fail("wc_se050_scp03_rotate_keys_seed", ret);
    }
    if (memcmp(&rotatedKeys, &recoveredKeys, sizeof(rotatedKeys)) != 0) {
        return fail("power-cycle SCP03 key derivation mismatch", -1);
    }

    ret = wc_se050_close();
    if (ret != 0) {
        return fail("wc_se050_close(seed rotation)", ret);
    }

    ret = wc_se050_init_ex(NULL, &recoveredKeys);
    if (ret != 0) {
        return fail("wc_se050_init_ex(rederived)", ret);
    }
#ifdef WOLFSSL_SE050_CRYPT
    {
        static const byte aesKey1[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        };
        static const byte aesKey2[16] = {
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        };
        Aes aes;
        int aesInit = 0;

        ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
        if (ret == 0) {
            aesInit = 1;
            ret = wc_AesSetKey(&aes, aesKey1, sizeof(aesKey1), NULL,
                AES_ENCRYPTION);
        }
        if (ret == 0) {
            ret = wc_AesSetKey(&aes, aesKey2, sizeof(aesKey2), NULL,
                AES_ENCRYPTION);
        }
        if (aesInit)
            wc_AesFree(&aes);
        if (ret != 0) {
            return fail("repeated SE05x AES key setup", ret);
        }
    }
#endif

    ret = wc_se050_insert_binary_object_ex(TEST_OBJECT_ID, value,
        (word32)sizeof(value) - 1U, WC_SE050_POLICY_ALLOW_READ, 0);
    if (ret != 0) {
        return fail("policy insert", ret);
    }
    ret = wc_se050_get_object_attributes(TEST_OBJECT_ID, attributes,
        &attributesSz);
    if ((ret != 0) || (attributesSz < 24U)) {
        return fail("attribute read", ret);
    }
    ret = wc_se050_get_binary_object(TEST_OBJECT_ID, readback, &readbackSz);
    if ((ret != 0) || (readbackSz != sizeof(value) - 1U) ||
            (memcmp(readback, value, readbackSz) != 0)) {
        return fail("policy object read", ret);
    }
    ret = wc_se050_insert_binary_object(TEST_OBJECT_ID, replacement,
        (word32)sizeof(replacement) - 1U);
    if (ret == 0) {
        return fail("no-write overwrite unexpectedly succeeded", ret);
    }
    ret = wc_se050_erase_object(TEST_OBJECT_ID);
    if (ret == 0) {
        return fail("no-delete erase unexpectedly succeeded", ret);
    }

    attributesSz = sizeof(attributes);
    ret = wc_se050_ecc_insert_public_key_ex(TEST_ECC_ID, eccPublicDer,
        sizeof(eccPublicDer), WC_SE050_POLICY_ALLOW_DELETE |
        WC_SE050_POLICY_ALLOW_READ | WC_SE050_POLICY_ALLOW_VERIFY, 0);
    if (ret != 0) {
        return fail("combined ECC policy insert", ret);
    }
    ret = wc_se050_get_object_attributes(TEST_ECC_ID, attributes,
        &attributesSz);
    if ((ret != 0) || (attributesSz < 23U) || (attributes[14] != 8U) ||
            (attributes[19] != 0x08U) || (attributes[20] != 0x24U) ||
            (attributes[21] != 0x00U) || (attributes[22] != 0x00U)) {
        return fail("combined ECC policy attributes", ret);
    }
    ret = wc_se050_erase_object(TEST_ECC_ID);
    if (ret != 0) {
        return fail("combined ECC policy delete", ret);
    }

    ret = wc_se050_insert_binary_object_ex(TEST_LARGE_ID, largeValue,
        sizeof(largeValue), WC_SE050_POLICY_ALLOW_READ |
        WC_SE050_POLICY_ALLOW_WRITE | WC_SE050_POLICY_ALLOW_DELETE, 0);
    if (ret != 0) {
        return fail("chunked binary policy insert", ret);
    }
    ret = wc_se050_get_binary_object(TEST_LARGE_ID, largeReadback,
        &largeReadbackSz);
    if ((ret != 0) || (largeReadbackSz != sizeof(largeValue)) ||
            (memcmp(largeReadback, largeValue, sizeof(largeValue)) != 0)) {
        return fail("chunked binary policy read", ret);
    }
    ret = wc_se050_insert_binary_object_ex(TEST_LARGE_ID, replacement,
        (word32)sizeof(replacement) - 1U, 0, 0);
    if (ret == 0) {
        return fail("duplicate zero-policy insert unexpectedly succeeded",
            ret);
    }
    ret = wc_se050_erase_object(TEST_LARGE_ID);
    if (ret != 0) {
        return fail("chunked binary policy delete", ret);
    }

    attributesSz = sizeof(attributes);
    ret = wc_se050_rsa_insert_public_key_ex(TEST_RSA_ID,
        client_keypub_der_2048, sizeof_client_keypub_der_2048,
        WC_SE050_POLICY_ALLOW_DELETE | WC_SE050_POLICY_ALLOW_READ |
        WC_SE050_POLICY_ALLOW_VERIFY, 0);
    if (ret != 0) {
        return fail("combined RSA policy insert", ret);
    }
    ret = wc_se050_get_object_attributes(TEST_RSA_ID, attributes,
        &attributesSz);
    if ((ret != 0) || (attributesSz < 23U) || (attributes[14] != 8U) ||
            (attributes[19] != 0x08U) || (attributes[20] != 0x24U) ||
            (attributes[21] != 0x00U) || (attributes[22] != 0x00U)) {
        return fail("combined RSA policy attributes", ret);
    }
    ret = wc_se050_erase_object(TEST_RSA_ID);
    if (ret != 0) {
        return fail("combined RSA policy delete", ret);
    }

    ret = wc_se050_rsa_insert_public_key_ex(TEST_RSA4K_ID,
        client_keypub_der_4096, sizeof_client_keypub_der_4096,
        WC_SE050_POLICY_ALLOW_DELETE | WC_SE050_POLICY_ALLOW_READ |
        WC_SE050_POLICY_ALLOW_VERIFY, 0);
    if (ret != 0) {
        return fail("RSA-4096 policy insert", ret);
    }
    ret = wc_se050_erase_object(TEST_RSA4K_ID);
    if (ret != 0) {
        return fail("RSA-4096 policy delete", ret);
    }

    attributesSz = sizeof(attributes);
    ret = wc_se050_ecc_generate_key_ex(TEST_ECC_GEN_ID, 32,
        ECC_SECP256R1, WC_SE050_POLICY_ALLOW_DELETE |
        WC_SE050_POLICY_ALLOW_READ | WC_SE050_POLICY_ALLOW_SIGN |
        WC_SE050_POLICY_ALLOW_VERIFY, 0);
    if (ret != 0) {
        return fail("policy ECC key generation", ret);
    }
    ret = wc_se050_ecc_generate_key_ex(TEST_ECC_GEN_ID, 32,
        ECC_SECP256R1, 0, 0);
    if (ret == 0) {
        return fail("duplicate ECC generation unexpectedly succeeded", ret);
    }
    ret = wc_se050_get_object_attributes(TEST_ECC_GEN_ID, attributes,
        &attributesSz);
    if ((ret != 0) || (attributesSz < 28U) || (attributes[14] != 8U) ||
            (attributes[19] != 0x18U) || (attributes[20] != 0x24U) ||
            (attributes[21] != 0x00U) || (attributes[22] != 0x00U) ||
            (attributes[23] != 0x02U)) {
        return fail("generated ECC policy attributes and origin", ret);
    }
    ret = wc_ecc_init(&generatedEcc);
    if (ret == 0) {
        generatedEccInit = 1;
        ret = wc_ecc_use_key_id(&generatedEcc, TEST_ECC_GEN_ID, 0);
    }
    if (ret == 0) {
        ret = wc_ecc_get_key_id(&generatedEcc, &generatedKeyId);
    }
    if (generatedEccInit) {
        wc_ecc_free(&generatedEcc);
    }
    if ((ret != 0) || (generatedKeyId != TEST_ECC_GEN_ID)) {
        return fail("bind generated ECC key", ret);
    }
    ret = wc_se050_erase_object(TEST_ECC_GEN_ID);
    if (ret != 0) {
        return fail("generated ECC key delete", ret);
    }

    attributesSz = sizeof(attributes);
    generatedKeyId = 0U;
    ret = wc_se050_rsa_generate_key_ex(TEST_RSA_GEN_ID, 2048, 65537,
        WC_SE050_POLICY_ALLOW_DELETE | WC_SE050_POLICY_ALLOW_READ |
        WC_SE050_POLICY_ALLOW_SIGN | WC_SE050_POLICY_ALLOW_VERIFY, 0);
    if (ret != 0) {
        return fail("policy RSA key generation", ret);
    }
    ret = wc_se050_rsa_generate_key_ex(TEST_RSA_GEN_ID, 2048, 65537,
        0, 0);
    if (ret == 0) {
        return fail("duplicate RSA generation unexpectedly succeeded", ret);
    }
    ret = wc_se050_get_object_attributes(TEST_RSA_GEN_ID, attributes,
        &attributesSz);
    if ((ret != 0) || (attributesSz < 28U) || (attributes[14] != 8U) ||
            (attributes[19] != 0x18U) || (attributes[20] != 0x24U) ||
            (attributes[21] != 0x00U) || (attributes[22] != 0x00U) ||
            (attributes[23] != 0x02U)) {
        return fail("generated RSA policy attributes and origin", ret);
    }
    ret = wc_InitRsaKey(&generatedRsa, NULL);
    if (ret == 0) {
        generatedRsaInit = 1;
        ret = wc_RsaUseKeyId(&generatedRsa, TEST_RSA_GEN_ID, 0);
    }
    if (ret == 0) {
        ret = wc_RsaGetKeyId(&generatedRsa, &generatedKeyId);
    }
    if (generatedRsaInit) {
        wc_FreeRsaKey(&generatedRsa);
    }
    if ((ret != 0) || (generatedKeyId != TEST_RSA_GEN_ID)) {
        return fail("bind generated RSA key", ret);
    }
    ret = wc_se050_erase_object(TEST_RSA_GEN_ID);
    if (ret != 0) {
        return fail("generated RSA key delete", ret);
    }

    ret = wolfCrypt_Cleanup();
    if (ret != 0) {
        return fail("wolfCrypt_Cleanup", ret);
    }
    if (wc_se050_get_session() != NULL) {
        return fail("wolfCrypt_Cleanup did not close SE05x", -1);
    }
    readbackSz = sizeof(readback);
    ret = wc_se050_get_binary_object(TEST_OBJECT_ID, readback, &readbackSz);
    if (ret != BAD_STATE_E) {
        return fail("uninitialized object read was not rejected", ret);
    }
    ret = wc_se050_erase_object(TEST_OBJECT_ID);
    if (ret != BAD_STATE_E) {
        return fail("uninitialized object erase was not rejected", ret);
    }
    puts("PASS: runtime SCP03, power-cycle derivation, initialization, "
         "rotation, session, policy insertion and policy key generation");
    return 0;
}
