/*
 * Standalone wolfCrypt test with SE050 simulator initialization.
 */

#include <stdio.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/port/nxp/se050_port.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

/* wolfcrypt_test defined in test.c */
int wolfcrypt_test(void* args);

int main(void)
{
    int ret;

    printf("=== Initializing SE050 Simulator Connection ===\n");
    fflush(stdout);

    ret = wc_se050_init(NULL);
    if (ret != 0) {
        printf("ERROR: wc_se050_init() failed with %d\n", ret);
        return -1;
    }

    printf("=== SE050 Connection Established ===\n");
    fflush(stdout);

    wolfSSL_Init();

    /* Quick ECC test before running full suite */
    {
        ecc_key testKey;
        WC_RNG rng;
        wc_InitRng(&rng);
        wc_ecc_init(&testKey);
        ret = wc_ecc_make_key_ex(&rng, 32, &testKey, ECC_SECP256R1);
        printf("=== Quick P-256 keygen: %s (ret=%d) ===\n",
               ret == 0 ? "OK" : "FAILED", ret);
        if (ret == 0) {
            byte sig[128];
            word32 sigSz = sizeof(sig);
            byte hash[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                            17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
            ret = wc_ecc_sign_hash(hash, sizeof(hash), sig, &sigSz, &rng, &testKey);
            printf("=== Quick P-256 sign: %s (ret=%d, sigSz=%u) ===\n",
                   ret == 0 ? "OK" : "FAILED", ret, sigSz);
            if (ret == 0) {
                int verified = 0;
                ret = wc_ecc_verify_hash(sig, sigSz, hash, sizeof(hash), &verified, &testKey);
                printf("=== Quick P-256 verify: %s (ret=%d, verified=%d) ===\n",
                       ret == 0 ? "OK" : "FAILED", ret, verified);
            }
        }
        wc_ecc_free(&testKey);
        wc_FreeRng(&rng);
        fflush(stdout);
    }

    printf("=== Calling wolfcrypt_test... ===\n");
    fflush(stdout);
    fflush(stderr);

    ret = wolfcrypt_test(NULL);

    fflush(stdout);
    fflush(stderr);
    wolfSSL_Cleanup();

    printf("\n=== wolfCrypt Test %s (return code: %d) ===\n",
           ret == 0 ? "PASSED" : "FAILED", ret);

    return ret;
}
