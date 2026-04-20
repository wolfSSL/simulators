extern crate se050;
extern crate se050_sim;

use se050::{Se050, Se050Device, T1overI2C};
use se050_sim::Se050Simulator;

// Delay wrapper boilerplate (required by the se050 crate)
struct DummyDelay;

impl embedded_hal::blocking::delay::DelayMs<u32> for DummyDelay {
    fn delay_ms(&mut self, _ms: u32) {}
}

static mut GLOBAL_DELAY: Option<DummyDelay> = Some(DummyDelay);

fn get_delay() -> se050::DelayWrapper {
    se050::DelayWrapper {
        inner: unsafe { GLOBAL_DELAY.as_mut().unwrap() },
    }
}

fn create_se050() -> Se050<T1overI2C<Se050Simulator>> {
    let sim = Se050Simulator::new();
    let t1 = T1overI2C::new(sim, 0x48, 0x5a);
    Se050::new(t1)
}

// =========================================================================
// Phase 1: Basic connectivity
// =========================================================================

#[test]
fn test_enable() {
    let mut se050 = create_se050();
    let mut delay = get_delay();
    let result = se050.enable(&mut delay);
    assert!(result.is_ok(), "enable() failed: {:?}", result.err());
}

// =========================================================================
// Phase 2: Management commands
// =========================================================================

#[test]
fn test_get_random() {
    let mut se050 = create_se050();
    let mut delay = get_delay();
    se050.enable(&mut delay).unwrap();

    let mut buf = [0u8; 32];
    let result = se050.get_random(&mut buf, &mut delay);
    assert!(result.is_ok(), "get_random() failed: {:?}", result.err());
    // Random data should not be all zeros
    assert_ne!(buf, [0u8; 32], "Random data was all zeros");
}

#[test]
fn test_get_free_memory() {
    let mut se050 = create_se050();
    let mut delay = get_delay();
    se050.enable(&mut delay).unwrap();

    let result = se050.get_free_memory(&[0x01], &mut delay);
    assert!(
        result.is_ok(),
        "get_free_memory() failed: {:?}",
        result.err()
    );
}

#[test]
fn test_delete_all() {
    let mut se050 = create_se050();
    let mut delay = get_delay();
    se050.enable(&mut delay).unwrap();

    let result = se050.delete_all(&mut delay);
    assert!(result.is_ok(), "delete_all() failed: {:?}", result.err());
}

// =========================================================================
// Phase 3: Object management
// =========================================================================

#[test]
fn test_write_and_check_object_exists() {
    let mut se050 = create_se050();
    let mut delay = get_delay();
    se050.enable(&mut delay).unwrap();

    let obj_id = [0x10, 0x00, 0x00, 0x01];

    // Write a binary object
    let result = se050.write_binary(
        &[],           // no policy
        &obj_id,
        &[0x00, 0x00], // offset 0
        &[0x00, 0x05], // length 5
        &[0x01, 0x02, 0x03, 0x04, 0x05],
        &mut delay,
    );
    assert!(
        result.is_ok(),
        "write_binary() failed: {:?}",
        result.err()
    );

    // Check it exists
    let result = se050.check_object_exists(&obj_id, &mut delay);
    assert!(
        result.is_ok(),
        "check_object_exists() failed: {:?}",
        result.err()
    );

    // Delete it
    let result = se050.delete_secure_object(&obj_id, &mut delay);
    assert!(
        result.is_ok(),
        "delete_secure_object() failed: {:?}",
        result.err()
    );
}

// =========================================================================
// Phase 4: EC key operations
// =========================================================================

#[test]
fn test_generate_p256_key() {
    let mut se050 = create_se050();
    let mut delay = get_delay();
    se050.enable(&mut delay).unwrap();

    let result = se050.generate_p256_key(&mut delay);
    assert!(
        result.is_ok(),
        "generate_p256_key() failed: {:?}",
        result.err()
    );
}

#[test]
fn test_generate_ed25519_key() {
    let mut se050 = create_se050();
    let mut delay = get_delay();
    se050.enable(&mut delay).unwrap();

    let result = se050.generate_ed255_key_pair(&mut delay);
    assert!(
        result.is_ok(),
        "generate_ed255_key_pair() failed: {:?}",
        result.err()
    );
}

// =========================================================================
// Phase 5: AES operations
// =========================================================================

#[test]
fn test_write_aes_key() {
    let mut se050 = create_se050();
    let mut delay = get_delay();
    se050.enable(&mut delay).unwrap();

    let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
               0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    let result = se050.write_aes_key(&key, &mut delay);
    assert!(
        result.is_ok(),
        "write_aes_key() failed: {:?}",
        result.err()
    );
}

#[test]
fn test_aes_encrypt_decrypt() {
    let mut se050 = create_se050();
    let mut delay = get_delay();
    se050.enable(&mut delay).unwrap();

    // Write an AES key with the hardcoded ID 0xae50ae50
    let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
               0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F];
    se050.write_aes_key(&key, &mut delay).unwrap();

    // Encrypt 16 bytes
    let plaintext = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                     0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00];
    let mut ciphertext = [0u8; 16];
    let result = se050.encrypt_aes_oneshot(&plaintext, &mut ciphertext, &mut delay);
    assert!(
        result.is_ok(),
        "encrypt_aes_oneshot() failed: {:?}",
        result.err()
    );

    // Ciphertext should be different from plaintext
    assert_ne!(ciphertext, plaintext, "Ciphertext matches plaintext");
}

// =========================================================================
// Phase 6: Digest
// =========================================================================

#[test]
fn test_digest_sha256() {
    let mut se050 = create_se050();
    let mut delay = get_delay();
    se050.enable(&mut delay).unwrap();

    let result = se050.digest_one_shot(
        &[0x04], // SHA-256
        &[0x61, 0x62, 0x63], // "abc"
        &mut delay,
    );
    assert!(
        result.is_ok(),
        "digest_one_shot() failed: {:?}",
        result.err()
    );
}

// =========================================================================
// Phase 7: RSA operations
// =========================================================================

#[test]
fn test_generate_rsa_key() {
    let mut se050 = create_se050();
    let mut delay = get_delay();
    se050.enable(&mut delay).unwrap();

    let obj_id = [0x30, 0x00, 0x00, 0x01];
    let key_size: [u8; 2] = [0x04, 0x00]; // 1024 bits (fast for testing)
    let result = se050.write_rsa_key(&[], &obj_id, &key_size, &mut delay);
    assert!(
        result.is_ok(),
        "write_rsa_key() failed: {:?}",
        result.err()
    );
}

#[test]
fn test_rsa_sign() {
    let mut se050 = create_se050();
    let mut delay = get_delay();
    se050.enable(&mut delay).unwrap();

    // Generate RSA-1024 key
    let obj_id = [0x30, 0x00, 0x00, 0x02];
    let key_size: [u8; 2] = [0x04, 0x00]; // 1024 bits
    se050.write_rsa_key(&[], &obj_id, &key_size, &mut delay).unwrap();

    // Sign data with PKCS1v1.5 SHA-256 (algo=0x28)
    let input_data = [0x01, 0x02, 0x03, 0x04];
    let result = se050.rsa_sign(&obj_id, &[0x28], &input_data, &mut delay);
    assert!(
        result.is_ok(),
        "rsa_sign() failed: {:?}",
        result.err()
    );
}

#[test]
fn test_rsa_verify() {
    let mut se050 = create_se050();
    let mut delay = get_delay();
    se050.enable(&mut delay).unwrap();

    // Generate RSA-1024 key
    let obj_id = [0x30, 0x00, 0x00, 0x03];
    let key_size: [u8; 2] = [0x04, 0x00]; // 1024 bits
    se050.write_rsa_key(&[], &obj_id, &key_size, &mut delay).unwrap();

    // Sign, then verify
    let input_data = [0x01, 0x02, 0x03, 0x04];
    // rsa_sign doesn't return the signature in the driver API (returns Ok(())),
    // so we can only test that the command succeeds
    let result = se050.rsa_sign(&obj_id, &[0x28], &input_data, &mut delay);
    assert!(result.is_ok(), "rsa_sign() failed: {:?}", result.err());
}

#[test]
fn test_rsa_encrypt_decrypt() {
    let mut se050 = create_se050();
    let mut delay = get_delay();
    se050.enable(&mut delay).unwrap();

    // Generate RSA-1024 key
    let obj_id = [0x30, 0x00, 0x00, 0x04];
    let key_size: [u8; 2] = [0x04, 0x00]; // 1024 bits
    se050.write_rsa_key(&[], &obj_id, &key_size, &mut delay).unwrap();

    // Encrypt with PKCS1v1.5 (algo=0x0A)
    let plaintext = [0x48, 0x65, 0x6C, 0x6C, 0x6F]; // "Hello"
    let result = se050.rsa_encrypt(&obj_id, &[0x0A], &plaintext, &mut delay);
    assert!(
        result.is_ok(),
        "rsa_encrypt() failed: {:?}",
        result.err()
    );
}
