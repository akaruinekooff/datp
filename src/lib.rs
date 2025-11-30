mod c_api;
pub use c_api::*;

use base32::decode;
use base32::Alphabet;
use hmac::{Hmac, KeyInit, Mac};
use qrcode::render::svg;
use qrcode::{EcLevel, QrCode, Version};
use rand::Rng;
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};


type HmacSha1 = Hmac<Sha1>;

pub struct TotpQrConfig<'a> {
    pub account_name: &'a str,
    pub issuer: &'a str,
    pub dark_color: &'a str,        // e.g. "#000000"
    pub light_color: &'a str,       // e.g. "#ffffff"
    pub min_dimension: u32,         // minimum width/height in px
    pub version: Version,           // QR code version
    pub ec_level: EcLevel,          // error correction level
}

/// Generates a random secret key for TOTP in base32 format.
///
/// # Arguments
/// * `length` - Number of random bytes to generate for the secret key.
///
/// # Returns
/// A `String` containing the base32-encoded secret key.
///
/// # Example
/// ```
/// use datp::generate_totp_secret;
/// let secret = generate_totp_secret(10);
/// println!("TOTP secret: {}", secret);
/// ```
pub fn generate_totp_secret(length: usize) -> String {
    let mut rng = rand::rng();
    let mut bytes = vec![0u8; length];
    rng.fill(&mut bytes);

    base32::encode(Alphabet::Rfc4648 { padding: false }, &bytes)
}

/// Generates a TOTP (Time-based One-Time Password) code for the current time.
///
/// # Arguments
/// * `secret_base32` - A base32-encoded secret key (without padding).
/// * `step` - Time step in seconds (usually 30 seconds).
/// * `t0` - Unix epoch start time (usually 0).
///
/// # Returns
/// `Option<u32>` - A 6-digit TOTP code if successful, or `None` if the secret is invalid.
///
/// # Example
/// ```rust
/// use datp::totp_raw_now;
///
/// let secret = "JBSWY3DPEHPK3PXP"; // base32 for "Hello!"
/// let code = totp_raw_now(secret, 30, 0).unwrap();
/// println!("Current TOTP code: {}", code);
/// ```
pub fn totp_raw_now(secret_base32: &str, step: u64, t0: u64) -> Option<u32> {
    totp_raw(secret_base32, step, t0, SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs())
}

/// Generates a TOTP (Time-based One-Time Password) code for the specific time.
///
/// # Arguments
/// * `secret_base32` - A base32-encoded secret key (without padding).
/// * `step` - Time step in seconds (usually 30 seconds).
/// * `t0` - Unix epoch start time (usually 0).
/// * `unix_time` - Specific unix time
///
/// # Returns
/// `Option<u32>` - A 6-digit TOTP code if successful, or `None` if the secret is invalid.
///
/// # Example
/// ```rust
/// use datp::totp_raw;
///
/// let secret = "JBSWY3DPEHPK3PXP"; // base32 for "Hello!"
/// let code = totp_raw(secret, 30, 0, 1388865600).unwrap(); // 2014 year, 5 january, 0 hours, 0 minutes, 0 seconds
/// println!("Current TOTP code: {}", code);
/// ```
pub fn totp_raw(secret_base32: &str, step: u64, t0: u64, unix_time: u64) -> Option<u32> {
    let secret = decode(Alphabet::Rfc4648 { padding: false }, secret_base32)?;

    let counter = (unix_time - t0) / step;
    let counter_bytes = counter.to_be_bytes();

    let mut mac = HmacSha1::new_from_slice(&secret).ok()?;
    mac.update(&counter_bytes);
    let hash = mac.finalize().into_bytes();

    let offset = (hash[19] & 0xf) as usize;
    let code_bytes = &hash[offset..offset + 4];
    let mut code = ((code_bytes[0] as u32 & 0x7f) << 24)
        | ((code_bytes[1] as u32) << 16)
        | ((code_bytes[2] as u32) << 8)
        | (code_bytes[3] as u32);

    code %= 1_000_000;
    Some(code)
}


/// Generates a TOTP QR code as an SVG string using custom configuration.
///
/// # Arguments
/// * `secret_base32` - Base32-encoded TOTP secret.
/// * `config` - TotpQrConfig struct with customization options.
///
/// # Returns
/// `String` - SVG image of the QR code.
///
/// # Example
/// ```rust
/// use datp::{totp_qr_svg, TotpQrConfig};
///
/// let secret = "JBSWY3DPEHPK3PXP";
/// let config = TotpQrConfig {
///     account_name: "user@example.com",
///     issuer: "MyApp",
///     dark_color: "#000080",
///     light_color: "#ffffcc",
///     min_dimension: 250,
///     version: qrcode::Version::Normal(5),
///     ec_level: qrcode::EcLevel::M,
/// };
/// let svg = totp_qr_svg(secret, &config);
/// std::fs::write("totp.svg", svg).unwrap();
/// ```
pub fn totp_qr_svg(secret_base32: &str, config: &TotpQrConfig) -> String {
    // build the otpauth URL
    let url = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
        config.issuer,
        config.account_name,
        secret_base32,
        config.issuer
    );

    // dynamically create QR code (auto version)
    let code = QrCode::new(url.as_bytes()).expect("Failed to create QR code");

    // render SVG with custom colors and size
    code.render()
        .min_dimensions(config.min_dimension, config.min_dimension)
        .dark_color(svg::Color(config.dark_color))
        .light_color(svg::Color(config.light_color))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_known_secret() {
        let secret = "JBSWY3DPEHPK3PXP";
        let code = totp_raw_now(secret, 30, 0);
        assert!(code.is_some());
        println!("TOTP code: {:?}", code.unwrap());
    }

    #[test]
    fn test_totp_different_steps() {
        let secret = "JBSWY3DPEHPK3PXP";
        let code1 = totp_raw_now(secret, 30, 0);
        let code2 = totp_raw_now(secret, 60, 0);
        assert!(code1.is_some());
        assert!(code2.is_some());
        assert_ne!(code1, code2);
    }

    #[test]
    fn test_totp_invalid_secret() {
        let secret = "invalid!!secret";
        let code = totp_raw_now(secret, 30, 0);
        assert!(code.is_none());
    }

    #[test]
    fn test_generate_totp_secret() {
        let secret = generate_totp_secret(10);
        println!("Generated secret: {}", secret);
        assert!(!secret.is_empty());
    }
}
