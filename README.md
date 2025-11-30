# datp

`datp` is a lightweight Rust library for working with TOTP (Time-based One-Time Password) and generating QR codes for two-factor authentication.

## Features

- Generate random TOTP secrets in base32.
- Compute TOTP codes for the current or a specific time.
- Generate SVG QR codes with customizable colors, size, and version.

## Installation

Add to `Cargo.toml`:

```toml
[dependencies]
datp = "0.1.0"
````

## Usage Examples

### Generate a secret

```rust
use datp::generate_totp_secret;

let secret = generate_totp_secret(10);
println!("TOTP secret: {}", secret);
```

### Get the current TOTP code

```rust
use datp::totp_raw_now;

let secret = "JBSWY3DPEHPK3PXP";
let code = totp_raw_now(secret, 30, 0).unwrap();
println!("Current TOTP code: {}", code);
```

### TOTP code for a specific time

```rust
use datp::totp_raw;

let secret = "JBSWY3DPEHPK3PXP";
let code = totp_raw(secret, 30, 0, 1_388_865_600).unwrap();
println!("TOTP code at specific time: {}", code);
```

### Generate a TOTP QR code

```rust
use datp::{totp_qr_svg, TotpQrConfig};
use qrcode::EcLevel;
use qrcode::Version;

let secret = "JBSWY3DPEHPK3PXP";
let config = TotpQrConfig {
    account_name: "user@example.com",
    issuer: "MyApp",
    dark_color: "#000080",
    light_color: "#ffffcc",
    min_dimension: 250,
    version: Version::Normal(5),
    ec_level: EcLevel::M,
};

let svg = totp_qr_svg(secret, &config);
std::fs::write("totp.svg", svg).unwrap();
```

## Notes

* Uses `Hmac<Sha1>` for TOTP generation.
* Fully compatible with TOTP apps like Google Authenticator or Authy.
* QR code colors and size are customizable.
