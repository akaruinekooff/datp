use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_uint};

use super::*; 

#[repr(C)]
#[doc(hidden)]
pub struct TotpQrConfigC {
    pub dark_color: *const c_char,
    pub light_color: *const c_char,
    pub min_dimension: c_uint,
    pub version: u8,
    pub ec_level: u8,
}

#[unsafe(no_mangle)]
#[doc(hidden)]
pub extern "C" fn generate_totp_secret_c(length: c_uint) -> *mut c_char {
    let secret = generate_totp_secret(length as usize);
    CString::new(secret).unwrap().into_raw()
}

#[unsafe(no_mangle)]
#[allow(unused)]
#[doc(hidden)]
pub extern "C" fn free_c_string(s: *mut c_char) {
    if s.is_null() { return; }
    unsafe { CString::from_raw(s) };
}

#[unsafe(no_mangle)]
#[doc(hidden)]
pub extern "C" fn totp_raw_now_c(secret: *const c_char, step: u64, t0: u64) -> c_uint {
    if secret.is_null() { return 0; }
    let secret_str = unsafe { CStr::from_ptr(secret).to_string_lossy() };
    totp_raw_now(secret_str.as_ref(), step, t0).unwrap_or(0)
}

#[unsafe(no_mangle)]
#[doc(hidden)]
pub extern "C" fn totp_raw_c(secret: *const c_char, step: u64, t0: u64, unix_time: u64) -> c_uint {
    if secret.is_null() { return 0; }
    let secret_str = unsafe { CStr::from_ptr(secret).to_string_lossy() };
    totp_raw(secret_str.as_ref(), step, t0, unix_time).unwrap_or(0)
}

#[unsafe(no_mangle)]
#[doc(hidden)]
pub extern "C" fn totp_qr_svg_c(secret: *const c_char, config: *const TotpQrConfigC) -> *mut c_char {
    if secret.is_null() || config.is_null() { return std::ptr::null_mut(); }

    let secret_str = unsafe { CStr::from_ptr(secret).to_string_lossy() };
    let cfg = unsafe { &*config };
    let dark = unsafe { CStr::from_ptr(cfg.dark_color).to_string_lossy() };
    let light = unsafe { CStr::from_ptr(cfg.light_color).to_string_lossy() };

    let qr_config = TotpQrConfig {
        account_name: "totp",  // можно сделать отдельное поле для C api
        issuer: "totp",
        dark_color: &dark,
        light_color: &light,
        min_dimension: cfg.min_dimension,
        version: match cfg.version {
            0 => Version::Normal(1),
            1 => Version::Normal(2),
            2 => Version::Normal(3),
            3 => Version::Normal(4),
            4 => Version::Normal(5),
            _ => Version::Normal(1),
        },
        ec_level: match cfg.ec_level {
            0 => EcLevel::L,
            1 => EcLevel::M,
            2 => EcLevel::Q,
            3 => EcLevel::H,
            _ => EcLevel::M,
        },
    };

    let svg = totp_qr_svg(secret_str.as_ref(), &qr_config);
    CString::new(svg).unwrap().into_raw()
}
