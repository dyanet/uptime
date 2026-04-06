//! Runtime plugin loading for alternate store implementations.
//!
//! Alternate backends are compiled as `cdylib` crates that export a single
//! C function:
//!
//! ```ignore
//! #[no_mangle]
//! pub extern "C" fn create_store(config_json: *const c_char) -> *mut dyn StorePlugin;
//! ```
//!
//! The returned trait object bundles all store traits into one.

use std::ffi::CString;
use std::path::Path;

use crate::traits::*;
use crate::types::*;

/// Combined trait that plugin implementations must satisfy.
/// A single object provides all storage operations.
pub trait StorePlugin: DomainReader + UptimeWriter + UptimeReader + ErrorWriter + BaselineStore {}

// Blanket impl: anything implementing all sub-traits is a StorePlugin.
impl<T> StorePlugin for T where T: DomainReader + UptimeWriter + UptimeReader + ErrorWriter + BaselineStore {}

/// Load a store plugin from a shared library at runtime.
///
/// `config_json` is passed to the plugin's `create_store` function so it can
/// configure itself (e.g. database connection string, file paths, etc.).
///
/// # Safety
/// The loaded library must export `create_store` with the correct signature.
/// The caller owns the returned Box and must drop it to free resources.
#[allow(improper_ctypes_definitions)]
pub unsafe fn load_plugin(
    lib_path: &Path,
    config_json: &str,
) -> Result<Box<dyn StorePlugin>, StoreError> {
    type CreateFn = unsafe extern "C" fn(*const std::ffi::c_char) -> *mut dyn StorePlugin;

    let lib = unsafe {
        libloading::Library::new(lib_path)
            .map_err(|e| StoreError(format!("failed to load plugin {}: {e}", lib_path.display())))?
    };

    let create: libloading::Symbol<CreateFn> = unsafe {
        lib.get(b"create_store")
            .map_err(|e| StoreError(format!("plugin missing create_store symbol: {e}")))?
    };

    let c_config = CString::new(config_json)
        .map_err(|e| StoreError(format!("invalid config string: {e}")))?;

    let raw = unsafe { create(c_config.as_ptr()) };
    if raw.is_null() {
        return Err(StoreError("plugin create_store returned null".into()));
    }

    // Leak the library so it stays loaded for the lifetime of the plugin.
    std::mem::forget(lib);

    Ok(unsafe { Box::from_raw(raw) })
}
