// ring and aws_lc_rs are mutually exclusive.
#[cfg(all(feature = "aws_lc_rs", feature = "ring"))]
compile_error!("features `aws_lc_rs` and `ring` cannot be enabled at the same time");

#[cfg(feature = "aws_lc_rs")]
pub use rustls::crypto::aws_lc_rs as crypto_provider;
#[cfg(feature = "ring")]
pub use rustls::crypto::ring as crypto_provider;

pub fn install_crypto_provider() {
    let _ = crypto_provider::default_provider().install_default();
}
