//! Credential provider abstraction
//!
//! Defines the [`CredentialProvider`] trait for pluggable password manager
//! backends, and ships the built-in [`BitwardenProvider`].

mod bitwarden;

pub use bitwarden::BitwardenProvider;
use bw_rat_client::UserCredentialData;
use color_eyre::eyre::{Result, bail};

/// What kind of credential to look up.
#[allow(dead_code)]
pub enum CredentialQuery<'a> {
    /// Look up by domain / URL.
    Domain(&'a str),
    /// Look up by credential ID.
    CredentialId(&'a str),
    /// Free-text search.
    Search(&'a str),
}

/// Current readiness of a credential provider.
#[allow(dead_code)]
pub enum ProviderStatus {
    /// Provider is ready to serve credentials.
    Ready { user_info: Option<String> },
    /// Provider requires an unlock step (e.g. master password or session key).
    Locked {
        prompt: String,
        user_info: Option<String>,
    },
    /// Provider is installed but not usable (e.g. not logged in).
    Unavailable { reason: String },
    /// Provider binary is not installed.
    NotInstalled { install_hint: String },
}

/// Result of a credential lookup.
pub enum LookupResult {
    /// A credential was found.
    Found(UserCredentialData),
    /// No matching credential exists.
    NotFound,
    /// The provider is not ready (e.g. vault locked).
    NotReady { message: String },
}

/// A pluggable credential provider.
///
/// Implementations back different password managers (Bitwarden CLI, 1Password,
/// etc.) behind a uniform interface so the listen command can work with any of
/// them.
pub trait CredentialProvider: Send + Sync {
    /// Human-readable name shown in the TUI header (e.g. "Bitwarden").
    fn name(&self) -> &str;

    /// Check current readiness.
    fn status(&self) -> ProviderStatus;

    /// Attempt to unlock the provider.
    ///
    /// The semantics of `input` are provider-specific. For Bitwarden it may be
    /// a master password *or* a raw session key — the implementation
    /// auto-detects which.
    fn unlock(&mut self, input: &str) -> Result<(), String>;

    /// Look up a credential.
    fn lookup(&self, query: &CredentialQuery<'_>) -> LookupResult;
}

/// Create a provider by name.
pub fn create_provider(name: &str) -> Result<Box<dyn CredentialProvider>> {
    match name {
        "bitwarden" => Ok(Box::new(BitwardenProvider::new())),
        _ => bail!("Unknown credential provider: '{name}'. Available: bitwarden"),
    }
}
