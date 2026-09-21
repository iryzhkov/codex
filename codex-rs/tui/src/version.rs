/// The current Codex CLI version as embedded at compile time.
#[cfg(not(test))]
pub const CODEX_CLI_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
pub const CODEX_CLI_VERSION: &str = "0.0.0";
