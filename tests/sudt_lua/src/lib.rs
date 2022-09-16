//! pub use const BUNDLED_CELL: Files
//! pub use const CODE_HASH_LUA_LOADER: [u8; 32]
//! pub use const CODE_HASH_SUDT_LUA: [u8; 32]

#![allow(clippy::unreadable_literal)]

include!(concat!(env!("OUT_DIR"), "/bundled.rs"));
include!(concat!(env!("OUT_DIR"), "/code_hashes.rs"));

#[cfg(test)]
mod tests;
