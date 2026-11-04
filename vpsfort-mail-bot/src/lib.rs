//! The bot as a library: the binary (`main.rs`) only reads the settings, the tests in
//! `tests/` drive the same code against a fake mail server and GnuPG, and the fuzz targets in
//! `fuzz/` reach it through [`fuzzing`].

pub mod bot;
pub mod fuzzing;
pub mod mime;
pub mod seal;
pub mod smtp;

// shared with the other copy bots (../vpsfort-botlib)
pub use vpsfort_botlib::{logger, outbox, redact, servers};
