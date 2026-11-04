//! What vpsfort's copy bots (vpsfort-tg-bot, vpsfort-mail-bot, vpsfort-signal-bot,
//! vpsfort-matrix-bot, vpsfort-push-bot) share, in one place instead of a copy per bot:
//! the outbox they empty (vpsfort's `botbox` format), the pseudonyms and server names of
//! `SANITIZE`, the OpenPGP files for an admin's key, and the bot log. A fix here lands in
//! every bot (the mail bot's fuzzing once found a bug the Telegram bot had too).

pub mod logger;
pub mod outbox;
pub mod redact;
pub mod seal;
pub mod servers;
