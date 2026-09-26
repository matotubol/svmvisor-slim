//! Process inspection from offline captures or an explicitly requested live physical bridge.

pub(crate) use self::command::command;
pub(crate) use self::live::command as live_command;

mod command;
mod image;
mod live;
