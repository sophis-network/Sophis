use crate::Notification;

pub type ChannelConnection = sophis_notify::connection::ChannelConnection<Notification>;
pub use sophis_notify::connection::ChannelType;
