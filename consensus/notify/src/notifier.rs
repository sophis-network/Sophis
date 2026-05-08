use crate::notification::Notification;
use sophis_notify::{connection::ChannelConnection, notifier::Notifier};

pub type ConsensusNotifier = Notifier<Notification, ChannelConnection<Notification>>;
