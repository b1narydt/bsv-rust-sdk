//! Overlay tools for SHIP/SLAP service discovery and broadcasting.
//!
//! This module provides the infrastructure for interacting with the
//! BSV overlay network: discovering competent hosts via SLAP trackers,
//! broadcasting transactions via SHIP, managing host reputation, and
//! building transaction ancestry history.

pub mod admin_token_template;
pub mod historian;
pub mod host_reputation;
pub mod lookup_resolver;
pub mod retry;
pub mod topic_broadcaster;
pub mod types;

pub use admin_token_template::OverlayAdminTokenTemplate;
pub use historian::{Historian, InterpreterFn};
pub use host_reputation::{HostReputationEntry, HostReputationTracker, RankedHost};
pub use lookup_resolver::LookupResolver;
pub use retry::with_double_spend_retry;
pub use topic_broadcaster::TopicBroadcaster;
#[allow(deprecated)]
pub use types::AcknowledgmentMode;
pub use types::{
    AckPolicy, AckTopics, AdmittanceInstructions, LookupAnswer, LookupOutputEntry, LookupQuestion,
    LookupResolverConfig, Network, TaggedBEEF, TopicBroadcasterConfig, STEAK,
};
