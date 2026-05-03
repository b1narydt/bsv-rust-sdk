//! High-level STAS-3 transaction factories.
//!
//! Each factory builds a fully-signed transaction for one operation shape.
//! Phase 5a delivered transfer; Phase 5b adds split + redeem; Phase 5c adds
//! merge; Phase 5d adds freeze, unfreeze, confiscate; Phase 7 adds the
//! swap factories (mark, cancel, execute).

pub mod common;
pub mod confiscate;
pub mod freeze;
pub mod issue;
pub mod merge;
pub mod merge_chain;
pub mod pieces;
pub mod redeem;
pub mod split;
pub mod swap_cancel;
pub mod swap_execute;
pub mod swap_mark;
pub mod transfer;
pub mod types;
pub mod unfreeze;

pub use confiscate::{build_confiscate, ConfiscateRequest};
pub use freeze::{build_freeze, FreezeRequest};
pub use issue::{build_issue, IssueDestination, IssueRequest, IssueResult};
pub use merge::{build_merge, MergeRequest};
pub use merge_chain::{build_merge_chain, MergeChainRequest};
pub use pieces::counterparty_script_from_lock;
pub use redeem::{build_redeem, RedeemRequest};
pub use split::{build_split, SplitDestination, SplitRequest};
pub use swap_cancel::{build_swap_cancel, SwapCancelRequest};
pub use swap_execute::{build_swap_execute, SwapExecuteRequest};
pub use swap_mark::{build_swap_mark, SwapMarkRequest};
pub use transfer::{build_transfer, TransferRequest};
pub use types::{FundingInput, SigningKey, TokenInput};
pub use unfreeze::{build_unfreeze, UnfreezeRequest};
