//! RemittanceModule trait and erased variant for object-safe storage.
//!
//! `RemittanceModule` is the typed public trait with associated types for
//! OptionTerms, SettlementArtifact, and ReceiptData. Because associated types
//! make a trait non-object-safe, `ErasedRemittanceModule` provides an
//! object-safe internal variant using `serde_json::Value` at the boundary.
//! A blanket impl bridges the two: `impl<T: RemittanceModule> ErasedRemittanceModule for T`.
//!
//! Phase 3 (RemittanceManager) stores modules as `HashMap<String, Box<dyn ErasedRemittanceModule>>`.

#![cfg(feature = "network")]

use async_trait::async_trait;

use crate::remittance::error::RemittanceError;
use crate::remittance::types::{Invoice, ModuleContext, Settlement, Termination};

// ---------------------------------------------------------------------------
// Return enums
// ---------------------------------------------------------------------------

/// The result of `RemittanceModule::build_settlement`.
///
/// Mirrors the TypeScript SDK union `{ settle: A } | { terminate: Termination }`.
#[derive(Debug)]
pub enum BuildSettlementResult<A> {
    /// Payment artifact produced; proceed with settlement.
    Settle { artifact: A },
    /// Module cannot build a settlement; terminate the thread.
    Terminate { termination: Termination },
}

/// The result of `RemittanceModule::accept_settlement`.
///
/// Mirrors the TypeScript SDK union `{ accept: R | undefined } | { terminate: Termination }`.
#[derive(Debug)]
pub enum AcceptSettlementResult<R> {
    /// Settlement accepted; optional receipt data to send back to the payer.
    Accept { receipt_data: Option<R> },
    /// Settlement rejected; terminate the thread.
    Terminate { termination: Termination },
}

// ---------------------------------------------------------------------------
// Typed public trait
// ---------------------------------------------------------------------------

/// Pluggable payment-module interface consumed by `RemittanceManager`.
///
/// Each associated type must be `Send + Sync + Serialize + DeserializeOwned + 'static`
/// so the blanket impl can erase them to `serde_json::Value` at the storage boundary.
///
/// Optional methods (`create_option`, `process_receipt`, `process_termination`) have
/// default implementations that match the TypeScript SDK's behaviour for modules that
/// do not implement those extension points. Check `supports_create_option()` before
/// calling `create_option`, mirroring the TS `if (typeof mod.createOption === 'function')`
/// guard in the manager.
#[async_trait]
pub trait RemittanceModule: Send + Sync {
    /// Opaque terms produced by `create_option` and consumed by `build_settlement`.
    type OptionTerms: Send + Sync + serde::Serialize + serde::de::DeserializeOwned + 'static;
    /// Opaque artifact produced by `build_settlement` and consumed by `accept_settlement`.
    type SettlementArtifact: Send + Sync + serde::Serialize + serde::de::DeserializeOwned + 'static;
    /// Optional receipt payload returned by `accept_settlement` and consumed by `process_receipt`.
    type ReceiptData: Send + Sync + serde::Serialize + serde::de::DeserializeOwned + 'static;

    // ------------------------------------------------------------------
    // Required getters
    // ------------------------------------------------------------------

    /// Unique identifier for this module (e.g. "direct").
    fn id(&self) -> &str;

    /// Human-readable name (e.g. "Direct BSV").
    fn name(&self) -> &str;

    /// Whether the manager should accept settlements that arrive without a
    /// prior invoice (unsolicited).
    fn allow_unsolicited_settlements(&self) -> bool;

    // ------------------------------------------------------------------
    // Optional capability flag
    // ------------------------------------------------------------------

    /// Returns `true` if this module supports `create_option`.
    ///
    /// Mirrors the TypeScript SDK's `if (typeof mod.createOption === 'function')` guard.
    /// The manager checks this before calling `create_option`.
    /// Default: `false`.
    fn supports_create_option(&self) -> bool {
        false
    }

    // ------------------------------------------------------------------
    // Optional async methods
    // ------------------------------------------------------------------

    /// Generate option terms for one entry in the invoice options map.
    ///
    /// Default: returns a `Protocol` error. Override when `supports_create_option` is `true`.
    async fn create_option(
        &self,
        thread_id: &str,
        invoice: &Invoice,
        ctx: &ModuleContext,
    ) -> Result<Self::OptionTerms, RemittanceError> {
        let _ = (thread_id, invoice, ctx);
        Err(RemittanceError::Protocol(
            "createOption not implemented for this module".into(),
        ))
    }

    // ------------------------------------------------------------------
    // Required async methods
    // ------------------------------------------------------------------

    /// Build a settlement artifact from an option selection.
    async fn build_settlement(
        &self,
        thread_id: &str,
        invoice: Option<&Invoice>,
        option: &Self::OptionTerms,
        note: Option<&str>,
        ctx: &ModuleContext,
    ) -> Result<BuildSettlementResult<Self::SettlementArtifact>, RemittanceError>;

    /// Accept (or reject) an incoming settlement artifact.
    async fn accept_settlement(
        &self,
        thread_id: &str,
        invoice: Option<&Invoice>,
        settlement: &Self::SettlementArtifact,
        sender: &str,
        ctx: &ModuleContext,
    ) -> Result<AcceptSettlementResult<Self::ReceiptData>, RemittanceError>;

    // ------------------------------------------------------------------
    // Optional async notification methods
    // ------------------------------------------------------------------

    /// Process a receipt from the payee after a successful settlement.
    ///
    /// Default: no-op `Ok(())`.
    async fn process_receipt(
        &self,
        thread_id: &str,
        invoice: Option<&Invoice>,
        receipt_data: &Self::ReceiptData,
        sender: &str,
        ctx: &ModuleContext,
    ) -> Result<(), RemittanceError> {
        let _ = (thread_id, invoice, receipt_data, sender, ctx);
        Ok(())
    }

    /// Process a termination notification for a thread.
    ///
    /// Default: no-op `Ok(())`.
    async fn process_termination(
        &self,
        thread_id: &str,
        invoice: Option<&Invoice>,
        settlement: Option<&Settlement>,
        termination: &Termination,
        sender: &str,
        ctx: &ModuleContext,
    ) -> Result<(), RemittanceError> {
        let _ = (thread_id, invoice, settlement, termination, sender, ctx);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Erased return structs (pub(crate) — internal to the crate)
// ---------------------------------------------------------------------------

/// Type-erased result of `build_settlement` — carries `serde_json::Value`
/// instead of the module's `SettlementArtifact` associated type.
pub struct BuildSettlementErased {
    /// Either "settle" or "terminate".
    pub action: &'static str,
    pub artifact: Option<serde_json::Value>,
    pub termination: Option<Termination>,
}

/// Type-erased result of `accept_settlement` — carries `serde_json::Value`
/// instead of the module's `ReceiptData` associated type.
pub struct AcceptSettlementErased {
    /// Either "accept" or "terminate".
    pub action: &'static str,
    pub receipt_data: Option<serde_json::Value>,
    pub termination: Option<Termination>,
}

// ---------------------------------------------------------------------------
// Object-safe erased trait (pub(crate) — internal to the crate)
// ---------------------------------------------------------------------------

/// Object-safe mirror of `RemittanceModule`, with associated types replaced by
/// `serde_json::Value`. Used by `RemittanceManager` to store modules
/// behind `Box<dyn ErasedRemittanceModule>` in a `HashMap<String, …>`.
///
/// External callers pass concrete `RemittanceModule` implementors to the constructor;
/// the blanket impl `impl<T: RemittanceModule> ErasedRemittanceModule for T` handles
/// the coercion automatically.
#[async_trait]
pub trait ErasedRemittanceModule: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn allow_unsolicited_settlements(&self) -> bool;
    fn supports_create_option(&self) -> bool;

    async fn create_option_erased(
        &self,
        thread_id: &str,
        invoice: &Invoice,
        ctx: &ModuleContext,
    ) -> Result<serde_json::Value, RemittanceError>;

    async fn build_settlement_erased(
        &self,
        thread_id: &str,
        invoice: Option<&Invoice>,
        option_json: &serde_json::Value,
        note: Option<&str>,
        ctx: &ModuleContext,
    ) -> Result<BuildSettlementErased, RemittanceError>;

    async fn accept_settlement_erased(
        &self,
        thread_id: &str,
        invoice: Option<&Invoice>,
        artifact_json: &serde_json::Value,
        sender: &str,
        ctx: &ModuleContext,
    ) -> Result<AcceptSettlementErased, RemittanceError>;

    async fn process_receipt_erased(
        &self,
        thread_id: &str,
        invoice: Option<&Invoice>,
        receipt_json: &serde_json::Value,
        sender: &str,
        ctx: &ModuleContext,
    ) -> Result<(), RemittanceError>;

    /// `settlement` is `Option<&Settlement>` (the concrete struct), not `serde_json::Value`,
    /// because `Settlement` is already a concrete wire-format type — no erasure needed,
    /// matching the TypeScript SDK where `settlement?: Settlement` is the full struct.
    async fn process_termination_erased(
        &self,
        thread_id: &str,
        invoice: Option<&Invoice>,
        settlement: Option<&Settlement>,
        termination: &Termination,
        sender: &str,
        ctx: &ModuleContext,
    ) -> Result<(), RemittanceError>;
}

// ---------------------------------------------------------------------------
// Blanket impl: every RemittanceModule is automatically ErasedRemittanceModule
// ---------------------------------------------------------------------------

#[async_trait]
impl<T: RemittanceModule> ErasedRemittanceModule for T {
    fn id(&self) -> &str {
        RemittanceModule::id(self)
    }

    fn name(&self) -> &str {
        RemittanceModule::name(self)
    }

    fn allow_unsolicited_settlements(&self) -> bool {
        RemittanceModule::allow_unsolicited_settlements(self)
    }

    fn supports_create_option(&self) -> bool {
        RemittanceModule::supports_create_option(self)
    }

    async fn create_option_erased(
        &self,
        thread_id: &str,
        invoice: &Invoice,
        ctx: &ModuleContext,
    ) -> Result<serde_json::Value, RemittanceError> {
        let typed = self.create_option(thread_id, invoice, ctx).await?;
        // clone inside to_value is not needed for owned value, but serde_json::to_value
        // requires ownership of the value
        let v = serde_json::to_value(typed)?;
        Ok(v)
    }

    async fn build_settlement_erased(
        &self,
        thread_id: &str,
        invoice: Option<&Invoice>,
        option_json: &serde_json::Value,
        note: Option<&str>,
        ctx: &ModuleContext,
    ) -> Result<BuildSettlementErased, RemittanceError> {
        // clone is necessary — from_value consumes the value but we only have a reference
        let option: T::OptionTerms = serde_json::from_value(option_json.clone())?;
        let result = self
            .build_settlement(thread_id, invoice, &option, note, ctx)
            .await?;
        match result {
            BuildSettlementResult::Settle { artifact } => {
                let v = serde_json::to_value(artifact)?;
                Ok(BuildSettlementErased {
                    action: "settle",
                    artifact: Some(v),
                    termination: None,
                })
            }
            BuildSettlementResult::Terminate { termination } => Ok(BuildSettlementErased {
                action: "terminate",
                artifact: None,
                termination: Some(termination),
            }),
        }
    }

    async fn accept_settlement_erased(
        &self,
        thread_id: &str,
        invoice: Option<&Invoice>,
        artifact_json: &serde_json::Value,
        sender: &str,
        ctx: &ModuleContext,
    ) -> Result<AcceptSettlementErased, RemittanceError> {
        // clone is necessary — from_value consumes the value but we only have a reference
        let artifact: T::SettlementArtifact = serde_json::from_value(artifact_json.clone())?;
        let result = self
            .accept_settlement(thread_id, invoice, &artifact, sender, ctx)
            .await?;
        match result {
            AcceptSettlementResult::Accept { receipt_data } => {
                let receipt_json = match receipt_data {
                    Some(rd) => Some(serde_json::to_value(rd)?),
                    None => None,
                };
                Ok(AcceptSettlementErased {
                    action: "accept",
                    receipt_data: receipt_json,
                    termination: None,
                })
            }
            AcceptSettlementResult::Terminate { termination } => Ok(AcceptSettlementErased {
                action: "terminate",
                receipt_data: None,
                termination: Some(termination),
            }),
        }
    }

    async fn process_receipt_erased(
        &self,
        thread_id: &str,
        invoice: Option<&Invoice>,
        receipt_json: &serde_json::Value,
        sender: &str,
        ctx: &ModuleContext,
    ) -> Result<(), RemittanceError> {
        // clone is necessary — from_value consumes the value but we only have a reference
        let receipt_data: T::ReceiptData = serde_json::from_value(receipt_json.clone())?;
        self.process_receipt(thread_id, invoice, &receipt_data, sender, ctx)
            .await
    }

    async fn process_termination_erased(
        &self,
        thread_id: &str,
        invoice: Option<&Invoice>,
        settlement: Option<&Settlement>,
        termination: &Termination,
        sender: &str,
        ctx: &ModuleContext,
    ) -> Result<(), RemittanceError> {
        // settlement is Option<&Settlement> — concrete type, no erasure needed
        self.process_termination(thread_id, invoice, settlement, termination, sender, ctx)
            .await
    }
}

// Tests are in tests/remittance_module.rs (integration test file) to avoid
// pre-existing wallet module compilation errors in the lib test target.
