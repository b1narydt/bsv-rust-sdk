//! `Stas3Wallet::mint_eac` — wallet-aware EAC issuance wrapper around
//! `factory::build_issue`.
//!
//! Constructs a 2-tx contract+issue flow (see `factory::issue` for the
//! production-parity rationale) where every destination gets an EAC
//! locking script (i.e. one whose `optional_data` carries the EAC schema
//! per `eac::EacFields::to_optional_data`). The wrapper handles:
//!
//! - service-fields assembly from the `freeze_auth_pkh` /
//!   `confiscate_auth_pkh` arguments per the spec §5.2.3 ordering rule
//!   (one entry per set flag bit, low-to-high: bit 0 = FREEZABLE → first
//!   entry; bit 1 = CONFISCATABLE → second entry);
//! - `redemption_pkh` derivation from the issuer's signing key (so callers
//!   don't have to redo Type-42 themselves);
//! - the `IssueDestination::action_data` defaults to `Passive(empty)` —
//!   if you need a non-default initial state, drop down to
//!   `factory::build_issue` directly.

use crate::primitives::hash::hash160;
use crate::wallet::interfaces::{GetPublicKeyArgs, WalletInterface};

use super::super::action_data::ActionData;
use super::super::eac::EacFields;
use super::super::error::Stas3Error;
use super::super::factory::issue::{
    build_issue, IssueDestination, IssueRequest, IssueResult,
};
use super::super::factory::types::{FundingInput, SigningKey};
use super::super::flags::{is_confiscatable, is_freezable};
use super::Stas3Wallet;

impl<W: WalletInterface> Stas3Wallet<W> {
    /// Mint EAC tokens via the production 2-tx contract+issue flow.
    ///
    /// `destinations` is a list of `(owner_pkh, satoshis, eac_fields)`
    /// triples. Each gets an STAS-3 output whose `optional_data` is
    /// `eac_fields.to_optional_data()` and whose initial var2 is
    /// `Passive(empty)`.
    ///
    /// `flags` follows the standard STAS-3 mapping:
    ///   - bit 0 (`FREEZABLE = 0x01`) requires `freeze_auth_pkh =
    ///     Some(...)`; `service_fields[0]` will be set to that pkh.
    ///   - bit 1 (`CONFISCATABLE = 0x02`) requires
    ///     `confiscate_auth_pkh = Some(...)`; the next service-fields
    ///     slot (after the freeze pkh, if any) will be set to that pkh.
    ///
    /// `scheme_metadata` is written into the contract tx's
    /// `OP_FALSE OP_RETURN` annotation (mirrors `scheme.toBytes()` in
    /// the production TS reference).
    ///
    /// `fee_rate_sat_per_kb` matches the TS `feeRate` (default 500).
    ///
    /// The returned `IssueResult` carries both signed transactions; the
    /// caller is responsible for broadcasting the contract tx first
    /// (the issue tx references its outputs).
    #[allow(clippy::too_many_arguments)]
    pub async fn mint_eac(
        &self,
        originator: Option<&str>,
        issuer_signing_key: SigningKey,
        funding_input: FundingInput,
        flags: u8,
        freeze_auth_pkh: Option<[u8; 20]>,
        confiscate_auth_pkh: Option<[u8; 20]>,
        destinations: Vec<([u8; 20], u64, EacFields)>,
        scheme_metadata: Vec<u8>,
        fee_rate_sat_per_kb: u64,
    ) -> Result<IssueResult, Stas3Error> {
        // 1. Service-fields assembly per spec §5.2.3.
        let mut service_fields: Vec<Vec<u8>> = Vec::new();
        if is_freezable(flags) {
            let pkh = freeze_auth_pkh.ok_or_else(|| {
                Stas3Error::InvalidScript(
                    "mint_eac: FREEZABLE flag set but no freeze_auth_pkh provided".into(),
                )
            })?;
            service_fields.push(pkh.to_vec());
        }
        if is_confiscatable(flags) {
            let pkh = confiscate_auth_pkh.ok_or_else(|| {
                Stas3Error::InvalidScript(
                    "mint_eac: CONFISCATABLE flag set but no confiscate_auth_pkh provided"
                        .into(),
                )
            })?;
            service_fields.push(pkh.to_vec());
        }

        // 2. Derive issuer pubkey + pkh (used as redemption_pkh).
        let issuer_triple = match &issuer_signing_key {
            SigningKey::P2pkh(t) => t.clone(),
            SigningKey::Multi { .. } => {
                return Err(Stas3Error::InvalidScript(
                    "mint_eac: multisig issuer is not supported (production parity)".into(),
                ));
            }
        };
        let pk = self
            .wallet
            .get_public_key(
                GetPublicKeyArgs {
                    identity_key: false,
                    protocol_id: Some(issuer_triple.protocol_id.clone()),
                    key_id: Some(issuer_triple.key_id.clone()),
                    counterparty: Some(issuer_triple.counterparty.clone()),
                    privileged: false,
                    privileged_reason: None,
                    for_self: Some(true),
                    seek_permission: None,
                },
                originator,
            )
            .await
            .map_err(|e| Stas3Error::InvalidScript(format!("mint_eac issuer pubkey: {e}")))?;
        let redemption_pkh = hash160(&pk.public_key.to_der());

        // 3. Map (owner, sats, fields) -> IssueDestination.
        let issue_destinations: Vec<IssueDestination> = destinations
            .into_iter()
            .map(|(owner_pkh, satoshis, fields)| IssueDestination {
                owner_pkh,
                action_data: ActionData::Passive(vec![]),
                satoshis,
                optional_data: fields.to_optional_data(),
            })
            .collect();

        // 4. Delegate to the factory.
        build_issue(IssueRequest {
            wallet: &*self.wallet,
            originator,
            issuer_signing_key,
            redemption_pkh,
            flags,
            service_fields,
            scheme_bytes: scheme_metadata,
            funding_input,
            destinations: issue_destinations,
            fee_rate_sat_per_kb,
        })
        .await
    }
}
