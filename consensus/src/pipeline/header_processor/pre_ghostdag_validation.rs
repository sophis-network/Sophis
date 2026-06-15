use super::*;
use crate::constants;
use crate::errors::{BlockProcessResult, RuleError};
use crate::model::services::reachability::ReachabilityService;
use crate::model::stores::headers::HeaderStoreReader;
use crate::model::stores::headers_selected_tip::HeadersSelectedTipStoreReader;
use crate::model::stores::statuses::StatusesStoreReader;
use sophis_consensus_core::BlockLevel;
use sophis_consensus_core::blockhash::BlockHashExtensions;
use sophis_consensus_core::blockstatus::BlockStatus::StatusInvalid;
use sophis_consensus_core::header::Header;
use sophis_core::time::unix_now;
use sophis_database::prelude::StoreResultExt;
use sophis_pow::calc_level_from_pow;

impl HeaderProcessor {
    /// Validates the header in isolation including pow check against header declared bits.
    /// Returns the block level as computed from pow state or a rule error if such was encountered
    pub(super) fn validate_header_in_isolation(&self, header: &Header) -> BlockProcessResult<BlockLevel> {
        self.check_header_version(header)?;
        self.check_block_timestamp_in_isolation(header)?;
        self.check_parents_limit(header)?;
        Self::check_parents_not_origin(header)?;
        self.check_pow_and_calc_block_level(header)
    }

    pub(super) fn validate_parent_relations(&self, header: &Header) -> BlockProcessResult<()> {
        self.check_parents_exist(header)?;
        self.check_parents_incest(header)?;
        Ok(())
    }

    fn check_header_version(&self, header: &Header) -> BlockProcessResult<()> {
        if header.version != constants::BLOCK_VERSION {
            return Err(RuleError::WrongBlockVersion(header.version));
        }
        Ok(())
    }

    fn check_block_timestamp_in_isolation(&self, header: &Header) -> BlockProcessResult<()> {
        // Timestamp deviation tolerance is in seconds so we multiply by 1000 to get milliseconds (without BPS dependency)
        let max_block_time = unix_now() + self.timestamp_deviation_tolerance * 1000;
        if header.timestamp > max_block_time {
            return Err(RuleError::TimeTooFarIntoTheFuture(header.timestamp, max_block_time));
        }
        Ok(())
    }

    fn check_parents_limit(&self, header: &Header) -> BlockProcessResult<()> {
        if header.direct_parents().is_empty() {
            return Err(RuleError::NoParents);
        }

        let max_block_parents = self.max_block_parents as usize;
        if header.direct_parents().len() > max_block_parents {
            return Err(RuleError::TooManyParents(header.direct_parents().len(), max_block_parents));
        }

        Ok(())
    }

    fn check_parents_not_origin(header: &Header) -> BlockProcessResult<()> {
        if header.direct_parents().iter().any(|&parent| parent.is_origin()) {
            return Err(RuleError::OriginParent);
        }

        Ok(())
    }

    fn check_parents_exist(&self, header: &Header) -> BlockProcessResult<()> {
        let mut missing_parents = Vec::new();
        for parent in header.direct_parents() {
            match self.statuses_store.read().get(*parent).optional().unwrap() {
                None => missing_parents.push(*parent),
                Some(StatusInvalid) => {
                    return Err(RuleError::InvalidParent(*parent));
                }
                Some(_) => {}
            }
        }
        if !missing_parents.is_empty() {
            return Err(RuleError::MissingParents(missing_parents));
        }
        Ok(())
    }

    fn check_parents_incest(&self, header: &Header) -> BlockProcessResult<()> {
        let parents = header.direct_parents();
        for parent_a in parents.iter() {
            for parent_b in parents.iter() {
                if parent_a == parent_b {
                    continue;
                }

                if self.reachability_service.is_dag_ancestor_of(*parent_a, *parent_b) {
                    return Err(RuleError::InvalidParentsRelation(*parent_a, *parent_b));
                }
            }
        }

        Ok(())
    }

    fn check_pow_and_calc_block_level(&self, header: &Header) -> BlockProcessResult<BlockLevel> {
        // F-34: Bound header.daa_score before building the 256 MB RandomX epoch cache.
        // An attacker flooding distinct-epoch headers forces a new cache rebuild per epoch;
        // this gate limits damage to O(finality_depth / EPOCH_LENGTH) distinct epochs.
        // Skipped when skip_proof_of_work is true (tests use synthetic daa_score values).
        if !self.skip_proof_of_work {
            self.check_daa_score_pre_pow(header)?;
        }
        let state = sophis_pow::State::new(header);
        let (passed, pow) = state.check_pow(header.nonce);
        if passed || self.skip_proof_of_work { Ok(calc_level_from_pow(pow, self.max_block_level)) } else { Err(RuleError::InvalidPoW) }
    }

    fn check_daa_score_pre_pow(&self, header: &Header) -> BlockProcessResult<()> {
        // Soft-fail on store errors — don't turn infrastructure failure into a false rejection.
        let Ok(tip) = self.headers_selected_tip_store.read().get() else {
            return Ok(());
        };
        let Ok(tip_daa) = self.headers_store.get_daa_score(tip.hash) else {
            return Ok(());
        };
        // Allow headers within 22 epochs (~45 056 blocks, ≈ 75 min) behind the tip and 2 epochs
        // ahead. Note: this window is NOT finality_depth (which is ~211 epochs / 12 h); it was
        // chosen to bound the number of distinct epoch caches an attacker can force, not to
        // match the reorg safety horizon. Headers outside this window are physically impossible
        // to validate honestly and are almost certainly from a DoS flood or a deeply-desynchronised peer.
        let min_daa = tip_daa.saturating_sub(sophis_pow::EPOCH_LENGTH * 22);
        let max_daa = tip_daa.saturating_add(sophis_pow::EPOCH_LENGTH * 2);
        if header.daa_score < min_daa || header.daa_score > max_daa {
            return Err(RuleError::DaaScoreOutOfPlausibleRange(header.daa_score, min_daa, max_daa));
        }
        Ok(())
    }
}
