use std::time::Duration;
use tracing::{debug, info, warn};

use crate::{
    components::{block_synchronizer::BlockSynchronizerProgress, consensus::ChainspecConsensusExt},
    effect::{requests::BlockSynchronizerRequest, EffectBuilder, EffectExt, Effects},
    reactor,
    reactor::main_reactor::{MainEvent, MainReactor},
    NodeRng,
};

pub(super) enum ValidateInstruction {
    Do(Duration, Effects<MainEvent>),
    CheckLater(String, Duration),
    NonSwitchBlock,
    KeepUp,
    ShutdownForUpgrade,
    Fatal(String),
}

impl MainReactor {
    pub(super) fn validate_instruction(
        &mut self,
        effect_builder: EffectBuilder<MainEvent>,
        rng: &mut NodeRng,
    ) -> ValidateInstruction {
        let queue_depth = self.contract_runtime.queue_depth();
        if queue_depth > 0 {
            warn!("Validate: should_validate queue_depth {}", queue_depth);
            return ValidateInstruction::CheckLater(
                "allow time for contract runtime execution to occur".to_string(),
                self.control_logic_default_delay.into(),
            );
        }

        match self.block_synchronizer.historical_progress() {
            BlockSynchronizerProgress::Idle => {}
            BlockSynchronizerProgress::Syncing(_, _, _) => {
                return ValidateInstruction::Do(
                    Duration::ZERO,
                    effect_builder.immediately().event(|_| {
                        MainEvent::BlockSynchronizerRequest(BlockSynchronizerRequest::NeedNext)
                    }),
                );
            }
            BlockSynchronizerProgress::Executing(_, _, _) => todo!("error"),
            BlockSynchronizerProgress::Synced(block_hash, height, era_id) => {
                info!(%block_hash, "Executed and marked block complete as validator");
                let switch_blocks = self.storage.read_highest_switch_block_headers(1).unwrap();
                if let Some(switch_block) = switch_blocks.get(0) {
                    self.switch_block = Some(switch_block.clone());
                }
                self.block_accumulator.register_local_tip(height, era_id);
                self.block_synchronizer.purge_historical();
            }
        }

        if self.switch_block.is_none() {
            // validate status is only checked at switch blocks
            return ValidateInstruction::NonSwitchBlock;
        }

        if self.should_shutdown_for_upgrade() {
            return ValidateInstruction::ShutdownForUpgrade;
        }

        match self.create_required_eras(effect_builder, rng) {
            Ok(Some(effects)) => {
                let last_progress = self.consensus.last_progress();
                if last_progress > self.last_progress {
                    self.last_progress = last_progress;
                }
                if effects.is_empty() {
                    ValidateInstruction::CheckLater(
                        "consensus state is up to date".to_string(),
                        self.control_logic_default_delay.into(),
                    )
                } else {
                    ValidateInstruction::Do(Duration::ZERO, effects)
                }
            }
            Ok(None) => ValidateInstruction::KeepUp,
            Err(msg) => ValidateInstruction::Fatal(msg),
        }
    }

    pub(super) fn create_required_eras(
        &mut self,
        effect_builder: EffectBuilder<MainEvent>,
        rng: &mut NodeRng,
    ) -> Result<Option<Effects<MainEvent>>, String> {
        let recent_switch_block_headers = self
            .storage
            .read_highest_switch_block_headers(self.chainspec.number_of_past_switch_blocks_needed())
            .map_err(|err| err.to_string())?;

        let highest_switch_block_header = match recent_switch_block_headers.last() {
            None => {
                debug!(
                    state = %self.state,
                    "create_required_eras: recent_switch_block_headers is empty"
                );
                return Ok(None);
            }
            Some(header) => header,
        };
        debug!(
            state = %self.state,
            era = highest_switch_block_header.era_id().value(),
            block_hash = %highest_switch_block_header.block_hash(),
            height = highest_switch_block_header.height(),
            "highest_switch_block_header"
        );

        if let Some(current_era) = self.consensus.current_era() {
            debug!(state = %self.state,
                era = current_era.value(),
                "consensus current_era");
            if highest_switch_block_header.next_block_era_id() <= current_era {
                return Ok(Some(Effects::new()));
            }
        }

        let highest_era_weights = match highest_switch_block_header.next_era_validator_weights() {
            None => {
                return Err(format!(
                    "{}: highest switch block has no era end: {}",
                    self.state, highest_switch_block_header,
                ));
            }
            Some(weights) => weights,
        };
        if !highest_era_weights.contains_key(self.consensus.public_key()) {
            info!(state = %self.state,"highest_era_weights does not contain signing_public_key");
            return Ok(None);
        }

        if self
            .deploy_buffer
            .have_full_ttl_of_deploys(highest_switch_block_header)
        {
            debug!(state = %self.state,"sufficient deploy TTL awareness to safely participate in consensus");
        } else {
            info!(state = %self.state,"insufficient deploy TTL awareness to safely participate in consensus");
            return Ok(None);
        }

        let era_id = highest_switch_block_header.era_id();
        if self.upgrade_watcher.should_upgrade_after(era_id) {
            info!(state = %self.state, era_id = era_id.value(), "upgrade required after given era");
            return Ok(None);
        }

        let create_required_eras =
            self.consensus
                .create_required_eras(effect_builder, rng, &recent_switch_block_headers);
        match &create_required_eras {
            Some(effects) => {
                if effects.is_empty() {
                    info!(state = %self.state,"create_required_eras is empty");
                } else {
                    info!(state = %self.state,"will attempt to create required eras for consensus");
                }
            }
            None => {
                info!(state = %self.state,"create_required_eras is none");
            }
        }
        Ok(
            create_required_eras
                .map(|effects| reactor::wrap_effects(MainEvent::Consensus, effects)),
        )
    }
}
