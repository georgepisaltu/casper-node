use std::{sync::Arc, time::Duration};

use derive_more::{Display, From};
use prometheus::Registry;
use rand::RngCore;
use serde::Serialize;
use tempfile::TempDir;

use casper_execution_engine::core::engine_state::ExecutableDeployItem;
use casper_types::{runtime_args, EraId, PublicKey, RuntimeArgs, SecretKey, TimeDiff, U512};

use super::*;
use crate::{
    components::{
        consensus::EraReport,
        network::Identity as NetworkIdentity,
        storage::{self, Storage},
    },
    effect::announcements::{ContractRuntimeAnnouncement, ControlAnnouncement, FatalAnnouncement},
    protocol::Message,
    reactor::{self, EventQueueHandle, ReactorEvent, Runner},
    testing::{self, network::NetworkedReactor, ConditionCheckReactor},
    types::{BlockPayload, Chainspec, ChainspecRawBytes, Deploy, DeployHashWithApprovals},
    utils::{Loadable, WithDir, RESOURCES_PATH},
    NodeRng,
};

const RECENT_ERA_COUNT: u64 = 5;
const MAX_TTL: TimeDiff = TimeDiff::from_seconds(86400);
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Top-level event for the reactor.
#[derive(Debug, From, Serialize, Display)]
#[must_use]
enum Event {
    #[from]
    ContractRuntime(super::Event),
    #[from]
    ContractRuntimeRequest(ContractRuntimeRequest),
    #[from]
    ContractRuntimeAnnouncement(ContractRuntimeAnnouncement),
    #[from]
    Storage(storage::Event),
    #[from]
    StorageRequest(StorageRequest),
    #[from]
    MetaBlockAnnouncement(MetaBlockAnnouncement),
}

impl ReactorEvent for Event {
    fn is_control(&self) -> bool {
        false
    }

    fn try_into_control(self) -> Option<ControlAnnouncement> {
        None
    }
}

trait Unhandled {}

impl<T: Unhandled> From<T> for Event {
    fn from(_: T) -> Self {
        unimplemented!("not handled in contract runtime tests")
    }
}

impl Unhandled for ControlAnnouncement {}
impl Unhandled for FatalAnnouncement {}
impl Unhandled for NetworkRequest<Message> {}
impl Unhandled for UnexecutedBlockAnnouncement {}

struct Reactor {
    storage: Storage,
    contract_runtime: ContractRuntime,
    _storage_tempdir: TempDir,
}

impl reactor::Reactor for Reactor {
    type Event = Event;
    type Config = Config;
    type Error = ConfigError;

    fn new(
        config: Self::Config,
        chainspec: Arc<Chainspec>,
        _chainspec_raw_bytes: Arc<ChainspecRawBytes>,
        _network_identity: NetworkIdentity,
        registry: &Registry,
        _event_queue: EventQueueHandle<Self::Event>,
        _rng: &mut NodeRng,
    ) -> Result<(Self, Effects<Self::Event>), Self::Error> {
        let (storage_config, storage_tempdir) = storage::Config::default_for_tests();
        let storage_withdir = WithDir::new(storage_tempdir.path(), storage_config);
        let storage = Storage::new(
            &storage_withdir,
            None,
            chainspec.protocol_version(),
            EraId::default(),
            "test",
            MAX_TTL,
            RECENT_ERA_COUNT,
            Some(registry),
            false,
        )
        .unwrap();

        let contract_runtime = ContractRuntime::new(
            chainspec.protocol_version(),
            storage.root_path(),
            &config,
            chainspec.wasm_config,
            chainspec.system_costs_config,
            chainspec.core_config.max_associated_keys,
            chainspec.core_config.max_runtime_call_stack_height,
            chainspec.core_config.minimum_delegation_amount,
            chainspec.protocol_config.activation_point,
            chainspec.core_config.prune_batch_size,
            chainspec.core_config.strict_argument_checking,
            chainspec.core_config.vesting_schedule_period.millis(),
            Some(chainspec.core_config.max_delegators_per_validator),
            registry,
        )?;

        let reactor = Reactor {
            storage,
            contract_runtime,
            _storage_tempdir: storage_tempdir,
        };

        Ok((reactor, Effects::new()))
    }

    fn dispatch_event(
        &mut self,
        effect_builder: EffectBuilder<Self::Event>,
        rng: &mut NodeRng,
        event: Event,
    ) -> Effects<Self::Event> {
        trace!(?event);
        match event {
            Event::ContractRuntime(event) => reactor::wrap_effects(
                Event::ContractRuntime,
                self.contract_runtime
                    .handle_event(effect_builder, rng, event),
            ),
            Event::ContractRuntimeRequest(req) => reactor::wrap_effects(
                Event::ContractRuntime,
                self.contract_runtime
                    .handle_event(effect_builder, rng, req.into()),
            ),
            Event::ContractRuntimeAnnouncement(announcement) => {
                info!("{announcement}");
                Effects::new()
            }
            Event::Storage(event) => reactor::wrap_effects(
                Event::Storage,
                self.storage.handle_event(effect_builder, rng, event),
            ),
            Event::StorageRequest(req) => reactor::wrap_effects(
                Event::Storage,
                self.storage.handle_event(effect_builder, rng, req.into()),
            ),
            Event::MetaBlockAnnouncement(announcement) => {
                info!("{announcement}");
                Effects::new()
            }
        }
    }
}

impl NetworkedReactor for Reactor {}

/// Schedule the given block and its deploys to be executed by the contract runtime.
fn execute_block(
    finalized_block: FinalizedBlock,
    deploys: Vec<Deploy>,
) -> impl FnOnce(EffectBuilder<Event>) -> Effects<Event> {
    |effect_builder| {
        effect_builder
            .enqueue_block_for_execution(finalized_block, deploys, MetaBlockState::new())
            .ignore()
    }
}

/// A function to be used a condition check, indicating that execution has started.
fn execution_started(event: &Event) -> bool {
    matches!(
        event,
        Event::ContractRuntimeRequest(ContractRuntimeRequest::EnqueueBlockForExecution { .. })
    )
}

/// A function to be used a condition check, indicating that execution has completed.
fn execution_completed(event: &Event) -> bool {
    matches!(event, Event::MetaBlockAnnouncement(_))
}

#[tokio::test]
async fn should_not_set_shared_pre_state_to_lower_block_height() {
    testing::init_logging();

    let config = Config {
        max_global_state_size: Some(100 * 1024 * 1024),
        ..Config::default()
    };
    let (chainspec, chainspec_raw_bytes) =
        <(Chainspec, ChainspecRawBytes)>::from_resources("local");
    let chainspec = Arc::new(chainspec);
    let chainspec_raw_bytes = Arc::new(chainspec_raw_bytes);

    let mut rng = crate::new_rng();
    let rng = &mut rng;

    let mut runner: Runner<ConditionCheckReactor<Reactor>> = Runner::new(
        config,
        Arc::clone(&chainspec),
        Arc::clone(&chainspec_raw_bytes),
        rng,
    )
    .await
    .unwrap();

    // Commit genesis to set up initial global state.
    let post_commit_genesis_state_hash = runner
        .reactor()
        .inner()
        .contract_runtime
        .commit_genesis(chainspec.as_ref(), chainspec_raw_bytes.as_ref())
        .unwrap()
        .post_state_hash;

    let initial_pre_state = ExecutionPreState::new(
        0,
        post_commit_genesis_state_hash,
        BlockHash::default(),
        Digest::default(),
    );
    runner
        .reactor_mut()
        .inner_mut()
        .contract_runtime
        .set_initial_state(initial_pre_state);

    // Create the genesis immediate switch block.
    let block_0 = FinalizedBlock::new(
        BlockPayload::default(),
        Some(EraReport::default()),
        Timestamp::now(),
        EraId::new(0),
        0,
        PublicKey::System,
    );

    runner
        .process_injected_effects(execute_block(block_0, vec![]))
        .await;
    runner
        .crank_until(rng, execution_completed, TEST_TIMEOUT)
        .await;

    // Create the first block of era 1.
    let block_1 = FinalizedBlock::new(
        BlockPayload::default(),
        None,
        Timestamp::now(),
        EraId::new(1),
        1,
        PublicKey::System,
    );
    runner
        .process_injected_effects(execute_block(block_1, vec![]))
        .await;
    runner
        .crank_until(rng, execution_completed, TEST_TIMEOUT)
        .await;

    // Check that the next block height expected by the contract runtime is 2.
    assert_eq!(
        runner
            .reactor()
            .inner()
            .contract_runtime
            .execution_pre_state
            .lock()
            .unwrap()
            .next_block_height,
        2
    );

    // Prepare to create a block which will take a while to execute, i.e. loaded with many deploys
    // transferring from node-1's main account to new random public keys.
    let node_1_secret_key = SecretKey::from_file(
        RESOURCES_PATH
            .join("local")
            .join("secret_keys")
            .join("node-1.pem"),
    )
    .unwrap();
    let timestamp = Timestamp::now();
    let ttl = TimeDiff::from_seconds(100);
    let gas_price = 1;
    let chain_name = chainspec.network_config.name.clone();
    let payment = ExecutableDeployItem::ModuleBytes {
        module_bytes: Bytes::new(),
        args: runtime_args! {
          "amount" => U512::from(chainspec.system_costs_config.wasmless_transfer_cost()),
        },
    };

    let deploys: Vec<Deploy> = std::iter::repeat_with(|| {
        let target_public_key = PublicKey::random(rng);
        let session = ExecutableDeployItem::Transfer {
            args: runtime_args! {
              "amount" => U512::from(chainspec.deploy_config.native_transfer_minimum_motes),
              "target" => target_public_key,
              "id" => Some(9_u64),
            },
        };
        Deploy::new(
            timestamp,
            ttl,
            gas_price,
            vec![],
            chain_name.clone(),
            payment.clone(),
            session,
            &node_1_secret_key,
            None,
        )
    })
    .take(200)
    .collect();
    let block_payload = BlockPayload::new(
        vec![],
        deploys.iter().map(DeployHashWithApprovals::from).collect(),
        vec![],
        true,
    );
    let block_2 = FinalizedBlock::new(
        block_payload,
        None,
        Timestamp::now(),
        EraId::new(1),
        2,
        PublicKey::System,
    );
    runner
        .process_injected_effects(execute_block(block_2, deploys))
        .await;

    // Crank until execution is scheduled.
    runner
        .crank_until(rng, execution_started, TEST_TIMEOUT)
        .await;

    // While executing this block, set the execution pre-state to a later block (as if we had sync
    // leaped and skipped ahead).
    let next_block_height = 9;
    tokio::time::sleep(Duration::from_millis(50)).await;
    runner
        .reactor_mut()
        .inner_mut()
        .contract_runtime
        .set_initial_state(ExecutionPreState::new(
            next_block_height,
            Digest::hash(rng.next_u64().to_le_bytes()),
            BlockHash::random(rng),
            Digest::hash(rng.next_u64().to_le_bytes()),
        ));

    runner
        .crank_until(rng, execution_completed, TEST_TIMEOUT)
        .await;

    // Check that the next block height expected by the contract runtime is `next_block_height` and
    // not 3.
    assert_eq!(
        runner
            .reactor()
            .inner()
            .contract_runtime
            .execution_pre_state
            .lock()
            .unwrap()
            .next_block_height,
        next_block_height
    );
}
