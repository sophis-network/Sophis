use crate::common::{
    client::ListeningClient,
    client_notify::ChannelNotify,
    daemon::Daemon,
    utils::{fetch_spendable_utxos, generate_tx, mine_block, wait_for},
};
use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, ml_dsa_44};
use sophis_addresses::Address;
use sophis_alloc::init_allocator_with_default_settings;
use sophis_consensus::params::SIMNET_PARAMS;
use sophis_consensus_core::header::Header;
use sophis_consensusmanager::ConsensusManager;
use sophis_core::{task::runtime::AsyncRuntime, trace};
use sophis_grpc_client::GrpcClient;
use sophis_notify::scope::{BlockAddedScope, UtxosChangedScope, VirtualDaaScoreChangedScope};
use sophis_rpc_core::{Notification, RpcTransactionId, api::rpc::RpcApi};
use sophis_txscript::{pay_to_address_script, standard::dilithium_address};
use sophisd_lib::args::Args;
use std::{sync::Arc, time::Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn daemon_sanity_test() {
    init_allocator_with_default_settings();
    sophis_core::log::try_init_logger("INFO");

    // let total_fd_limit =  sophis_utils::fd_budget::get_limit() / 2 - 128;
    let total_fd_limit = 10;
    let mut sophisd1 = Daemon::new_random(total_fd_limit);
    let rpc_client1 = sophisd1.start().await;
    assert!(rpc_client1.handle_message_id() && rpc_client1.handle_stop_notify(), "the client failed to collect server features");

    let mut sophisd2 = Daemon::new_random(total_fd_limit);
    let rpc_client2 = sophisd2.start().await;
    assert!(rpc_client2.handle_message_id() && rpc_client2.handle_stop_notify(), "the client failed to collect server features");

    tokio::time::sleep(Duration::from_secs(1)).await;
    rpc_client1.disconnect().await.unwrap();
    drop(rpc_client1);
    sophisd1.shutdown();

    rpc_client2.disconnect().await.unwrap();
    drop(rpc_client2);
    sophisd2.shutdown();
}

/// Two-daemon mining + block-relay smoke test. Spawns two `Daemon`s in
/// simnet, peers daemon-2 → daemon-1, mines 10 blocks via RPC on daemon-1,
/// asserts daemon-2 received all 10 via the v7 BlockRelay flow.
///
/// Audit/F-8 (Session 5, 2026-05-14): the `#[ignore]` with "depends on
/// legacy signing path" was **stale** — the test uses
/// `sophis_addresses::Version::PubKeyDilithium` (line above) and the
/// mining path goes through `submit_block` (no transaction signing
/// involved). Verified locally in release: 1 passed / 0 failed / 7.16 s
/// wall. Un-ignored to exercise the IBD + BlockRelay flow paths flagged
/// in F-8 (audit/AUDIT_REPORT.md §2 F-8) as 0% coverage. This is the
/// first cargo-level test that drives 2 sophisd processes through real
/// p2p relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn daemon_mining_test() {
    init_allocator_with_default_settings();
    sophis_core::log::try_init_logger("INFO");

    let args = Args {
        simnet: true,
        unsafe_rpc: true,
        enable_unsynced_mining: true,
        disable_upnp: true, // UPnP registration might take some time and is not needed for this test
        ..Default::default()
    };
    // let total_fd_limit = sophis_utils::fd_budget::get_limit() / 2 - 128;
    let total_fd_limit = 10;

    let mut sophisd1 = Daemon::new_random_with_args(args.clone(), total_fd_limit);
    let mut sophisd2 = Daemon::new_random_with_args(args, total_fd_limit);
    let rpc_client1 = sophisd1.start().await;
    let rpc_client2 = sophisd2.start().await;

    rpc_client2.add_peer(format!("127.0.0.1:{}", sophisd1.p2p_port).try_into().unwrap(), true).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await; // Let it connect
    assert_eq!(rpc_client2.get_connected_peer_info().await.unwrap().peer_info.len(), 1);

    let (sender, event_receiver) = async_channel::unbounded();
    rpc_client1.start(Some(Arc::new(ChannelNotify::new(sender)))).await;
    rpc_client1.start_notify(Default::default(), VirtualDaaScoreChangedScope {}.into()).await.unwrap();

    // Mine 10 blocks to daemon #1
    let mut last_block_hash = None;
    for i in 0..10 {
        let template = rpc_client1
            .get_block_template(Address::new(sophisd1.network.into(), sophis_addresses::Version::PubKeyDilithium, &[0; 32]), vec![])
            .await
            .unwrap();
        let header: Header = (&template.block.header).try_into().unwrap();
        last_block_hash = Some(header.hash);
        rpc_client1.submit_block(template.block, false).await.unwrap();

        while let Ok(notification) = match tokio::time::timeout(Duration::from_secs(1), event_receiver.recv()).await {
            Ok(res) => res,
            Err(elapsed) => panic!("expected virtual event before {}", elapsed),
        } {
            match notification {
                Notification::VirtualDaaScoreChanged(msg) if msg.virtual_daa_score == i + 1 => {
                    break;
                }
                Notification::VirtualDaaScoreChanged(msg) if msg.virtual_daa_score > i + 1 => {
                    panic!("DAA score too high for number of submitted blocks")
                }
                Notification::VirtualDaaScoreChanged(_) => {}
                _ => panic!("expected only DAA score notifications"),
            }
        }
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    // Expect the blocks to be relayed to daemon #2
    let dag_info = rpc_client2.get_block_dag_info().await.unwrap();
    assert_eq!(dag_info.block_count, 10);
    assert_eq!(dag_info.sink, last_block_hash.unwrap());

    // Check that acceptance data contains the expected coinbase tx ids
    let vc = rpc_client2
        .get_virtual_chain_from_block(
            sophis_consensus::params::SIMNET_GENESIS.hash, //
            true,
            None,
        )
        .await
        .unwrap();
    assert_eq!(vc.removed_chain_block_hashes.len(), 0);
    assert_eq!(vc.added_chain_block_hashes.len(), 10);
    assert_eq!(vc.accepted_transaction_ids.len(), 10);
    for accepted_txs_pair in vc.accepted_transaction_ids {
        assert_eq!(accepted_txs_pair.accepted_transaction_ids.len(), 1);
    }
}

/// `cargo test --release --package sophis-testing-integration --lib -- daemon_integration_tests::daemon_utxos_propagation_test`
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
/// Two-daemon UTXO propagation smoke test. Mirrors `daemon_mining_test` but
/// goes further: after the syncer receives all coinbase blocks, the test
/// constructs a transaction, broadcasts it, and verifies UTXO/notification
/// propagation across both nodes via the v7 BlockRelay + UtxosChanged flows.
///
/// Audit/F-8 + F-19 (Session 5, 2026-05-14): the original "legacy signing
/// path" TODO was stale. F-19 (helper drift in `common/utils.rs:155`,
/// fixed in this commit) was the first blocker — script-space equivalence
/// now bridges the `PubKeyDilithium` vs canonicalized `ScriptHash` shape
/// gap. With that fix, the test progresses further (line 155 → line 121),
/// but a second wait_for in the propagation phase times out, suggesting a
/// downstream notification or relay issue not captured by F-19. Kept
/// `#[ignore]` with updated rationale; follow-up issue tracked as F-20.
// Audit/F-20 (Session 6, 2026-05-14): un-ignored after generate_tx was
// rewritten to actually Dilithium-sign. Original `#[ignore]` rationale
// ("legacy signing path") was Schnorr-era residue; the real root cause
// surfaced as a strict-mempool rejection of empty signature_script at
// line 308 after F-19 cleared the earlier address-shape assertion.
async fn daemon_utxos_propagation_test() {
    #[cfg(feature = "heap")]
    let _profiler = dhat::Profiler::builder().file_name("sophis-testing-integration-heap.json").build();

    sophis_core::log::try_init_logger(
        "INFO,sophis_testing_integration=trace,sophis_notify=debug,sophis_rpc_core=debug,sophis_grpc_client=debug",
    );

    let args = Args {
        simnet: true,
        unsafe_rpc: true,
        enable_unsynced_mining: true,
        disable_upnp: true, // UPnP registration might take some time and is not needed for this test
        utxoindex: true,
        ..Default::default()
    };
    let total_fd_limit = 10;

    let coinbase_maturity = SIMNET_PARAMS.coinbase_maturity();
    let mut sophisd1 = Daemon::new_random_with_args(args.clone(), total_fd_limit);
    let mut sophisd2 = Daemon::new_random_with_args(args, total_fd_limit);
    let rpc_client1 = sophisd1.start().await;
    let rpc_client2 = sophisd2.start().await;

    // Let rpc_client1 receive virtual DAA score changed notifications
    let (sender1, event_receiver1) = async_channel::unbounded();
    rpc_client1.start(Some(Arc::new(ChannelNotify::new(sender1)))).await;
    rpc_client1.start_notify(Default::default(), VirtualDaaScoreChangedScope {}.into()).await.unwrap();

    // Connect sophisd2 to sophisd1
    rpc_client2.add_peer(format!("127.0.0.1:{}", sophisd1.p2p_port).try_into().unwrap(), true).await.unwrap();
    let check_client = rpc_client2.clone();
    wait_for(
        50,
        20,
        move || {
            async fn peer_connected(client: GrpcClient) -> bool {
                client.get_connected_peer_info().await.unwrap().peer_info.len() == 1
            }
            Box::pin(peer_connected(check_client.clone()))
        },
        "the nodes did not connect to each other",
    )
    .await;

    // Generate a real Dilithium-2 keypair so the miner address resolves to a
    // payload that we can later spend. The arbitrary `[1u8; 32]` payload of
    // the pre-F-20 test produced an address whose P2SH redeem-script preimage
    // is computationally infeasible to derive, so any spend attempt failed at
    // mempool validation.
    //
    // Deterministic randomness keeps the test reproducible; SK/VK derivation
    // is pure given the seed bytes.
    let mut randomness = [0u8; KEY_GENERATION_RANDOMNESS_SIZE];
    randomness.iter_mut().enumerate().for_each(|(i, b)| *b = (i as u8).wrapping_mul(7).wrapping_add(13));
    let keypair = ml_dsa_44::generate_key_pair(randomness);
    let mut miner_sk = [0u8; 2560];
    let mut miner_vk = [0u8; 1312];
    miner_sk.copy_from_slice(keypair.signing_key.as_ref());
    miner_vk.copy_from_slice(keypair.verification_key.as_ref());

    // Mining address derived from the real VK (Blake2b-256(redeem_script)).
    let miner_address = dilithium_address(&miner_vk, sophisd1.network.into()).expect("dilithium_address");
    let miner_spk = pay_to_address_script(&miner_address);

    // User address — destination only, never spent in this test, so a fixed
    // payload is fine (the resulting UTXO is locked to a P2SH script whose
    // redeem-script preimage is unknown, but the test only checks arrival).
    let user_address = Address::new(sophisd1.network.into(), sophis_addresses::Version::PubKeyDilithium, &[2u8; 32]);

    // Some dummy non-monitored address
    let blank_address = Address::new(sophisd1.network.into(), sophis_addresses::Version::PubKeyDilithium, &[0; 32]);

    // Mine 1000 blocks to daemon #1
    let initial_blocks = coinbase_maturity;
    let mut last_block_hash = None;
    for i in 0..initial_blocks {
        let template = rpc_client1.get_block_template(miner_address.clone(), vec![]).await.unwrap();
        let header: Header = (&template.block.header).try_into().unwrap();
        last_block_hash = Some(header.hash);
        rpc_client1.submit_block(template.block, false).await.unwrap();

        while let Ok(notification) = match tokio::time::timeout(Duration::from_secs(1), event_receiver1.recv()).await {
            Ok(res) => res,
            Err(elapsed) => panic!("expected virtual event before {}", elapsed),
        } {
            match notification {
                Notification::VirtualDaaScoreChanged(msg) if msg.virtual_daa_score == i + 1 => {
                    break;
                }
                Notification::VirtualDaaScoreChanged(msg) if msg.virtual_daa_score > i + 1 => {
                    panic!("DAA score too high for number of submitted blocks")
                }
                Notification::VirtualDaaScoreChanged(_) => {}
                _ => panic!("expected only DAA score notifications"),
            }
        }
    }

    // Audit/F-20 (Session 6, 2026-05-14): bumped from 50ms × 20 (= 1s) to
    // 100ms × 600 (= 60s). The original budget was set for the Schnorr-era
    // SIMNET when coinbase_maturity was small; with the current 10-BPS SIMNET
    // params (= 1000 blocks) daemon-2 needs ~30 s of relay catch-up under
    // workspace contention.
    let check_client = rpc_client2.clone();
    wait_for(
        100,
        600,
        move || {
            async fn daa_score_reached(client: GrpcClient) -> bool {
                let virtual_daa_score = client.get_server_info().await.unwrap().virtual_daa_score;
                trace!("Virtual DAA score: {}", virtual_daa_score);
                virtual_daa_score == SIMNET_PARAMS.coinbase_maturity()
            }
            Box::pin(daa_score_reached(check_client.clone()))
        },
        "the nodes did not add and relay all the initial blocks",
    )
    .await;

    // Expect the blocks to be relayed to daemon #2
    let dag_info = rpc_client2.get_block_dag_info().await.unwrap();
    assert_eq!(dag_info.block_count, initial_blocks);
    assert_eq!(dag_info.sink, last_block_hash.unwrap());

    // Check that acceptance data contains the expected coinbase tx ids
    let vc = rpc_client2.get_virtual_chain_from_block(sophis_consensus::params::SIMNET_GENESIS.hash, true, None).await.unwrap();
    assert_eq!(vc.removed_chain_block_hashes.len(), 0);
    assert_eq!(vc.added_chain_block_hashes.len() as u64, initial_blocks);
    assert_eq!(vc.accepted_transaction_ids.len() as u64, initial_blocks);
    for accepted_txs_pair in vc.accepted_transaction_ids {
        assert_eq!(accepted_txs_pair.accepted_transaction_ids.len(), 1);
    }

    // Create a multi-listener RPC client on each node...
    let mut clients = vec![ListeningClient::connect(&sophisd2).await, ListeningClient::connect(&sophisd1).await];

    // ...and subscribe each to some notifications
    for x in clients.iter_mut() {
        x.start_notify(BlockAddedScope {}.into()).await.unwrap();
        x.start_notify(UtxosChangedScope::new(vec![miner_address.clone(), user_address.clone()]).into()).await.unwrap();
        x.start_notify(VirtualDaaScoreChangedScope {}.into()).await.unwrap();
    }

    // Mine some extra blocks so the latest miner reward is added to its balance and some UTXOs reach maturity
    const EXTRA_BLOCKS: usize = 10;
    for _ in 0..EXTRA_BLOCKS {
        mine_block(blank_address.clone(), &rpc_client1, &clients).await;
    }

    // Check the balance of the miner address
    let miner_balance = rpc_client2.get_balance_by_address(miner_address.clone()).await.unwrap();
    assert_eq!(miner_balance, initial_blocks * SIMNET_PARAMS.pre_deflationary_phase_base_subsidy);
    let miner_balance = rpc_client1.get_balance_by_address(miner_address.clone()).await.unwrap();
    assert_eq!(miner_balance, initial_blocks * SIMNET_PARAMS.pre_deflationary_phase_base_subsidy);

    // Get the miner UTXOs
    let utxos = fetch_spendable_utxos(&rpc_client1, miner_address.clone(), coinbase_maturity).await;
    assert_eq!(utxos.len(), EXTRA_BLOCKS - 1);
    for utxo in utxos.iter() {
        assert!(utxo.1.is_coinbase);
        assert_eq!(utxo.1.amount, SIMNET_PARAMS.pre_deflationary_phase_base_subsidy);
        assert_eq!(utxo.1.script_public_key, miner_spk);
    }

    // Drain UTXOs and Virtual DAA score changed notification channels
    clients.iter().for_each(|x| x.utxos_changed_listener().unwrap().drain());
    clients.iter().for_each(|x| x.virtual_daa_score_changed_listener().unwrap().drain());

    // Spend some coins - sending funds from miner address to user address
    // The transaction here is later used to verify utxo return address RPC
    const NUMBER_INPUTS: u64 = 2;
    const NUMBER_OUTPUTS: u64 = 2;
    const TX_AMOUNT: u64 = SIMNET_PARAMS.pre_deflationary_phase_base_subsidy * (NUMBER_INPUTS * 5 - 1) / 5;
    let transaction = generate_tx(&utxos[0..NUMBER_INPUTS as usize], TX_AMOUNT, NUMBER_OUTPUTS, &user_address, &miner_sk, &miner_vk);
    rpc_client1.submit_transaction((&transaction).into(), false).await.unwrap();

    // Audit/F-20 (Session 6, 2026-05-14): bumped from 50ms × 20 (= 1s) to
    // 100ms × 100 (= 10s). Mempool indexer can lag the submit return path
    // under workspace contention.
    let check_client = rpc_client1.clone();
    let transaction_id = transaction.id();
    wait_for(
        100,
        100,
        move || {
            async fn transaction_in_mempool(client: GrpcClient, transaction_id: RpcTransactionId) -> bool {
                let entry = client.get_mempool_entry(transaction_id, false, false).await;
                entry.is_ok()
            }
            Box::pin(transaction_in_mempool(check_client.clone(), transaction_id))
        },
        "the transaction was not added to the mempool",
    )
    .await;

    mine_block(blank_address.clone(), &rpc_client1, &clients).await;

    // Audit/F-20 (Session 6, 2026-05-14): the indexer canonicalizes
    // addresses to ScriptHash shape; the test's `miner_address` /
    // `user_address` are PubKeyDilithium shape (same script, different
    // version byte). Compare via `pay_to_address_script` for script-space
    // equivalence — same approach as common/utils.rs::fetch_spendable_utxos.
    let miner_spk_check = pay_to_address_script(&miner_address);
    let user_spk_check = pay_to_address_script(&user_address);
    // Check UTXOs changed notifications
    for x in clients.iter() {
        let Notification::UtxosChanged(uc) = x.utxos_changed_listener().unwrap().receiver.recv().await.unwrap() else {
            panic!("wrong notification type")
        };
        assert!(
            uc.removed
                .iter()
                .all(|x| { x.address.is_some() && pay_to_address_script(x.address.as_ref().unwrap()) == miner_spk_check })
        );
        assert!(
            uc.added.iter().all(|x| { x.address.is_some() && pay_to_address_script(x.address.as_ref().unwrap()) == user_spk_check })
        );
        assert_eq!(uc.removed.len() as u64, NUMBER_INPUTS);
        assert_eq!(uc.added.len() as u64, NUMBER_OUTPUTS);
        assert_eq!(
            uc.removed.iter().map(|x| x.utxo_entry.amount).sum::<u64>(),
            SIMNET_PARAMS.pre_deflationary_phase_base_subsidy * NUMBER_INPUTS
        );
        // generate_tx floor-divides; remainder is lost. Compare to the
        // realized aggregate, not the nominal TX_AMOUNT.
        assert_eq!(uc.added.iter().map(|x| x.utxo_entry.amount).sum::<u64>(), (TX_AMOUNT / NUMBER_OUTPUTS) * NUMBER_OUTPUTS);
    }

    // Check the balance of both miner and user addresses
    for x in clients.iter() {
        let miner_balance = x.get_balance_by_address(miner_address.clone()).await.unwrap();
        assert_eq!(miner_balance, (initial_blocks - NUMBER_INPUTS) * SIMNET_PARAMS.pre_deflationary_phase_base_subsidy);

        // Audit/F-20 (Session 6, 2026-05-14): generate_tx allocates
        // `amount / num_outputs` (floor) to each output and discards the
        // remainder, so the user's resulting balance is the rounded-down
        // multiple. The original assertion `== TX_AMOUNT` only held when
        // TX_AMOUNT was a clean multiple of NUMBER_OUTPUTS.
        let expected_user_balance = (TX_AMOUNT / NUMBER_OUTPUTS) * NUMBER_OUTPUTS;
        let user_balance = x.get_balance_by_address(user_address.clone()).await.unwrap();
        assert_eq!(user_balance, expected_user_balance);
    }

    // UTXO Return Address Test
    // Mine another block to accept the transactions from the previous block
    // The tx above is sending from miner address to user address
    mine_block(blank_address.clone(), &rpc_client1, &clients).await;
    let new_utxos = rpc_client1.get_utxos_by_addresses(vec![user_address]).await.unwrap();
    let new_utxo = new_utxos
        .iter()
        .find(|utxo| utxo.outpoint.transaction_id == transaction.id())
        .expect("Did not find a utxo for the tx we just created but expected to");

    let utxo_return_address = rpc_client1
        .get_utxo_return_address(new_utxo.outpoint.transaction_id, new_utxo.utxo_entry.block_daa_score)
        .await
        .expect("We just created the tx and utxo here");

    // Audit/F-20 (Session 6, 2026-05-14): same canonicalization gap as F-19 —
    // the RPC returns the address in canonical ScriptHash shape; compare in
    // script-space.
    assert_eq!(pay_to_address_script(&miner_address), pay_to_address_script(&utxo_return_address));

    // Terminate multi-listener clients
    for x in clients.iter() {
        x.disconnect().await.unwrap();
        x.join().await.unwrap();
    }
}

// The following test runtime parameters are required for a graceful shutdown of the gRPC server
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn daemon_cleaning_test() {
    init_allocator_with_default_settings();
    sophis_core::log::try_init_logger(
        "info,sophis_grpc_core=trace,sophis_grpc_server=trace,sophis_grpc_client=trace,sophis_core=trace",
    );
    let args = Args { devnet: true, ..Default::default() };
    let consensus_manager;
    let async_runtime;
    let core;
    {
        let total_fd_limit = 10;
        let mut sophisd1 = Daemon::new_random_with_args(args, total_fd_limit);
        let dyn_consensus_manager = sophisd1.core.find(ConsensusManager::IDENT).unwrap();
        let dyn_async_runtime = sophisd1.core.find(AsyncRuntime::IDENT).unwrap();
        consensus_manager = Arc::downgrade(&Arc::downcast::<ConsensusManager>(dyn_consensus_manager.arc_any()).unwrap());
        async_runtime = Arc::downgrade(&Arc::downcast::<AsyncRuntime>(dyn_async_runtime.arc_any()).unwrap());
        core = Arc::downgrade(&sophisd1.core);

        let rpc_client1 = sophisd1.start().await;
        rpc_client1.disconnect().await.unwrap();
        drop(rpc_client1);
        sophisd1.shutdown();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(consensus_manager.strong_count(), 0);
    assert_eq!(async_runtime.strong_count(), 0);
    assert_eq!(core.strong_count(), 0);
}
