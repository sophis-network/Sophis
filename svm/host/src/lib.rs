mod dilithium;
#[cfg(feature = "plonky3")]
pub mod plonky3;
#[cfg(feature = "risc0")]
mod risc0;
mod sha3;

pub use crypto::SophisHostCrypto;

mod crypto {
    use sophis_svm_runtime::HostCrypto;

    use crate::dilithium::verify_dilithium_ml_dsa44;
    #[cfg(feature = "plonky3")]
    use crate::plonky3::verify_plonky3_proof_bytes;
    #[cfg(feature = "risc0")]
    use crate::risc0::verify_risc0_proof_bytes;
    use crate::sha3::sha3_384_hash;

    /// Production crypto backend — ML-DSA-44 (Dilithium) + SHA3-384 + Risc0 verifier + Plonky3 verifier.
    /// Injected into ContractExecutor at node startup.
    pub struct SophisHostCrypto;

    impl HostCrypto for SophisHostCrypto {
        fn verify_dilithium(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
            verify_dilithium_ml_dsa44(pk, msg, sig)
        }

        fn sha3_384(&self, data: &[u8]) -> [u8; 48] {
            sha3_384_hash(data)
        }

        #[cfg(feature = "risc0")]
        fn verify_risc0_proof(&self, seal: &[u8], journal: &[u8], image_id: &[u8]) -> bool {
            verify_risc0_proof_bytes(seal, journal, image_id)
        }

        // Lite build (no `risc0` feature): panic loudly rather than return
        // `false`. A silent `false` would cause feature-on and feature-off
        // nodes to disagree on Phase 3 ZK-Rollup state-update contracts,
        // producing an undetectable consensus fork. Panicking forces
        // operators to rebuild with `--features svm-zk` before running on
        // any network where rollup claims appear (mainnet, testnet). Local
        // Windows dev builds without the feature can still run wallet/RPC.
        #[cfg(not(feature = "risc0"))]
        fn verify_risc0_proof(&self, _seal: &[u8], _journal: &[u8], _image_id: &[u8]) -> bool {
            log::error!(
                "verify_risc0_proof invoked on a build compiled without the `risc0` feature. \
                 This node cannot validate Phase 3 ZK-Rollup state-update contracts and would \
                 fork from the network if it returned a verification result. Rebuild sophisd \
                 with `--features svm-zk` (or use the official Docker image) before \
                 participating in consensus on any network where rollup claims exist."
            );
            panic!(
                "sophis-svm-host built without `risc0` feature cannot verify Risc0 proofs; \
                 rebuild with `--features svm-zk`"
            );
        }

        #[cfg(feature = "plonky3")]
        fn verify_plonky3_proof(&self, proof: &[u8], public_values: &[u8], air_id: &[u8]) -> bool {
            verify_plonky3_proof_bytes(proof, public_values, air_id)
        }

        // Same loud-panic policy as `risc0` (above). Phase 5 ZK-Oracle
        // contracts call `verify_plonky3_proof`; a node without the
        // `plonky3` feature returning a silent `false` would diverge from
        // feature-on nodes and cause an undetectable consensus fork.
        #[cfg(not(feature = "plonky3"))]
        fn verify_plonky3_proof(&self, _proof: &[u8], _public_values: &[u8], _air_id: &[u8]) -> bool {
            log::error!(
                "verify_plonky3_proof invoked on a build compiled without the `plonky3` feature. \
                 This node cannot validate Phase 5 ZK-Oracle journal-binding contracts and would \
                 fork from the network if it returned a verification result. Rebuild sophisd \
                 with `--features svm-zk` (or use the official Docker image) before \
                 participating in consensus on any network where oracle claims exist."
            );
            panic!(
                "sophis-svm-host built without `plonky3` feature cannot verify Plonky3 proofs; \
                 rebuild with `--features svm-zk`"
            );
        }
    }
}
