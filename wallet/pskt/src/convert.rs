//!
//! Conversion functions for converting between
//! the [`sophis_consensus_client`], [`sophis_consensus_core`]
//! and [`sophis_wallet_pskt`](crate) types.
//!

use crate::error::Error;
use crate::input::{Input, InputBuilder};
use crate::output::{Output, OutputBuilder};
use crate::pskt::{Global, Inner};
use sophis_consensus_client::{Transaction, TransactionInput, TransactionInputInner, TransactionOutput, TransactionOutputInner};
use sophis_consensus_core::tx as cctx;

impl TryFrom<Transaction> for Inner {
    type Error = Error;
    fn try_from(_transaction: Transaction) -> Result<Self, Self::Error> {
        Inner::try_from(cctx::Transaction::from(&_transaction))
    }
}

impl TryFrom<TransactionInput> for Input {
    type Error = Error;
    fn try_from(input: TransactionInput) -> std::result::Result<Input, Self::Error> {
        let TransactionInputInner { previous_outpoint, signature_script: _, sequence: _, sig_op_count, utxo } = &*input.inner();

        let input = InputBuilder::default()
        .utxo_entry(utxo.as_ref().ok_or(Error::MissingUtxoEntry)?.into())
        .previous_outpoint(previous_outpoint.into())
        // .sequence(*sequence)
        // min_time
        // partial_sigs
        // sighash_type
        // redeem_script
        .sig_op_count(*sig_op_count)
        // bip32_derivations
        // final_script_sig
        .build()?;

        Ok(input)
    }
}

impl TryFrom<TransactionOutput> for Output {
    type Error = Error;
    fn try_from(output: TransactionOutput) -> std::result::Result<Output, Self::Error> {
        // Self::Transaction(transaction)

        let TransactionOutputInner { value, script_public_key } = &*output.inner();

        let output = OutputBuilder::default()
        .amount(*value)
        .script_public_key(script_public_key.clone())
        // .redeem_script
        // .bip32_derivations
        // .proprietaries
        // .unknowns
        .build()?;

        Ok(output)
    }
}

impl TryFrom<(cctx::Transaction, Vec<(&cctx::TransactionInput, &cctx::UtxoEntry)>)> for Inner {
    type Error = Error; // Define your error type

    fn try_from(
        (transaction, populated_inputs): (cctx::Transaction, Vec<(&cctx::TransactionInput, &cctx::UtxoEntry)>),
    ) -> Result<Self, Self::Error> {
        let inputs: Result<Vec<Input>, Self::Error> = populated_inputs
            .into_iter()
            .map(|(input, utxo)| {
                InputBuilder::default()
                    .utxo_entry(utxo.to_owned().clone())
                    .previous_outpoint(input.previous_outpoint)
                    .sig_op_count(input.sig_op_count)
                    .build()
                    .map_err(Error::TxToInnerConversionInputBuildingError)
                // Handle the error
            })
            .collect::<Result<_, _>>();

        let outputs: Result<Vec<Output>, Self::Error> = transaction
            .outputs
            .iter()
            .map(|output| {
                Output::try_from(TransactionOutput::from(output.to_owned())).map_err(|e| Error::TxToInnerConversionError(Box::new(e)))
            })
            .collect::<Result<_, _>>();

        Ok(Inner { global: Global::default(), inputs: inputs?, outputs: outputs? })
    }
}

impl TryFrom<cctx::Transaction> for Inner {
    type Error = Error;
    fn try_from(transaction: cctx::Transaction) -> Result<Self, self::Error> {
        let inputs = transaction
            .inputs
            .iter()
            .map(|input| {
                Input::try_from(TransactionInput::from(input.to_owned())).map_err(|e| Error::TxToInnerConversionError(Box::new(e)))
            })
            .collect::<Result<_, _>>()?;

        let outputs = transaction
            .outputs
            .iter()
            .map(|output| {
                Output::try_from(TransactionOutput::from(output.to_owned())).map_err(|e| Error::TxToInnerConversionError(Box::new(e)))
            })
            .collect::<Result<_, _>>()?;

        Ok(Inner { global: Global::default(), inputs, outputs })
    }
}

// Audit category-D coverage closure (Session 16, 2026-05-16):
// `convert.rs` was at 0% line coverage. These exercise the TryFrom
// conversion impls via the `cctx::*` types (which are constructible
// without the wasm-bindgen UtxoEntryReference): the outputs-only and
// populated-inputs Inner paths, the standalone Output conversion, the
// `MissingUtxoEntry` error path, and the client-Transaction entry point.
// Bounded residual: the `utxo: Some(_)` success branch of
// `TryFrom<client::TransactionInput> for Input` needs a
// `UtxoEntryReference` (wasm-oriented, Arc<client::UtxoEntry>) — the
// equivalent InputBuilder-with-utxo success is covered through the
// populated-inputs path instead; same architectural cost class as the
// `wasm/*` exclusion.
#[cfg(test)]
mod tests {
    use super::*;
    use sophis_consensus_core::tx::{ScriptPublicKey, ScriptVec, TransactionId, TransactionOutpoint};

    fn spk(b: u8) -> ScriptPublicKey {
        ScriptPublicKey::new(0, ScriptVec::from_slice(&[b]))
    }

    fn cctx_out(value: u64, b: u8) -> cctx::TransactionOutput {
        cctx::TransactionOutput { value, script_public_key: spk(b) }
    }

    fn cctx_in(txid: u8, index: u32) -> cctx::TransactionInput {
        cctx::TransactionInput {
            previous_outpoint: TransactionOutpoint::new(TransactionId::from_slice(&[txid; 32]), index),
            signature_script: vec![],
            sequence: 0,
            sig_op_count: 1,
        }
    }

    fn cctx_tx(ins: Vec<cctx::TransactionInput>, outs: Vec<cctx::TransactionOutput>) -> cctx::Transaction {
        cctx::Transaction::new(0, ins, outs, 0, Default::default(), 0, vec![])
    }

    #[test]
    fn output_tryfrom_client_output() {
        let o = Output::try_from(TransactionOutput::new(500, spk(7))).unwrap();
        assert_eq!(o.amount, 500);
        assert_eq!(o.script_public_key, spk(7));
    }

    #[test]
    fn input_tryfrom_missing_utxo_errors() {
        // client::TransactionInput::from(cctx input) carries utxo = None.
        let ci = TransactionInput::from(cctx_in(1, 0));
        assert!(matches!(Input::try_from(ci), Err(Error::MissingUtxoEntry)));
    }

    #[test]
    fn inner_tryfrom_cctx_outputs_only() {
        // No inputs → no MissingUtxoEntry; pure output mapping path.
        let tx = cctx_tx(vec![], vec![cctx_out(100, 1), cctx_out(200, 2)]);
        let inner = Inner::try_from(tx).unwrap();
        assert_eq!(inner.inputs.len(), 0);
        assert_eq!(inner.outputs.len(), 2);
        assert_eq!(inner.outputs[1].amount, 200);
    }

    #[test]
    fn inner_tryfrom_cctx_with_populated_inputs() {
        let tx = cctx_tx(vec![cctx_in(9, 0)], vec![cctx_out(300, 3)]);
        // Keep the borrowed input/utxo alive independently of the moved tx.
        let ins = [cctx_in(9, 0)];
        let utxos = [cctx::UtxoEntry::new(750, spk(3), 0, false)];
        let populated: Vec<(&cctx::TransactionInput, &cctx::UtxoEntry)> = vec![(&ins[0], &utxos[0])];
        let inner = Inner::try_from((tx, populated)).unwrap();
        assert_eq!(inner.inputs.len(), 1);
        assert_eq!(inner.inputs[0].utxo_entry.as_ref().unwrap().amount, 750);
        assert_eq!(inner.outputs.len(), 1);
        assert_eq!(inner.outputs[0].amount, 300);
    }

    #[test]
    fn inner_tryfrom_client_transaction() {
        // Covers `TryFrom<client::Transaction> for Inner` (delegates to
        // the cctx path). Outputs-only so the input conversion does not
        // hit MissingUtxoEntry.
        let client_tx = Transaction::from(cctx_tx(vec![], vec![cctx_out(42, 4)]));
        let inner = Inner::try_from(client_tx).unwrap();
        assert_eq!(inner.inputs.len(), 0);
        assert_eq!(inner.outputs.len(), 1);
        assert_eq!(inner.outputs[0].amount, 42);
    }
}
