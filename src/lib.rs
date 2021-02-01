/**
 * Doge DID Method Implementation (did:doge)
 **/

use std::str::FromStr;
use hex;
use bitcoin::{PubkeyHash, PublicKey, SigHashType, Txid};
use bitcoin::blockdata::script::{Script, Error as ScriptError, Builder, Instruction};
use bitcoin::blockdata::opcodes;
use bitcoin::blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut};
use bitcoin::util::key::PrivateKey;
use bitcoin_hashes::sha256d::Hash;
use secp256k1::{Message, Secp256k1};

type PrevOutPointToTxResolver = fn (&OutPoint) -> Option<Transaction>;
type TxResolver = fn (Txid) -> Option<Transaction>;

fn build_p2pkh_script(recv_pkh: &PubkeyHash) -> Script {
    Builder::new()
        .push_opcode(opcodes::all::OP_DUP)
        .push_opcode(opcodes::all::OP_HASH160)
        .push_slice(&recv_pkh[..])
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}

fn build_p2pkh_txout(value: u64, recv_pkh: &PubkeyHash) -> TxOut {
    TxOut { value, script_pubkey: build_p2pkh_script(recv_pkh) }
}

fn is_p2pkh_locking_script_with_pkh(script: &Script, pkh: &PubkeyHash) -> bool {
    if !script.is_p2pkh() {
        return false;
    }
    let expected_asm: Vec<Result<Instruction, ScriptError>> = vec![
        Ok(Instruction::Op(opcodes::all::OP_DUP)),
        Ok(Instruction::Op(opcodes::all::OP_HASH160)),
        Ok(Instruction::PushBytes(pkh)),
        Ok(Instruction::Op(opcodes::all::OP_EQUALVERIFY)),
        Ok(Instruction::Op(opcodes::all::OP_CHECKSIG)),
    ];
    let matching_asm = script.instructions()
        .zip(&expected_asm)
        .filter(|(a, b)| &a == b);
    return expected_asm.len() == matching_asm.count();
}

fn is_p2pkh_unlocking_script(script: &Script) -> bool {
    return try_extract_pubkey_from_p2pkh_unlocking_script(script).is_some();
}

fn extract_pubkey_from_p2pkh_unlocking_script(script: &Script) -> PublicKey {
    return try_extract_pubkey_from_p2pkh_unlocking_script(script).unwrap();
}

fn try_extract_pubkey_from_p2pkh_unlocking_script(script: &Script) -> Option<PublicKey> {
    // Check txin0, grab the pubkey
    let pk_data;
    let mut asm = script.instructions();
    // signature
    match asm.next() {
        // TODO: further verify signature
        Some(Ok(Instruction::PushBytes(_))) => (),
        _ => return None,
    }
    // public key
    match asm.next() {
        Some(Ok(Instruction::PushBytes(d))) => {
            pk_data = d;
        },
        _ => return None,
    }
    // empty
    match asm.next() {
        None => (),
        _ => return None,
    }
    let pk = match PublicKey::from_slice(pk_data) {
        Ok(pk) => pk,
        _ => return None,
    };
    return Some(pk);
}

fn sign_tx(tx: &Transaction, resolve_tx: TxResolver, private_key: &PrivateKey) -> Transaction {
    let po = tx.input[0].previous_output;
    let prev_tx = resolve_tx(po.txid).unwrap();
    let prev_script = &prev_tx.output[po.vout as usize].script_pubkey;
    let sig_hash = tx.signature_hash(0, &prev_script, SigHashType::All as u32);
    let secp256k1 = Secp256k1::new();
    let sig = secp256k1.sign(&Message::from_slice(&sig_hash).unwrap(), &private_key.key);
    let der_sig = sig.serialize_der();
    let mut der_sig_padded = der_sig.to_vec();
    der_sig_padded.extend_from_slice(&[0x01]);
    let script_sig = Builder::new()
        .push_slice(&der_sig_padded)
        .push_slice(&private_key.public_key(&secp256k1).key.serialize())
        .into_script();
    let mut signed_tx = tx.clone();
    signed_tx.input[0].script_sig = script_sig;
    return signed_tx;
}

// Genesis Transaction (GTX)
struct Gtx {}
impl Gtx {
    #[inline]
    pub fn magic_number() -> Vec<u8> {
        let magic_number_str =
            "5468652054696d65732032372f4a616e2f32303231202744756d62204d6f6e657927204973206f6e2047616d6553746f70";
        return hex::decode(magic_number_str).unwrap();
    }
    fn build_txout1_script() -> Script {
        Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice(&Gtx::magic_number())
            .into_script()
    }
    fn build_txout1() -> TxOut {
        TxOut { value: 0, script_pubkey: Gtx::build_txout1_script() }
    }
    fn build_tx(input: &Vec<TxIn>, value: u64, signing_pkh: &PubkeyHash) -> Transaction {
        let txout0 = build_p2pkh_txout(value, signing_pkh);
        let txout1 = Gtx::build_txout1();
        return Transaction {
            input: input.clone(),
            output: vec![txout0, txout1],
            version: 1,
            lock_time: 0,
        };
    }

    // We don't know if it's actually the GTX without querying all the other transactions on the
    // blockchain, so at this point the best we can say is that it's conforming based on the txins
    // and txouts.
    fn is_gtx_conforming(tx: &Transaction) -> bool {
        // Check txin0, try to grab the pubkey
        let pkh;
        match try_extract_pubkey_from_p2pkh_unlocking_script(&tx.input[0].script_sig) {
            Some(pk) => { pkh = pk.pubkey_hash(); },
            None => return false,
        }

        // Check txout0
        match is_p2pkh_locking_script_with_pkh(&tx.output[0].script_pubkey, &pkh) {
            true => (),
            false => return false,
        }

        // Check txout1
        let magic_number = Gtx::magic_number();
        let expected_txout1_asm: Vec<Result<Instruction, ScriptError>> = vec![
            Ok(Instruction::Op(opcodes::all::OP_RETURN)),
            Ok(Instruction::Op(opcodes::all::OP_PUSHBYTES_49)),
            Ok(Instruction::PushBytes(&magic_number)),
        ];
        let txout1_script = &tx.output[1].script_pubkey;
        if !txout1_script.is_provably_unspendable() {
            return false;
        }
        let txout1_matching = txout1_script.instructions()
            .zip(&expected_txout1_asm)
            .filter(|(a, b)| &a == b);
        if expected_txout1_asm.len() != txout1_matching.count() {
            return false;
        }

        return true;
    }

    /*
    fn is_gtx(tx: &Transaction) -> bool { return false; }

    fn next(tx: &Transaction, pop_to_tx: PrevOutPointToTxResolver) -> Option<Transaction> {
        match Gtx::is_gtx(tx) {
            true => pop_to_tx(&OutPoint {
                txid: tx.txid(),
                vout: 0,
            }),
            false => None,
        }
    }
    */
}

// Update Transaction (UTX)
struct Utx {}
impl Utx {
    fn build_txout1_script(service_endpoint_uri: &[u8]) -> Script {
        assert!(service_endpoint_uri.len() <= 79);
        return Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice(service_endpoint_uri)
            .into_script();
    }
    fn build_txout1(service_endpoint_uri: &[u8]) -> TxOut {
        TxOut { value: 0, script_pubkey: Utx::build_txout1_script(service_endpoint_uri) }
    }
    fn build_tx(input: &Vec<TxIn>, value: u64, next_pkh: &PubkeyHash, next_svc: &[u8]) -> Transaction {
        let txout0 = build_p2pkh_txout(value, next_pkh);
        let txout1 = Utx::build_txout1(next_svc);
        return Transaction {
            input: input.clone(),
            output: vec![txout0, txout1],
            version: 1,
            lock_time: 0,
        };
    }

    // We don't know if it's actually a UTX without querying all the other transactions on the
    // blockchain, so at this point the best we can say is that it's conforming based on the txins
    // and txouts.
    fn is_utx_conforming(tx: &Transaction) -> bool {
        // Check txin0
        match is_p2pkh_unlocking_script(&tx.input[0].script_sig) {
            true => (),
            false => return false,
        }

        // Check txout0
        match tx.output[0].script_pubkey.is_p2pkh() {
            true => (),
            false => return false,
        }

        // Check txout1
        let txout1_script = &tx.output[1].script_pubkey;
        if !txout1_script.is_provably_unspendable() {
            return false;
        }
        let mut txout1_asm = txout1_script.instructions();
        // OP_RETURN
        match txout1_asm.next() {
            Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) => (),
            _ => return false,
        }
        // Service Endpoint URI
        match txout1_asm.next() {
            Some(Ok(Instruction::PushBytes(_))) => (),
            _ => return false,
        }
        // empty
        match txout1_asm.next() {
            None => (),
            _ => return false,
        }

        return true;
    }

    /*
    fn is_utx(tx: &Transaction, resolve_tx: TxResolver) -> bool {
        return false;
    }

    fn next(tx: &Transaction, resolve_tx: TxResolver, pop_to_tx: PrevOutPointToTxResolver) -> Option<Transaction> {
        match Utx::is_utx(tx, resolve_tx) {
            true => pop_to_tx(&OutPoint {
                txid: tx.txid(),
                vout: 0,
            }),
            false => None,
        }
    }
    */
}

// Deactivation Transaction (UTX)
struct Dtx {}
impl Dtx {
    fn build_tx(input: &Vec<TxIn>, value: u64, recv_pkh: &PubkeyHash) -> Transaction {
        let txout0 = build_p2pkh_txout(value, recv_pkh);
        return Transaction {
            input: input.clone(),
            output: vec![txout0],
            version: 1,
            lock_time: 0,
        };
    }

    // We don't know if it's actually a DTX without querying all the other transactions on the
    // blockchain, so at this point the best we can say is that it's conforming based on the txins
    // and txouts.
    fn is_dtx_conforming(tx: &Transaction) -> bool {
        // Check txin0
        match is_p2pkh_unlocking_script(&tx.input[0].script_sig) {
            true => (),
            false => return false,
        }

        // Check for no OP_RETURN instructions across txouts
        for txout in tx.output.iter() {
            if txout.script_pubkey.is_provably_unspendable() {
                return false;
            }
        }

        return true;
    }

    /*
    fn is_dtx(tx: &Transaction) -> bool {
        return false;
    }
    */
}

#[cfg(test)]
mod tests {
    use bitcoin::{blockdata::script::{Script, Builder, Instruction}, consensus::Encodable};
    use bitcoin::blockdata::opcodes;
    use bitcoin::util::key;
    use super::*;

    static TEST_PRIVKEY: &str =
        "16639f75cd0fedb471ae4b130ddfd25325376b03415060105c6e62bb7f19227a";
    static TEST_PRIVKEY_WIF: &str =
        "5Hz9Uvs52LD2JtWwmdbAv8dfcoqppCKpwqENBgTXp8LzPn7ApyU";
    static TEST_PUBKEY: &str =
        "0403bd27e65ea627147ac58c96254dcae8e2606c1c98255dcde887ea0471f604002aa236d3fb776b96c57ca0a59a2883f0f35afeb51b17d7bd557cdade81ea5618";
    static TEST_SERVICE_URI: &str =
        "https://my-service-endpoint.com:1337";

    #[test]
    fn test_build_p2pkh() {
        let expected_asm = 
            "OP_DUP OP_HASH160 OP_PUSHBYTES_20 52162d2b55310382b7e55c169cdb5f71fb6ad713 OP_EQUALVERIFY OP_CHECKSIG";
        let pk = key::PublicKey::from_slice(&hex::decode(TEST_PUBKEY).unwrap()).unwrap();
        let pkh = pk.pubkey_hash();
        let script = build_p2pkh_script(&pkh);
        assert_eq!(expected_asm, script.asm());
        assert!(script.is_p2pkh());
        assert_eq!(pkh.as_ref(), &script.as_bytes()[3..23]);
    }

    #[test]
    fn test_build_gtx_txout1_script() {
        let expected_asm = 
            "OP_RETURN OP_PUSHBYTES_49 5468652054696d65732032372f4a616e2f32303231202744756d62204d6f6e657927204973206f6e2047616d6553746f70";
        let gtx_txout1_script = Gtx::build_txout1_script();
        assert_eq!(expected_asm, gtx_txout1_script.asm());
        assert!(gtx_txout1_script.is_provably_unspendable());
    }

    #[test]
    fn test_build_utx_txout1_script() {
        let expected_asm = 
            "OP_RETURN OP_PUSHBYTES_36 68747470733a2f2f6d792d736572766963652d656e64706f696e742e636f6d3a31333337";
        let utx_txout1_script = Utx::build_txout1_script(TEST_SERVICE_URI.as_bytes());
        assert_eq!(expected_asm, utx_txout1_script.asm());
        assert!(utx_txout1_script.is_provably_unspendable());
        assert_eq!(TEST_SERVICE_URI.as_bytes(), &utx_txout1_script.as_bytes()[2..(2 + 36)]);
    }

    #[test]
    fn test_gtx_sign() {
        let prev_txhash = 
            Hash::from_str("b3e4573c18f2b8e56943f6c09904dfb4aef7391a2a1f3ddbcc569b515eee16e1")
                .unwrap();
        let txin = TxIn {
            previous_output: OutPoint {
                txid: Txid::from_hash(prev_txhash),
                vout: 0,
            },
            script_sig: Script::default(),
            sequence: 0xFFFFFFFF,
            witness: Vec::new(),
        };
        let pk = key::PublicKey::from_slice(&hex::decode(TEST_PUBKEY).unwrap()).unwrap();
        let pkh = pk.pubkey_hash();
        let private_key = key::PrivateKey::from_str(TEST_PRIVKEY_WIF).unwrap();
        let unsigned_tx = Gtx::build_tx(&vec![txin], 31337, &pkh);
        fn resolve_tx(txid: Txid) -> Option<Transaction> {
            let pk = key::PublicKey::from_slice(&hex::decode(TEST_PUBKEY).unwrap()).unwrap();
            let pkh = pk.pubkey_hash();
            return Some(Transaction {
                input: vec![],
                output: vec![TxOut {
                    script_pubkey: build_p2pkh_script(&pkh),
                    value: 31338,
                }],
                version: 0,
                lock_time: 0,
            });
        }
        let signed_tx = sign_tx(&unsigned_tx, resolve_tx, &private_key);
        let mut buf = Vec::new();
        let _ = signed_tx.consensus_encode(&mut buf).unwrap();
        let expected_buf = "0100000001E116EE5E519B56CCDB3D1F2A1A39F7AEB4DF0499C0F64369E5B8F2183C57E4B3000000006B483045022100E13508EA3CC20EE24B3EC4375B0A6734D4DC1FCCF4F5E5F4E37350DFFDCCF5B3022006FF3EE6750C4971D6C94C431CB11EF91CA3B6461CAE5ED83B8E25CDB658FF9201210203BD27E65EA627147AC58C96254DCAE8E2606C1C98255DCDE887EA0471F60400FFFFFFFF02697A0000000000001976A91452162D2B55310382B7E55C169CDB5F71FB6AD71388AC0000000000000000336A315468652054696D65732032372F4A616E2F32303231202744756D62204D6F6E657927204973206F6E2047616D6553746F7000000000";
        let string_list = buf.iter()
            .map(|v| format!("{:02X}", v))
            .collect::<Vec<String>>();
        assert_eq!(expected_buf, &string_list.join(""));
    }
}
