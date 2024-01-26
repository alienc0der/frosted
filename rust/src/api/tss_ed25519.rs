use crate::api::tss_ed25519::frost::keys::IdentifierList;
use base64::{engine::general_purpose, Engine as _};
use frost::{
    aggregate,
    keys::{generate_with_dealer, KeyPackage, PublicKeyPackage, SecretShare},
    round1, round2, Identifier, Signature, SigningPackage,
};
use frost_ed25519 as frost;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[flutter_rust_bridge::frb(init)]
pub fn init_app() {
    // Default utilities - feel free to customize
    flutter_rust_bridge::setup_default_user_utils();
}

#[derive(Serialize, Deserialize)]
pub struct KeyShard {
    pub identifier: Vec<u8>,
    pub secret_share: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct KeygenResult {
    pub key_shards: Vec<KeyShard>,
    pub public_key_package: Vec<u8>,
    pub group_public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct SignRequest {
    pub message: String,
    pub key_shards: Vec<KeyShard>,
    pub public_key_package: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyRequest {
    pub message: String,
    pub signature_base64: String,
    pub public_key_package: Vec<u8>,
}

#[flutter_rust_bridge::frb]
pub async fn keygen(max_signers: u16, min_signers: u16) -> Result<KeygenResult, String> {
    let mut rng = thread_rng();
    match generate_with_dealer(max_signers, min_signers, IdentifierList::Default, &mut rng) {
        Ok((shares, pubkey_package)) => {
            let key_shards_result: Result<Vec<KeyShard>, String> = shares
                .into_iter()
                .map(|(identifier, secret_share)| {
                    let identifier_bytes = identifier.serialize();
                    let secret_share_bytes = secret_share.serialize().map_err(|e| e.to_string())?;
                    Ok(KeyShard {
                        identifier: identifier_bytes.to_vec(),
                        secret_share: secret_share_bytes,
                    })
                })
                .collect();

            let key_shards = key_shards_result?;
            let pubkey_package_bytes = pubkey_package.serialize().map_err(|e| e.to_string())?;
            let group_public_key_bytes = pubkey_package.group_public().serialize().to_vec();

            Ok(KeygenResult {
                key_shards,
                public_key_package: pubkey_package_bytes,
                group_public_key: group_public_key_bytes,
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

#[flutter_rust_bridge::frb]
pub async fn keysign(serialized_request: String) -> Result<String, String> {
    let sign_request: SignRequest = serde_json::from_str(&serialized_request)
        .map_err(|e| format!("Failed to deserialize signing request: {}", e))?;

    let mut rng = thread_rng();
    let mut nonces_map = HashMap::new();
    let mut commitments_map = BTreeMap::new();
    let mut signature_shares = HashMap::new();

    let public_key_package = PublicKeyPackage::deserialize(&sign_request.public_key_package)
        .map_err(|e| format!("Failed to deserialize PublicKeyPackage: {}", e))?;

    let key_packages = sign_request
        .key_shards
        .iter()
        .map(|shard| {
            let identifier_slice: &[u8] = &shard.identifier;
            let identifier_array: &[u8; 32] = identifier_slice
                .try_into()
                .map_err(|_| "Identifier conversion error")?;
            let identifier = Identifier::deserialize(identifier_array)
                .map_err(|e| format!("Failed to deserialize Identifier: {}", e))?;
            let secret_share = SecretShare::deserialize(&shard.secret_share)
                .map_err(|e| format!("Failed to deserialize SecretShare: {}", e))?;
            let key_package = KeyPackage::try_from(secret_share)
                .map_err(|e| format!("KeyPackage creation error: {}", e))?;
            Ok((identifier, key_package))
        })
        .collect::<Result<HashMap<_, _>, _>>()
        .map_err(|e: String| e)?;

    // Perform the FROST signature rounds
    for (identifier, key_package) in &key_packages {
        let (nonces, commitments) = round1::commit(&key_package.secret_share(), &mut rng);
        nonces_map.insert(*identifier, nonces);
        commitments_map.insert(*identifier, commitments);
    }

    let signing_package =
        SigningPackage::new(commitments_map.clone(), sign_request.message.as_bytes());

    for (identifier, key_package) in &key_packages {
        let nonces = &nonces_map[identifier];
        let signature_share = round2::sign(&signing_package, nonces, key_package)
            .map_err(|e| format!("Error in round 2 of signing: {}", e))?;
        signature_shares.insert(*identifier, signature_share);
    }

    let group_signature = aggregate(&signing_package, &signature_shares, &public_key_package)
        .map_err(|e| format!("Error in signature aggregation: {}", e))?;

    // Convert the signature to bas64
    let signature_encoded = general_purpose::STANDARD.encode(group_signature.serialize());

    Ok(signature_encoded)
}

#[flutter_rust_bridge::frb]
pub fn verify_signature(request: VerifyRequest) -> Result<bool, String> {
    let signature_bytes = general_purpose::STANDARD
        .decode(&request.signature_base64)
        .map_err(|e| format!("Failed to decode signature: {}", e))?;
    let signature_array: [u8; 64] = signature_bytes
        .try_into()
        .map_err(|_| "Signature bytes are not the correct length".to_string())?;
    let signature = Signature::deserialize(signature_array)
        .map_err(|e| format!("Failed to deserialize signature: {}", e))?;
    let public_key_package = PublicKeyPackage::deserialize(&request.public_key_package)
        .map_err(|e| format!("Failed to deserialize public key package: {}", e))?;

    match public_key_package
        .group_public()
        .verify(request.message.as_bytes(), &signature)
    {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}
