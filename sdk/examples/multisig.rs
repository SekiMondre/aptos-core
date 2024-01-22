
use aptos_sdk::{
    types::LocalAccount,
    types::{account_address::AccountAddress, AccountKey}, coin_client::CoinClient,
    types::transaction::EntryFunction,
    types::chain_id::ChainId,
};

use anyhow::{Context, Result};
use aptos_crypto::{
    multi_ed25519::{MultiEd25519PublicKey, MultiEd25519PrivateKey}, 
    compat::Sha3_256, 
    ed25519::Ed25519PrivateKey, 
    SigningKey, Uniform, ValidCryptoMaterialStringExt
};
use aptos_rest_client::{FaucetClient, Client};

use aptos_types::transaction::{
    RawTransaction, 
    Multisig, 
    SignedTransaction, 
};

use ed25519_dalek_bip32::ed25519_dalek::Digest;
use move_core_types::{language_storage::{ModuleId, TypeTag}, identifier::Identifier};
use once_cell::sync::Lazy;
use std::{str::FromStr, time::{SystemTime, UNIX_EPOCH}};
use url::Url;

static NODE_URL: Lazy<Url> = Lazy::new(|| {
    Url::from_str(
        std::env::var("APTOS_NODE_URL")
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("https://fullnode.devnet.aptoslabs.com"),
    )
    .unwrap()
});

static FAUCET_URL: Lazy<Url> = Lazy::new(|| {
    Url::from_str(
        std::env::var("APTOS_FAUCET_URL")
            .as_ref()
            .map(|s| s.as_str())
            .unwrap_or("https://faucet.devnet.aptoslabs.com"),
    )
    .unwrap()
});

#[tokio::main]
async fn main() -> Result<()> {

    let rest_client = Client::new(NODE_URL.clone());
    let faucet_client = FaucetClient::new(FAUCET_URL.clone(), NODE_URL.clone());

    let coin_client = CoinClient::new(&rest_client);


    let a_priv_key = Ed25519PrivateKey::generate(&mut rand::rngs::OsRng);
    let bts = a_priv_key.to_encoded_string().unwrap();
    let a_priv_key2 = Ed25519PrivateKey::from_encoded_string(&bts);

    // let pr_key = Arc::new(a_priv_key);
    let a_acc_key = AccountKey::from_private_key(a_priv_key);
    // let alice = LocalAccount::generate(&mut rand::rngs::OsRng);
    let alice = LocalAccount::new(a_acc_key.authentication_key().account_address(), a_acc_key, 0);
    let bob = LocalAccount::generate(&mut rand::rngs::OsRng);
    let chad = LocalAccount::generate(&mut rand::rngs::OsRng);

    println!("\n=== Account addresses ===");
    println!("Alice: {}", alice.address().to_hex_literal());
    println!("Bob: {}", bob.address().to_hex_literal());
    println!("Chad: {}", chad.address().to_hex_literal());

    println!("\n=== Authentication keys ===");
    println!("Alice: {}", alice.authentication_key());
    println!("Bob: {}", bob.authentication_key());
    println!("Chad: {}", chad.authentication_key());

    println!("\n=== Public keys ===");
    println!("Alice: {}", alice.public_key());
    println!("Bob: {}", bob.public_key());
    println!("Chad: {}", chad.public_key());

    let threshold = 2;

    let multisig_pub_key = MultiEd25519PublicKey::new(vec![
        alice.public_key().clone(),
        bob.public_key().clone(),
        chad.public_key().clone()
    ], threshold)
        .context("Failed to generate multisig public key")?;

    let mut hasher = Sha3_256::new();
    hasher.update(alice.public_key());
    hasher.update(bob.public_key());
    hasher.update(chad.public_key());
    hasher.update(&[threshold]);
    hasher.update(&[0x01]);
    let result = hasher.finalize();
    let mut auth_key = [0u8; 32];
    auth_key.copy_from_slice(&result);

    let multisig_address = AccountAddress::new(auth_key);

    println!("\n=== Multisig ===");
    println!("Multisig public key: {}", multisig_pub_key);
    println!("Multisig address: {}", multisig_address);

    faucet_client
        .fund(alice.address(), 10_000_000)
        .await
        .context("Failed to fund Alice")?;
    faucet_client
        .fund(bob.address(), 20_000_000)
        .await
        .context("Failed to fund Bob")?;
    faucet_client
        .fund(chad.address(), 30_000_000)
        .await
        .context("Failed to fund Chad")?;

    faucet_client
        .fund(multisig_address, 40_000_000)
        .await
        .context("Failed to fund multisig")?;

    println!("\n=== Funding accounts ===");
    println!("Alice's balance: {}", coin_client.get_account_balance(&alice.address()).await.context("Fail")?);
    println!("Bob's balance: {}", coin_client.get_account_balance(&bob.address()).await.context("Fail")?);
    println!("Chad's balance: {}", coin_client.get_account_balance(&chad.address()).await.context("Fail")?);

    let multisig_balance = coin_client
        .get_account_balance(&multisig_address)
        .await
        .context("Failed to get multisig account balance")?;
    println!("Multisig balance: {}", multisig_balance);

    // === transaction

    println!("\n=== Transaction ===");
    
    let entry_func = EntryFunction::new(
        ModuleId::new(AccountAddress::ONE, Identifier::new("coin").unwrap()), 
        Identifier::new("transfer").unwrap(),
        vec![TypeTag::from_str("0x1::aptos_coin::AptosCoin").unwrap()], 
        vec![
            bcs::to_bytes(&chad.address()).unwrap(),
            bcs::to_bytes(&100).unwrap(),
        ]
    );
    
    let txn = RawTransaction::new_multisig(
        multisig_address, 
        0, 
        Multisig {
            multisig_address: multisig_address,
            transaction_payload: Some(aptos_types::transaction::MultisigTransactionPayload::EntryFunction(entry_func)),
        }, 
        5_000, 
        100, 
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 10, 
        ChainId::new(rest_client.get_index().await.context("Failed to get chain ID")?.inner().chain_id)
    );

    // === signature

    let multisig_priv_key = MultiEd25519PrivateKey::new(
        vec![
            a_priv_key2.unwrap(),
            Ed25519PrivateKey::from_encoded_string(&bob.private_key().to_encoded_string().unwrap()).unwrap(),
            Ed25519PrivateKey::from_encoded_string(&chad.private_key().to_encoded_string().unwrap()).unwrap(),
        ], threshold)
        .unwrap();

    let multi_signature = multisig_priv_key.sign(&txn).unwrap();

    let sign_txn = SignedTransaction::new_multisig(txn, multisig_pub_key, multi_signature);
    let txn_hash = rest_client
        .submit(&sign_txn)
        .await
        .context("Failed transaction")?
        .into_inner();

    // === submit

    rest_client
        .wait_for_transaction(&txn_hash)
        .await
        .context("Failed wait for txn")?;

    let f_balance = coin_client.get_account_balance(&multisig_address).await.context("Failed")?;
    println!("FINAL BALANCE: {}", f_balance);
    println!("Alice's balance: {}", coin_client.get_account_balance(&alice.address()).await.context("Failed")?);
    println!("Bob's balance: {}", coin_client.get_account_balance(&bob.address()).await.context("Failed")?);
    println!("Chad's balance: {}", coin_client.get_account_balance(&chad.address()).await.context("Failed")?);

    Ok(())
}
