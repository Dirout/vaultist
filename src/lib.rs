/*
	This file is part of Vaultist.
	Vaultist is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	Vaultist is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.
	You should have received a copy of the GNU Affero General Public License
	along with Vaultist.  If not, see <https://www.gnu.org/licenses/>.
*/

#![no_std]
#![warn(missing_docs)]
#![doc(
	html_logo_url = "https://github.com/Dirout/vaultist/raw/master/branding/app_icon.png",
	html_favicon_url = "https://github.com/Dirout/vaultist/raw/master/branding/app_icon.png"
)]
#![feature(drain_filter)]
#![feature(slice_partition_dedup)]

use alloc::borrow::ToOwned;
use alloc::str;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use argon2::password_hash::SaltString;
use argon2::PasswordHasher;
use chacha20poly1305::aead::{Aead, AeadCore};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use derive_more::{Constructor, From, Into};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "bitwarden_reader")]
pub mod bitwarden_reader;
#[cfg(feature = "chrome_reader")]
pub mod chrome_reader;
#[cfg(feature = "firefox_reader")]
pub mod firefox_reader;
#[cfg(feature = "keychain_reader")]
pub mod keychain_reader;
#[cfg(feature = "password_generator")]
pub mod password_generator;

#[derive(Eq, PartialEq, PartialOrd, Clone, Debug, Serialize, Deserialize, From, Hash)]
/// The possible versions of a Vaultist vault
pub enum VaultVersion {
	/// The Vaultist vault format introduced in December 2022
	December2022,
}

impl Default for VaultVersion {
	fn default() -> Self {
		VaultVersion::latest()
	}
}

impl VaultVersion {
	/// Get the latest version of the Vaultist vault format
	pub fn latest() -> Self {
		VaultVersion::December2022
	}

	/// Gets the Argon2 configuration for the vault version
	pub fn get_argon2_config(&self) -> (argon2::Algorithm, argon2::Version, argon2::Params) {
		match self {
			VaultVersion::December2022 => (
				argon2::Algorithm::Argon2id,
				argon2::Version::V0x13,
				argon2::Params::new(1048576u32, 4u32, 4u32, None).unwrap(),
			),
		}
	}
}

#[derive(
	Eq,
	PartialEq,
	PartialOrd,
	Clone,
	Debug,
	Serialize,
	Deserialize,
	From,
	zeroize::Zeroize,
	zeroize::ZeroizeOnDrop,
)]
/// A vault for storing secrets
pub struct Vault {
	/// The salt applied to the vault's password
	pub salt: Vec<u8>,
	/// The nonce used to encrypt the vault
	pub nonce: XNonce,
	/// The encrypted secrets in the vault
	pub encrypted_secrets: Vec<u8>,
	#[zeroize(skip)]
	/// The version of the vault
	pub version: VaultVersion,
}

impl Default for Vault {
	fn default() -> Self {
		Vault {
			salt: generate_salt(),
			nonce: generate_nonce(),
			encrypted_secrets: vec![],
			version: VaultVersion::default(),
		}
	}
}

impl Vault {
	/// Create a new vault with a user-supplied password.
	///
	/// # Arguments
	///
	/// * `password` - The password to use to encrypt the vault.
	pub fn new(password: String) -> Vault {
		let mut this = Vault::default();
		let secrets: Vec<Secret> = Vec::new();
		this.encrypted_secrets = encrypt_bytes(
			&this.generate_key_from_password(password).1,
			&bincode::serialize(&secrets).unwrap(),
			Some(&this.nonce),
		);
		this
	}

	/// Decrypt a vector of secrets with a user-supplied password.
	///
	/// # Arguments
	///
	/// * `password` - The user-supplied password.
	pub fn decrypt_vault_entries_by_password(&mut self, password: String) -> Vec<Secret> {
		let key = self.generate_key_from_password(password);
		self.decrypt_vault_entries_by_key(&key.1)
	}

	/// Decrypt a vector of secrets with a generated key.
	///
	/// # Arguments
	///
	/// * `key` - The key to decrypt the vault with.
	pub fn decrypt_vault_entries_by_key(&mut self, key: &[u8]) -> Vec<Secret> {
		bincode::deserialize(&decrypt_bytes(key, &self.encrypted_secrets, &self.nonce)).unwrap()
	}

	/// Generate a vault's key from a user-supplied password and a pre-generated salt.
	///
	/// # Arguments
	///
	/// * `password` - The user-supplied password.
	pub fn generate_key_from_password(&mut self, password: String) -> (String, Vec<u8>) {
		let salt_string = &SaltString::new(str::from_utf8(&self.salt).unwrap()).unwrap();
		let config = self.version.get_argon2_config();
		let argon2 = argon2::Argon2::new(config.0, config.1, config.2);
		let key = argon2
			.hash_password(password.as_bytes(), salt_string)
			.unwrap();
		// println!("GEN_KEY_STR: {}", key);
		// println!("GEN_KEY_BYTES: {}", key.hash.unwrap());
		(key.to_string(), key.hash.unwrap().as_bytes().to_vec())
	}

	/// Sorts entries by their last modified date & time, and then deduplicates items which have contents (and, optionally, names) in common.
	///
	/// # Arguments
	///
	/// * `key` - The key to decrypt the vault with.
	///
	/// * `ignore_names` - Whether or not to ignore common names in addition to common contents when deduplicating.
	pub fn deduplicate_items(&mut self, key: &[u8], ignore_names: bool) -> Vec<Secret> {
		let mut items = self.decrypt_vault_entries_by_key(<&[u8]>::clone(&key));
		items.sort_by_cached_key(|x| x.entry.last_modified);
		let mut items_clone = items.clone();
		match ignore_names {
			true => {
				let (dedup, duplicates) =
					items_clone.partition_dedup_by(|a, b| a.entry.hash == b.entry.hash);
				self.encrypt_secrets(key, dedup.to_vec());
				duplicates.to_vec()
			}
			false => {
				let (dedup, duplicates) = items_clone.partition_dedup_by(|a, b| {
					a.entry.name == b.entry.name && a.entry.hash == b.entry.hash
				});
				self.encrypt_secrets(key, dedup.to_vec());
				duplicates.to_vec()
			}
		}
	}

	/// Remove an item from a vault.
	///
	/// # Arguments
	///
	/// * `key` - The key to decrypt the vault with.
	///
	/// * `entry` - The entry to be removed.
	pub fn remove_item(&mut self, key: &[u8], entry: &Entry) {
		let mut items = self.decrypt_vault_entries_by_key(<&[u8]>::clone(&key));
		items.retain(|x| x.entry.id != entry.id);
		self.encrypted_secrets =
			encrypt_bytes(key, &bincode::serialize(&items).unwrap(), Some(&self.nonce));
	}

	/// Encrypt a vector of secrets into the vault.
	///
	/// # Arguments
	///
	/// * `key` - The vault's key.
	///
	/// * `items` - The items to encrypt.
	pub fn encrypt_secrets(&mut self, key: &[u8], items: Vec<Secret>) {
		self.encrypted_secrets =
			encrypt_bytes(key, &bincode::serialize(&items).unwrap(), Some(&self.nonce));
	}

	/// Encrypt an entry into the vault.
	///
	/// # Arguments
	///
	/// * `key` - The vault's key.
	///
	/// * `item` - The secret to encrypt.
	pub fn encrypt_secret(&mut self, key: &[u8], item: &mut Secret) {
		let mut items = self.decrypt_vault_entries_by_key(<&[u8]>::clone(&key));
		items.push(item.clone());
		self.encrypt_secrets(key, items);
	}
}

/// Generates a random nonce for use with the XChaCha20Poly1305 cipher.
pub fn generate_nonce() -> XNonce {
	XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng)
}

/// Generates a random salt for use with the Argon2 algorithm.
pub fn generate_salt() -> Vec<u8> {
	let salt = argon2::password_hash::SaltString::generate(&mut rand_core::OsRng);
	salt.as_str().as_bytes().to_vec()
}

/// Encrypt a byte array using a vault's key.
///
/// # Arguments
///
/// * `key` - A vault's key.
///
/// * `bytes` - The bytes to encrypt.
///
/// * `nonce_bytes` - The bytes of the nonce to use.
pub fn encrypt_bytes(key: &[u8], bytes: &[u8], nonce_bytes: Option<&[u8]>) -> Vec<u8> {
	// println!("ENC_KEY_UTF8: {}", String::from_utf8_lossy(key));
	// println!("ENC_KEY_32: {}", String::from_utf8_lossy(&key[..32]));
	let aead = XChaCha20Poly1305::new_from_slice(&key[..32]).unwrap();
	let nonce = match nonce_bytes {
		Some(bytes) => XNonce::from_slice(bytes).to_owned(),
		None => generate_nonce(),
	};
	aead.encrypt(&nonce, bytes).unwrap()
}

/// Decrypt a byte array using the vault's key.
///
/// # Arguments
///
/// * `key` - The vault's key.
///
/// * `bytes` - The bytes to decrypt.
///
/// * `nonce` - The nonce to use.
pub fn decrypt_bytes(key: &[u8], bytes: &[u8], nonce: &XNonce) -> Vec<u8> {
	let aead = XChaCha20Poly1305::new_from_slice(key).unwrap();

	aead.decrypt(nonce, bytes).unwrap()
}

/// Decrypt a secret from the vault.
///
/// # Arguments
///
/// * `key` - The vault's key.
///
/// * `encrypted_serialised` - The bytes of the encrypted secret.
///
/// * `nonce_bytes` - The bytes of the nonce used to encrypt the secret.
pub fn decrypt_secret(key: &[u8], encrypted_serialised: Vec<u8>, nonce_bytes: Vec<u8>) -> Secret {
	// let nonce_bytes: [u8; 24] = encrypted_serialised[..24].try_into().unwrap();
	let nonce = XNonce::from_slice(&nonce_bytes);
	let decrypted_serialised = decrypt_bytes(key, &encrypted_serialised, nonce);
	let decrypted: Secret = bincode::deserialize(&decrypted_serialised).unwrap();
	decrypted
}

#[derive(
	Eq,
	PartialEq,
	PartialOrd,
	Clone,
	Default,
	Debug,
	Serialize,
	Deserialize,
	From,
	Into,
	Hash,
	derive_more::Mul,
	derive_more::Div,
	derive_more::Rem,
	derive_more::Shr,
	derive_more::Shl,
	Constructor,
)]
/// An entry in the vault
pub struct Entry {
	/// The name of an entry
	pub name: String,
	/// The ID of the entry
	pub id: Uuid,
	/// The hash of the entry's contents
	pub hash: Vec<u8>,
	/// The date & time when the entry was last modified
	pub last_modified: chrono::DateTime<chrono::Utc>,
}

#[derive(
	Eq,
	PartialEq,
	PartialOrd,
	Clone,
	Default,
	Debug,
	Serialize,
	Deserialize,
	From,
	Constructor,
	zeroize::Zeroize,
	zeroize::ZeroizeOnDrop,
)]
/// An encrypted entry held within the vault
pub struct Secret {
	#[zeroize(skip)]
	/// The metadata of the secret
	pub entry: Entry,
	/// The secret, encrypted information
	pub contents: Vec<u8>,
	/// The nonce used to encrypt the secret
	pub nonce: Vec<u8>,
}
