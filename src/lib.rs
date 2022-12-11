/*
	This file is part of keywi.
	keywi is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	keywi is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.
	You should have received a copy of the GNU Affero General Public License
	along with keywi.  If not, see <https://www.gnu.org/licenses/>.
*/

#![cfg_attr(feature = "dox", feature(doc_cfg))]
#![allow(clippy::needless_doctest_main)]
#![feature(drain_filter)]
#![feature(slice_partition_dedup)]

use argon2::PasswordHasher;
use chacha20poly1305::aead::{Aead, AeadCore};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use derive_more::{Constructor, From, Into};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
	derive_more::Mul,
	derive_more::Div,
	derive_more::Rem,
	derive_more::Shr,
	derive_more::Shl,
	Constructor,
)]
/// The main vault file
pub struct Vault {
	/// The salt applied to the vault's password
	pub salt: Vec<u8>,
	/// The key of the vault
	pub key: String,
	/// The entries within the vault
	pub entries: Vec<Entry>,
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
	derive_more::Mul,
	derive_more::Div,
	derive_more::Rem,
	derive_more::Shr,
	derive_more::Shl,
	Constructor,
)]
/// An entry within the vault
pub struct Entry {
	/// The name of an entry
	pub name: String,
	/// The information contained within an entry
	pub contents: String,
	/// The ID of the entry
	pub id: Uuid,
	/// The date & time when the entry was last modified
	pub last_modified: chrono::DateTime<chrono::Utc>,
}

/// Generate the vault's key from a user-supplied password.
///
/// # Arguments
///
/// * `password` - The user-supplied password.
pub fn generate_key_from_password(password: String) -> Vault {
	let salt = argon2::password_hash::SaltString::generate(&mut rand_core::OsRng);
	let config = argon2::Argon2::default();
	let key = config
		.hash_password(password.as_bytes(), &salt)
		.unwrap()
		.to_string();
	return Vault {
		salt: salt.as_bytes().to_owned(),
		key,
		entries: Vec::new(),
	};
}

/// Encrypt an entry into the vault.
///
/// # Arguments
///
/// * `key` - The vault's key.
///
/// * `item` - The entry to encrypt.
pub fn encrypt_entry(key: String, item: &mut Entry) -> Vec<u8> {
	let nonce = XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng);
	let serialised: Vec<u8> = bincode::serialize(&item).unwrap();
	let encrypted_serialised = encrypt_bytes(key, &serialised, &nonce);
	return [nonce.to_vec(), encrypted_serialised].concat();
}

/// Decrypt an entry from the vault.
///
/// # Arguments
///
/// * `key` - The vault's key.
///
/// * `encrypted_serialised` - The bytes of the encrypted entry.
pub fn decrypt_entry(key: String, encrypted_serialised: Vec<u8>) -> Entry {
	let nonce_bytes: [u8; 24] = encrypted_serialised[..24].try_into().unwrap();
	let decrypted_serialised = decrypt_bytes(key, &encrypted_serialised, &nonce_bytes);
	let decrypted: Entry = bincode::deserialize(&decrypted_serialised).unwrap();
	return decrypted;
}

/// Encrypt a byte array using the vault's key.
///
/// # Arguments
///
/// * `key` - The vault's key.
///
/// * `bytes` - The bytes to encrypt.
///
/// * `nonce_bytes` - The nonce to use.
pub fn encrypt_bytes(key: String, bytes: &[u8], nonce: &XNonce) -> Vec<u8> {
	let enc_key = Key::from_slice(key.as_bytes());
	let aead = XChaCha20Poly1305::new(enc_key);
	let encrypted = aead.encrypt(&nonce, bytes).unwrap();
	return encrypted;
}

/// Decrypt a byte array using the vault's key.
///
/// # Arguments
///
/// * `key` - The vault's key.
///
/// * `bytes` - The bytes to decrypt.
///
/// * `nonce_bytes` - The nonce to use.
pub fn decrypt_bytes(key: String, bytes: &[u8], nonce_bytes: &[u8; 24]) -> Vec<u8> {
	let enc_key = Key::from_slice(key.as_bytes());
	let aead = XChaCha20Poly1305::new(enc_key);
	let nonce = XNonce::from_slice(nonce_bytes);
	let decrypted = aead.decrypt(&nonce, bytes).unwrap();
	return decrypted;
}

impl Vault {
	/// Sorts entries by their last modified date & time, and then deduplicates entries which have contents (and, optionally, names) in common.
	///
	/// # Arguments
	///
	/// * `ignore_names` - Whether or not to ignore common names in addition to common contents when deduplicating.
	pub fn deduplicate_entries(&mut self, ignore_names: bool) -> &mut [Entry] {
		self.entries.sort_by_cached_key(|x| x.last_modified);
		match ignore_names {
			true => {
				self.entries
					.partition_dedup_by(|a, b| a.contents == b.contents)
					.1
			}
			false => {
				self.entries
					.partition_dedup_by(|a, b| a.name == b.name && a.contents == b.contents)
					.1
			}
		}
	}

	/// Adds an entry into a vault.
	///
	/// # Arguments
	///
	/// * `item` - The entry to be added.
	pub fn add_entry(&mut self, item: Entry) {
		self.entries.push(item);
	}

	/// Remove an entry from a vault.
	///
	/// # Arguments
	///
	/// * `item` - The entry to be removed.
	pub fn remove_entry(&mut self, item: &Entry) {
		self.entries = self.entries.drain_filter(|x| x.id == item.id).collect();
	}
}
