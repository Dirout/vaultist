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

use argon2::PasswordHasher;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct Entry {
	pub name: String,
	pub contents: String,
}

/// Generate the vault's key from a user-supplied password.
///
/// # Arguments
///
/// * `password` - The user-supplied password.
pub fn generate_key_from_password(password: String) -> String {
	let salt = argon2::password_hash::SaltString::generate(&mut rand_core::OsRng);
	let config = argon2::Argon2::default();
	let key = config
		.hash_password(password.as_bytes(), &salt)
		.unwrap()
		.to_string();
	return key;
}

/// Encrypt an entry into the vault.
///
/// # Arguments
///
/// * `key` - The vault's key.
///
/// * `item` - The entry to encrypt.
pub fn encrypt_entry(key: String, item: &mut Entry) -> Vec<u8> {
	let mut nonce_bytes = [0u8; 24];
	rand_core::OsRng.fill_bytes(&mut nonce_bytes);

	let serialised: Vec<u8> = bincode::serialize(&item).unwrap();
	let encrypted_serialised = encrypt_bytes(key, &serialised, &nonce_bytes);
	return [nonce_bytes.to_vec(), encrypted_serialised].concat();
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
pub fn encrypt_bytes(key: String, bytes: &[u8], nonce_bytes: &[u8; 24]) -> Vec<u8> {
	let enc_key = Key::from_slice(key.as_bytes());
	let aead = XChaCha20Poly1305::new(enc_key);
	let nonce = XNonce::from_slice(nonce_bytes);
	let encrypted = aead.encrypt(nonce, bytes).unwrap();
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
