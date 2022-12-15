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

use argon2::password_hash::SaltString;
use argon2::PasswordHasher;
use chacha20poly1305::aead::{Aead, AeadCore};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use convert_case::{Case, Casing};
use derive_more::{Constructor, From, Into};
use lazy_static::lazy_static;
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

lazy_static! {
	/// A vector of symbol characters
	pub static ref SYMBOLS: Vec<char> = "~!@#$%^&*-_=+;:,./?()[]{}<>".chars().collect();
	/// A vector of similar-looking characters
	pub static ref SIMILAR_CHARACTERS: Vec<char> = "iI1loO0\"'`|".chars().collect();
	/// The possible non-separator elements of a `CorrectHorseBatteryStaple`-type password
	pub static ref ELEMENTS: Vec<CorrectHorseBatteryStapleElements> = vec![CorrectHorseBatteryStapleElements::WORD, CorrectHorseBatteryStapleElements::DIGIT];
}

/// The possible elements of a `CorrectHorseBatteryStaple`-type password
pub enum CorrectHorseBatteryStapleElements {
	/// An English-language word
	WORD,
	/// A separator character
	SEPARATOR,
	/// A digit character
	DIGIT,
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
/// A vault for storing secrets
pub struct Vault {
	/// The salt applied to the vault's password
	pub salt: Vec<u8>,
	/// The key of the vault
	pub key: String,
	/// The entries (and the nonces used to encrypt them) within the vault
	pub entries: Vec<(Entry, Vec<u8>)>,
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
	Into,
	derive_more::Mul,
	derive_more::Div,
	derive_more::Rem,
	derive_more::Shr,
	derive_more::Shl,
	Constructor,
)]
/// An encrypted entry held within the vault
pub struct Secret {
	/// The metadata of the secret
	pub entry: Entry,
	/// The secret, encrypted information
	pub contents: Vec<u8>,
	/// The nonce used to encrypt the secret
	pub nonce: Vec<u8>,
}

/// Generates a random nonce for use with the XChaCha20Poly1305 cipher.
pub fn generate_nonce() -> XNonce {
	XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng)
}

/// Generate the vault's key from a user-supplied password.
///
/// # Arguments
///
/// * `password` - The user-supplied password.
pub fn generate_vault_from_password(password: String) -> Vault {
	let salt = argon2::password_hash::SaltString::generate(&mut rand_core::OsRng);
	let password_and_salt = generate_key_from_password_and_salt(password, &salt);
	return Vault {
		salt: salt.as_bytes().to_owned(),
		key: password_and_salt.0,
		entries: Vec::new(),
	};
}

/// Generate the vault's key from a user-supplied password and a pre-generated salt.
///
/// # Arguments
///
/// * `password` - The user-supplied password.
///
/// * `salt` - The pre-generated salt string.
pub fn generate_key_from_password_and_salt(
	password: String,
	salt: &SaltString,
) -> (String, &SaltString) {
	let config = argon2::Argon2::default();
	let key = config
		.hash_password(password.as_bytes(), &salt)
		.unwrap()
		.to_string();
	return (key, salt);
}

/// Encrypt a byte array using the vault's key.
///
/// # Arguments
///
/// * `key` - The vault's key.
///
/// * `bytes` - The bytes to encrypt.
///
/// * `nonce_bytes` - The bytes of the nonce to use.
pub fn encrypt_bytes(key: &String, bytes: &[u8], nonce_bytes: &[u8]) -> Vec<u8> {
	let enc_key = Key::from_slice(&key.as_bytes()[..32]);
	let aead = XChaCha20Poly1305::new(enc_key);

	aead.encrypt(&XNonce::from_slice(nonce_bytes), bytes)
		.unwrap()
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
pub fn decrypt_bytes(key: String, bytes: &[u8], nonce: &XNonce) -> Vec<u8> {
	let enc_key = Key::from_slice(&key.as_bytes()[..32]);
	let aead = XChaCha20Poly1305::new(enc_key);

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
pub fn decrypt_secret(key: String, encrypted_serialised: Vec<u8>, nonce_bytes: Vec<u8>) -> Secret {
	// let nonce_bytes: [u8; 24] = encrypted_serialised[..24].try_into().unwrap();
	let nonce = XNonce::from_slice(&nonce_bytes);
	let decrypted_serialised = decrypt_bytes(key, &encrypted_serialised, &nonce);
	let decrypted: Secret = bincode::deserialize(&decrypted_serialised).unwrap();
	decrypted
}

impl Vault {
	/// Sorts entries by their last modified date & time, and then deduplicates entries which have contents (and, optionally, names) in common.
	///
	/// # Arguments
	///
	/// * `ignore_names` - Whether or not to ignore common names in addition to common contents when deduplicating.
	pub fn deduplicate_entries(&mut self, ignore_names: bool) -> &mut [(Entry, Vec<u8>)] {
		self.entries.sort_by_cached_key(|x| x.0.last_modified);
		match ignore_names {
			true => {
				self.entries
					.partition_dedup_by(|a, b| a.0.hash == b.0.hash)
					.1
			}
			false => {
				self.entries
					.partition_dedup_by(|a, b| a.0.name == b.0.name && a.0.hash == b.0.hash)
					.1
			}
		}
	}

	/// Adds an entry into a vault.
	///
	/// # Arguments
	///
	/// * `item` - The entry to be added.
	///
	/// * `nonce` - The nonce used when encrypting the entry.
	pub fn add_entry(&mut self, item: Entry, nonce: Vec<u8>) {
		self.entries.push((item, nonce));
	}

	/// Remove an entry from a vault.
	///
	/// # Arguments
	///
	/// * `item` - The entry to be removed.
	pub fn remove_entry(&mut self, item: &Entry) {
		self.entries = self.entries.drain_filter(|x| x.0.id == item.id).collect();
	}

	/// Encrypt an entry into the vault.
	///
	/// # Arguments
	///
	/// * `self` - The vault.
	///
	/// * `item` - The secret to encrypt.
	pub fn encrypt_secret(&mut self, item: &mut Secret) -> Vec<u8> {
		let serialised: Vec<u8> = bincode::serialize(&item).unwrap();
		let encrypted_serialised = encrypt_bytes(&self.key, &serialised, &item.nonce);
		self.entries.push((item.clone().entry, item.clone().nonce));
		encrypted_serialised
	}
}

/// Generate a `CorrectHorseBatteryStaple`-style password.\
/// Optionally, can use two additional elements:
/// 1. A randomly-picked special character to separate each element (note: the separator will always be a space if `spaces` is true)
/// 2. A randomly-picked one- or two-digit number (note: if numbers are allowed, the password will always end with one)
///
/// # Arguments
///
/// * `count` - The number of passwords to generate.
///
/// * `length` - The length of the generated passwords.
///
/// * `numbers` - Passwords are should contain at least one number.
///
/// * `lowercase_letters` - Passwords should contain at least one lowercase letter.
///
/// * `uppercase_letters` - Passwords should contain at least one uppercase letter.
///
/// * `symbols` - Passwords should contain at least one special character.
///
/// * `spaces` - Passwords should use a space to separate each password element.
///
/// * `exclude_similar_characters` - Whether or not to exclude similar looking ASCII characters (``iI1loO0"'`|``).
pub fn correct_horse_battery_staple(
	count: usize,
	length: usize,
	numbers: bool,
	lowercase_letters: bool,
	uppercase_letters: bool,
	symbols: bool,
	spaces: bool,
	exclude_similar_characters: bool,
) -> Vec<String> {
	let mut result: Vec<String> = Vec::new();
	let mut rng = rand::thread_rng();
	for _i in 0..count {
		let mut current_password: Vec<String> = Vec::new();
		let separator = if !spaces {
			SYMBOLS.choose(&mut rng).unwrap().to_string()
		} else {
			" ".to_owned()
		};
		let mut characters_remaining = length;
		let mut next_element = &CorrectHorseBatteryStapleElements::WORD;
		while characters_remaining > 0 {
			match next_element {
				CorrectHorseBatteryStapleElements::WORD => {
					// Leave three characters for at least a separator and two digits
					match characters_remaining >= 3 {
						true => {
							let mut randomly_selected_word = String::new();
							loop {
								if randomly_selected_word.len() > 0
									&& randomly_selected_word.len() <= characters_remaining - 3
								{
									match uppercase_letters && lowercase_letters {
										// Use both uppercase and lowercase letters
										true => {
											current_password
												.push(randomly_selected_word.to_case(Case::Title));
										}
										false => {
											match uppercase_letters {
												// Use only uppercase letters
												true => {
													current_password.push(
														randomly_selected_word.to_case(Case::Upper),
													);
												}
												// Use only lowercase letters
												false => {
													current_password.push(
														randomly_selected_word.to_case(Case::Lower),
													);
												}
											}
										}
									}
									characters_remaining -= randomly_selected_word.len();
									break;
								} else if randomly_selected_word.len() <= 0
									|| randomly_selected_word.len() >= characters_remaining - 3
								{
									randomly_selected_word = if !exclude_similar_characters {
										memorable_wordlist::WORDS
											.choose(&mut rng)
											.unwrap()
											.to_string()
									} else {
										let mut filtered_words =
											memorable_wordlist::WORDS.to_owned();
										filtered_words.retain(|&x| {
											x.contains(|c| SIMILAR_CHARACTERS.contains(&c))
										});
										filtered_words.choose(&mut rng).unwrap().to_string()
									};
								};
							}
						}
						false => {}
					}
					next_element = &CorrectHorseBatteryStapleElements::SEPARATOR;
				}
				CorrectHorseBatteryStapleElements::SEPARATOR => {
					match (symbols || spaces) && characters_remaining > 2 {
						true => {
							current_password.push(separator.clone());
							characters_remaining -= 1;
						}
						false => {}
					}
					match characters_remaining > 0 && characters_remaining < 3 {
						true => {
							next_element = &CorrectHorseBatteryStapleElements::DIGIT;
						}
						false => {
							next_element = ELEMENTS.choose(&mut rng).unwrap();
						}
					}
				}
				CorrectHorseBatteryStapleElements::DIGIT => match numbers {
					true => {
						let lower_bound = if exclude_similar_characters { 2 } else { 0 };
						let random_number_string;
						match characters_remaining {
							1 => {
								let random_number = rng.gen_range(lower_bound..10);
								random_number_string = random_number.to_string();
							}
							2 => {
								let random_first_digit = rng.gen_range(lower_bound..10);
								let random_second_digit = rng.gen_range(lower_bound..10);
								random_number_string = random_first_digit.to_string()
									+ &random_second_digit.to_string();
							}
							n if n > 2 => {
								if rng.gen_bool(0.5) {
									let random_number = rng.gen_range(lower_bound..10);
									random_number_string = random_number.to_string();
								} else {
									let random_first_digit = rng.gen_range(lower_bound..10);
									let random_second_digit = rng.gen_range(lower_bound..10);
									random_number_string = random_first_digit.to_string()
										+ &random_second_digit.to_string();
								}
							}
							_ => {
								unreachable!();
							}
						}

						current_password.push(random_number_string.clone());
						characters_remaining -= random_number_string.len();
						next_element = &CorrectHorseBatteryStapleElements::SEPARATOR;
					}
					false => {
						next_element = &CorrectHorseBatteryStapleElements::WORD;
					}
				},
			}
		}
		result.push(current_password.concat());
	}

	result
}
