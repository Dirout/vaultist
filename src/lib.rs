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
	[nonce.to_vec(), encrypted_serialised].concat()
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
	decrypted
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

	aead.encrypt(nonce, bytes).unwrap()
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

	aead.decrypt(nonce, bytes).unwrap()
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
