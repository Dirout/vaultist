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

#![cfg_attr(feature = "dox", feature(doc_cfg))]
#![allow(clippy::needless_doctest_main)]
#![doc(
	html_logo_url = "https://github.com/Dirout/vaultist/raw/master/branding/app_icon.png",
	html_favicon_url = "https://github.com/Dirout/vaultist/raw/master/branding/app_icon.png"
)]
#![feature(drain_filter)]
#![feature(slice_partition_dedup)]

use ansi_term::Colour;
use argon2::password_hash::SaltString;
use argon2::PasswordHasher;
use blake2::digest::Update;
use blake2::digest::VariableOutput;
use blake2::Blake2bVar;
use chacha20poly1305::aead::{Aead, AeadCore};
use chacha20poly1305::{Key, KeyInit, XChaCha20Poly1305, XNonce};
use convert_case::{Case, Casing};
use derive_more::{Constructor, From, Into};
use itertools::Itertools;
use lazy_static::lazy_static;
use passwords::{analyzer, scorer};
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fmt::Formatter;
use std::path::PathBuf;
use uuid::Uuid;
use zxcvbn::zxcvbn;

lazy_static! {
	/// A vector of symbol characters
	pub static ref SYMBOLS: Vec<char> = "~!@#$%^&*-_=+;:,./?()[]{}<>".chars().collect();
	/// A vector of similar-looking characters
	pub static ref SIMILAR_CHARACTERS: Vec<char> = "iI1loO0\"'`|".chars().collect();
	/// The possible non-separator elements of a `CorrectHorseBatteryStaple`-type password
	pub static ref ELEMENTS: Vec<CorrectHorseBatteryStapleElements> = vec![CorrectHorseBatteryStapleElements::WORD, CorrectHorseBatteryStapleElements::DIGIT];
}

#[derive(Eq, PartialEq, PartialOrd, Clone, Debug, Serialize, Deserialize, From, Hash)]
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
	Constructor,
	zeroize::Zeroize,
	zeroize::ZeroizeOnDrop,
)]
/// A vault for storing secrets
pub struct Vault {
	/// The salt applied to the vault's password
	pub salt: Vec<u8>,
	/// The key of the vault
	pub key: String,
	#[zeroize(skip)]
	/// The entries representing the secrets (and the nonces used to encrypt them) within the vault
	pub items: Vec<(Entry, Vec<u8>)>,
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
/// An exported Bitwarden vault
pub struct BitwardenVault {
	/// The folders in the vault
	pub folders: Vec<BitwardenFolder>,
	/// The items in the vault
	pub items: Vec<BitwardenRecordJSON>,
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
/// A folder in a Bitwarden vault
pub struct BitwardenFolder {
	/// The ID of the folder
	pub id: String,
	/// The name of the folder
	pub name: String,
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
/// A record in a Bitwarden exported in CSV format
pub struct BitwardenRecordCSV {
	/// The name of the folder the record is in
	pub folder: Option<String>,
	/// Whether or not the record is a favourite
	pub favorite: Option<usize>,
	#[serde(rename = "type")]
	/// The type of the record
	pub type_: String,
	/// The name of the record
	pub name: String,
	/// The notes associated with the record
	pub notes: Option<String>,
	/// The fields associated with the record
	pub fields: Option<Vec<BitwardenField>>,
	/// Whether or not the vault password should be reprompted to view the record
	pub reprompt: Option<usize>,
	/// The login URI of the record
	pub login_uri: Option<String>,
	/// The login username of the record
	pub login_username: Option<String>,
	/// The login password of the record
	pub login_password: Option<String>,
	/// The login TOTP of the record
	pub login_totp: Option<String>,
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
/// A record in a Bitwarden vault exported in JSON format
pub struct BitwardenRecordJSON {
	/// The ID of the record
	pub id: String,
	/// The ID of the organisation the record is in
	pub organization_id: Option<String>,
	/// The ID of the folder the record is in
	pub folder_id: Option<String>,
	#[zeroize(skip)]
	#[serde(rename = "type")]
	/// The type of the record (see: <https://bitwarden.com/help/managing-items/>).
	///
	/// Can be:
	/// - Login (1)
	/// - Secure Note (2)
	/// - Card (3)
	/// - Identity (4)
	///
	/// See: <https://bitwarden.com/help/cli/#enums>
	pub type_: usize,
	/// Whether or not the vault password should be reprompted to view the record
	pub reprompt: Option<usize>,
	/// The name of the record
	pub name: String,
	/// The notes associated with the record
	pub notes: Option<String>,
	/// Whether or not the record is a favourite
	pub favorite: bool,
	/// The fields associated with the record
	pub fields: Option<Vec<BitwardenField>>,
	/// The login information associated with the record
	pub login: Option<BitwardenLogin>,
	/// The secure note information associated with the record
	pub secure_note: Option<BitwardenSecureNote>,
	/// The card information associated with the record
	pub card: Option<BitwardenCard>,
	/// The identity information associated with the record
	pub identity: Option<BitwardenIdentity>,
	/// The IDs of the collections the record is in
	pub collection_ids: Option<Vec<String>>,
}

impl Display for BitwardenField {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"Name: {}\nValue: {}\nType: {}",
			self.name, self.value, self.type_
		)
	}
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
/// A field in a Bitwarden record
pub struct BitwardenField {
	/// The name of the field
	pub name: String,
	/// The value of the field
	pub value: String,
	#[serde(rename = "type")]
	/// The type of the field (see: <https://bitwarden.com/help/custom-fields/>).
	///
	/// Can be:
	/// - Text (0)
	/// - Hidden (1)
	/// - Boolean (2)
	///
	/// See: <https://bitwarden.com/help/cli/#enums>
	pub type_: usize,
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
/// A login Bitwarden record
pub struct BitwardenLogin {
	/// The URIs associated with the login record
	pub uris: Option<Vec<BitwardenURI>>,
	/// The username associated with the login record
	pub username: Option<String>,
	/// The password associated with the login record
	pub password: Option<String>,
	/// The TOTP associated with the login record
	pub totp: Option<String>,
}

impl Display for BitwardenLogin {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let uris_str = match self.uris {
			Some(ref uris) => {
				let mut uris_strs: Vec<String> = Vec::new();
				for uri in uris {
					uris_strs.push(uri.uri.clone());
				}
				uris_strs.join(", ")
			}
			None => String::from("None"),
		};
		write!(
			f,
			"Login URI: {}\nUsername: {}\nPassword: {}\nTOTP: {}",
			uris_str,
			self.username.clone().unwrap_or(String::from("None")),
			self.password.clone().unwrap_or(String::from("None")),
			self.totp.clone().unwrap_or(String::from("None"))
		)
	}
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
/// A URI in a Bitwarden login record
pub struct BitwardenURI {
	#[serde(rename = "match")]
	/// The match detection option of the URI (see: <https://bitwarden.com/help/uri-match-detection/#match-detection-options>).
	///
	/// Can be:
	/// - Domain (0)
	/// - Host (1)
	/// - Starts With (2)
	/// - Exact (3)
	/// - Regular Expression (4)
	/// - Never (5)
	///
	/// See: <https://bitwarden.com/help/cli/#enums>
	pub match_: Option<usize>,
	/// The URI
	pub uri: String,
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
/// A secure note Bitwarden record
pub struct BitwardenSecureNote {
	#[serde(rename = "type")]
	/// The type of the secure note
	pub type_: usize,
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
/// A card Bitwarden record
pub struct BitwardenCard {
	#[serde(rename = "cardholderName")]
	/// The cardholder name of the card
	pub cardholder_name: Option<String>,
	/// The brand of the card
	pub brand: Option<String>,
	/// The number of the card
	pub number: Option<String>,
	#[serde(rename = "expMonth")]
	/// The expiration month of the card
	pub exp_month: Option<String>,
	#[serde(rename = "expYear")]
	/// The expiration year of the card
	pub exp_year: Option<String>,
	/// The code of the card
	pub code: Option<String>,
}

impl Display for BitwardenCard {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"Cardholder name: {}\nBrand: {}\nNumber: {}\nExpiration month: {}\nExpiration year: {}\nCode: {}",
			self.cardholder_name.clone().unwrap_or(String::from("None")), self.brand.clone().unwrap_or(String::from("None")), self.number.clone().unwrap_or(String::from("None")), self.exp_month.clone().unwrap_or(String::from("None")), self.exp_year.clone().unwrap_or(String::from("None")), self.code.clone().unwrap_or(String::from("None"))
		)
	}
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
/// An identity Bitwarden record
pub struct BitwardenIdentity {
	/// The title of the person with the identity
	pub title: Option<String>,
	#[serde(rename = "firstName")]
	/// The first name of the person with the identity
	pub first_name: Option<String>,
	#[serde(rename = "middleName")]
	/// The middle name of the person with the identity
	pub middle_name: Option<String>,
	#[serde(rename = "lastName")]
	/// The last name of the person with the identity
	pub last_name: Option<String>,
	/// The first line of the address of the person with the identity
	pub address1: Option<String>,
	/// The second line of the address of the person with the identity
	pub address2: Option<String>,
	/// The third line of the address of the person with the identity
	pub address3: Option<String>,
	/// The city of the address of the person with the identity
	pub city: Option<String>,
	/// The state of the address of the person with the identity
	pub state: Option<String>,
	#[serde(rename = "postalCode")]
	/// The postal code of the address of the person with the identity
	pub postal_code: Option<String>,
	/// The country of the address of the person with the identity
	pub country: Option<String>,
	/// The company of the person with the identity
	pub company: Option<String>,
	/// The email of the person with the identity
	pub email: Option<String>,
	/// The phone of the person with the identity
	pub phone: Option<String>,
	/// The Social Security number of the person with the identity
	pub ssn: Option<String>,
	/// The username of the person with the identity
	pub username: Option<String>,
	#[serde(rename = "passportNumber")]
	/// The passport number of the person with the identity
	pub passport_number: Option<String>,
	#[serde(rename = "licenseNumber")]
	/// The license number of the person with the identity
	pub license_number: Option<String>,
}

impl Display for BitwardenIdentity {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"Title: {}\nFirst name: {}\nLast name: {}\nAddress 1: {}\nAddress 2: {}\nAddress 3: {}\nCity: {}\nState: {}\nPostal code: {}\nCountry: {}\nCompany: {}\nEmail: {}\nPhone: {}\nSSN: {}\nUsername: {}\nPassport number: {}\nLicense number: {}",
			self.title.clone().unwrap_or(String::from("None")), self.first_name.clone().unwrap_or(String::from("None")), self.last_name.clone().unwrap_or(String::from("None")), self.address1.clone().unwrap_or(String::from("None")), self.address2.clone().unwrap_or(String::from("None")), self.address3.clone().unwrap_or(String::from("None")), self.city.clone().unwrap_or(String::from("None")), self.state.clone().unwrap_or(String::from("None")), self.postal_code.clone().unwrap_or(String::from("None")), self.country.clone().unwrap_or(String::from("None")), self.company.clone().unwrap_or(String::from("None")), self.email.clone().unwrap_or(String::from("None")), self.phone.clone().unwrap_or(String::from("None")), self.ssn.clone().unwrap_or(String::from("None")), self.username.clone().unwrap_or(String::from("None")), self.passport_number.clone().unwrap_or(String::from("None")), self.license_number.clone().unwrap_or(String::from("None"))
		)
	}
}

/// Generates a random nonce for use with the XChaCha20Poly1305 cipher.
pub fn generate_nonce() -> XNonce {
	XChaCha20Poly1305::generate_nonce(&mut rand_core::OsRng)
}

/// Create a new vault from a user-supplied password.
///
/// # Arguments
///
/// * `password` - The user-supplied password.
pub fn create_vault_from_password(password: String) -> Vault {
	let salt = argon2::password_hash::SaltString::generate(&mut rand_core::OsRng);
	let key_and_salt = generate_key_from_password_and_salt(password, &salt);
	return Vault {
		salt: salt.as_bytes().to_owned(),
		key: key_and_salt.0,
		items: Vec::new(),
	};
}

/// Generate a vault's key from a user-supplied password and a pre-generated salt.
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
	let config = argon2::Argon2::new(
		argon2::Algorithm::default(),
		argon2::Version::default(),
		argon2::Params::new(1048576u32, 4u32, 4u32, None).unwrap(),
	);
	let key = config
		.hash_password(password.as_bytes(), &salt)
		.unwrap()
		.to_string();
	(key, salt)
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
pub fn encrypt_bytes(key: &String, bytes: &[u8], nonce_bytes: &[u8]) -> Vec<u8> {
	let enc_key = Key::from_slice(&key.as_bytes()[..32]);
	let aead = XChaCha20Poly1305::new(enc_key);

	aead.encrypt(XNonce::from_slice(nonce_bytes), bytes)
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
	let decrypted_serialised = decrypt_bytes(key, &encrypted_serialised, nonce);
	let decrypted: Secret = bincode::deserialize(&decrypted_serialised).unwrap();
	decrypted
}

impl Vault {
	/// Sorts entries by their last modified date & time, and then deduplicates items which have contents (and, optionally, names) in common.
	///
	/// # Arguments
	///
	/// * `ignore_names` - Whether or not to ignore common names in addition to common contents when deduplicating.
	pub fn deduplicate_items(&mut self, ignore_names: bool) -> &mut [(Entry, Vec<u8>)] {
		self.items.sort_by_cached_key(|x| x.0.last_modified);
		match ignore_names {
			true => self.items.partition_dedup_by(|a, b| a.0.hash == b.0.hash).1,
			false => {
				self.items
					.partition_dedup_by(|a, b| a.0.name == b.0.name && a.0.hash == b.0.hash)
					.1
			}
		}
	}

	/// Adds an item into a vault.
	///
	/// # Arguments
	///
	/// * `entry` - The entry to be added.
	///
	/// * `nonce` - The nonce used when encrypting the secret.
	pub fn add_item(&mut self, entry: Entry, nonce: Vec<u8>) {
		self.items.push((entry, nonce));
	}

	/// Remove an item from a vault.
	///
	/// # Arguments
	///
	/// * `entry` - The entry to be removed.
	pub fn remove_item(&mut self, entry: &Entry) {
		self.items = self.items.drain_filter(|x| x.0.id == entry.id).collect();
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
		let encrypted_serialised = encrypt_bytes(&self.key, &serialised, &item.nonce.clone());
		self.add_item(item.entry.clone(), item.nonce.clone());
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
								if !randomly_selected_word.is_empty()
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
								} else if randomly_selected_word.is_empty()
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

/// Analyses whether or not a password is sufficiently resistant against an attack.
///
/// Returns a tuple with a boolean and a string. The boolean is true if the password is sufficiently resistant against an attack, false otherwise.
///
/// The string is a message that explains whether the password is or is not sufficiently resistant against an attack, and, if not, some suggestions to give.
///
/// # Arguments
///
/// * `password` - The password to be analysed.
pub fn get_password_feedback(password: String) -> (bool, String) {
	let is_ok: bool;

	let analysed_password = analyzer::analyze(&password);
	let score = scorer::score(&analysed_password);

	let strength_estimate = zxcvbn(&password, &[]).unwrap();
	let warning_string = if strength_estimate.feedback().is_some() {
		match strength_estimate.feedback().as_ref().unwrap().warning() {
			Some(w) => format!("\nWarning: {}", Colour::Red.bold().paint(w.to_string())),
			None => "".to_owned(),
		}
	} else {
		"".to_owned()
	};
	let suggestions_string = if strength_estimate.feedback().is_some() {
		let suggestions = strength_estimate.feedback().as_ref().unwrap().suggestions();
		match suggestions.is_empty() {
			false => format!(
				"\n{}:\n{}",
				Colour::Yellow.bold().paint("Suggestions"),
				suggestions
					.iter()
					.map(|s| " - ".to_owned() + &s.to_string())
					.collect_vec()
					.join("\n")
			),
			true => "".to_owned(),
		}
	} else {
		"".to_owned()
	};
	let feedback = if strength_estimate.score() < 3 || score < 80.0 {
		is_ok = false;
		format!(
			"\n{}{}{}",
			Colour::Red
				.bold()
				.paint("❌ This password is insecure and should not be used."),
			warning_string,
			suggestions_string
		)
	} else if strength_estimate.score() >= 3 && score >= 80.0 {
		is_ok = true;
		format!(
			"\n{}",
			Colour::Green
				.bold()
				.paint("✔️ This password is sufficiently safe to use.")
		)
	} else {
		is_ok = false;
		format!(
			"\n{}{}{}",
			Colour::Yellow
				.bold()
				.paint("⚠️ This password may not be secure."),
			warning_string,
			suggestions_string
		)
	};

	(is_ok, feedback)
}

/// Gets a list of secrets from an exported Bitwarden vault.
///
/// # Arguments
///
/// * `path` - The path to the exported Bitwarden vault.
pub fn get_secrets_from_bitwarden(path: PathBuf) -> Result<Vec<Secret>, &'static str> {
	match path.extension().unwrap().to_str().unwrap() {
		"csv" => Ok(get_secrets_from_bitwarden_csv(path)),
		"json" => Ok(get_secrets_from_bitwarden_json(path)),
		_ => Err("Invalid file extension."),
	}
}

/// Gets a list of secrets from an exported Bitwarden vault in JSON format.
///
/// # Arguments
///
/// * `path` - The path to the exported Bitwarden vault.
pub fn get_secrets_from_bitwarden_json(path: PathBuf) -> Vec<Secret> {
	let file = std::fs::File::open(path).unwrap();
	let reader = std::io::BufReader::new(file);

	let mut secrets: Vec<Secret> = Vec::new();

	let json_reader: BitwardenVault = serde_json::from_reader(reader).unwrap();

	for record in json_reader.items.clone() {
		let fields_str = match record.fields.clone() {
			Some(fields) => {
				let mut fields_strs: Vec<String> = Vec::new();
				for field in fields {
					fields_strs.push(field.to_string());
				}
				fields_strs.join("\n")
			}
			None => String::from("None"),
		};
		let value_str = match record.type_ {
			1 => record.login.clone().unwrap().to_string(),
			2 => "Type: Secure note".to_string(),
			3 => record.card.clone().unwrap().to_string(),
			4 => record.identity.clone().unwrap().to_string(),
			_ => "".to_string(),
		};

		let contents = format!(
			"{}\nNotes:\n{}\nFields:\n{}\n",
			value_str,
			record.notes.clone().unwrap_or(String::from("None")),
			fields_str
		);

		let mut hasher = Blake2bVar::new(64).unwrap();
		hasher.update(contents.as_bytes());
		let mut content_hash = [0u8; 64];
		hasher.finalize_variable(&mut content_hash).unwrap();

		let new_entry = Entry {
			name: record.name.clone(),
			id: Uuid::new_v4(),
			hash: content_hash.to_vec(),
			last_modified: chrono::offset::Utc::now(),
		};

		let new_secret = Secret {
			entry: new_entry,
			contents: contents.as_bytes().to_vec(),
			nonce: generate_nonce().to_vec(),
		};

		secrets.push(new_secret);
	}

	secrets
}

/// Gets a list of secrets from an exported Bitwarden vault in CSV format.
///
/// # Arguments
///
/// * `path` - The path to the exported Bitwarden vault.
pub fn get_secrets_from_bitwarden_csv(path: PathBuf) -> Vec<Secret> {
	let file = std::fs::File::open(path).unwrap();
	let reader = std::io::BufReader::new(file);

	let mut secrets: Vec<Secret> = Vec::new();

	let mut csv_reader = csv::Reader::from_reader(reader);
	for result in csv_reader.deserialize() {
		let record: BitwardenRecordCSV = result.unwrap();

		let fields_str = match record.fields.clone() {
			Some(fields) => {
				let mut fields_strs: Vec<String> = Vec::new();
				for field in fields {
					fields_strs.push(field.to_string());
				}
				fields_strs.join("\n")
			}
			None => String::from("None"),
		};
		let contents = format!("Login URI: {}\nLogin username: {}\nLogin password: {}\nLogin TOTP: {}\nNotes:\n{}\nFields:\n{}\n", record.login_uri.clone().unwrap_or(String::from("None")), record.login_username.clone().unwrap_or(String::from("None")), record.login_password.clone().unwrap_or(String::from("None")), record.login_totp.clone().unwrap_or(String::from("None")), record.notes.clone().unwrap_or(String::from("None")), fields_str);

		let mut hasher = Blake2bVar::new(64).unwrap();
		hasher.update(contents.as_bytes());
		let mut content_hash = [0u8; 64];
		hasher.finalize_variable(&mut content_hash).unwrap();

		let new_entry = Entry {
			name: record.name.clone(),
			id: Uuid::new_v4(),
			hash: content_hash.to_vec(),
			last_modified: chrono::offset::Utc::now(),
		};

		let new_secret = Secret {
			entry: new_entry,
			contents: contents.as_bytes().to_vec(),
			nonce: generate_nonce().to_vec(),
		};

		secrets.push(new_secret);
	}
	secrets
}
