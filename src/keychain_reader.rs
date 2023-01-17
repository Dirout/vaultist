#![warn(missing_docs)]

use crate::{generate_nonce, Entry, Secret};
use alloc::format;
use alloc::str;
use alloc::string::String;
use alloc::vec::Vec;
use blake2::digest::Update;
use blake2::digest::VariableOutput;
use blake2::Blake2bVar;
use derive_more::{Constructor, From};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

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
/// A record in an iCloud Keychain vault
pub struct KeychainRecord {
	/// The title of the record
	#[serde(rename = "Title")]
	pub title: String,
	/// The URL of the record
	#[serde(rename = "URL")]
	pub url: String,
	/// The username of the record
	#[serde(rename = "Username")]
	pub username: Option<String>,
	/// The password of the record
	#[serde(rename = "Password")]
	pub password: String,
	/// The notes of the record
	#[serde(rename = "Notes")]
	pub notes: Option<String>,
	/// The OTP information of the record
	#[serde(rename = "OTPAuth")]
	pub otp_auth: Option<String>,
}

/// Gets a list of secrets from an exported iCloud Keychain vault.
///
/// # Arguments
///
/// * `path` - The path to the exported iCloud Keychain vault.
pub fn get_secrets_from_keychain(path: PathBuf) -> Vec<Secret> {
	let file = std::fs::File::open(path).unwrap();
	let reader = std::io::BufReader::new(file);

	let mut secrets: Vec<Secret> = Vec::new();

	let mut csv_reader = csv::Reader::from_reader(reader);
	for result in csv_reader.deserialize() {
		let record: KeychainRecord = result.unwrap();

		let contents = format!(
			"URL: {}\nUsername: {}\nPassword: {}\nNotes:\n{}\nOTP: {}",
			record.url.clone(),
			record.username.clone().unwrap_or(String::from("None")),
			record.password.clone(),
			record.notes.clone().unwrap_or(String::from("None")),
			record.otp_auth.clone().unwrap_or(String::from("None"))
		);

		let mut hasher = Blake2bVar::new(64).unwrap();
		hasher.update(contents.as_bytes());
		let mut content_hash = [0u8; 64];
		hasher.finalize_variable(&mut content_hash).unwrap();

		let new_entry = Entry {
			name: record.title.clone(),
			id: Uuid::now_v7(),
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
