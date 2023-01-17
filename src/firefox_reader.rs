use crate::{generate_nonce, Entry, Secret};
use alloc::format;
use alloc::str;
use alloc::string::String;
use alloc::vec::Vec;
use blake2::digest::Update;
use blake2::digest::VariableOutput;
use blake2::Blake2bVar;
use chrono::NaiveDateTime;
use chrono::Utc;
use derive_more::{Constructor, From};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;
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
/// A record in a Firefox vault
pub struct FirefoxRecord {
	/// The URL of the record
	pub url: String,
	/// The username of the record
	pub username: Option<String>,
	/// The password of the record
	pub password: String,
	#[serde(rename = "httpRealm")]
	/// The HTTP realm of the record
	pub http_realm: Option<String>,
	#[serde(rename = "formActionOrigin")]
	/// The form action where the record originated from
	pub form_action_origin: String,
	/// The ID of the record
	pub guid: String,
	#[serde(rename = "timeCreated")]
	/// The time the record was created
	pub time_created: u64,
	#[serde(rename = "timeLastUsed")]
	/// The time the record was last used (or when it was created, if not yet used)
	pub time_last_used: u64,
	#[serde(rename = "timePasswordChanged")]
	/// The time the record's password was last changed (or when it was created, if not yet changed)
	pub time_password_changed: u64,
}

/// Gets a list of secrets from an exported Firefox vault.
///
/// # Arguments
///
/// * `path` - The path to the exported Firefox vault.
pub fn get_secrets_from_firefox(path: PathBuf) -> Vec<Secret> {
	let file = std::fs::File::open(path).unwrap();
	let reader = std::io::BufReader::new(file);

	let mut secrets: Vec<Secret> = Vec::new();

	let mut csv_reader = csv::Reader::from_reader(reader);
	for result in csv_reader.deserialize() {
		let record: FirefoxRecord = result.unwrap();

		let contents = format!(
			"URL: {}\nUsername: {}\nPassword: {}",
			record.url,
			record.username.clone().unwrap_or(String::from("None")),
			record.password
		);

		let mut hasher = Blake2bVar::new(64).unwrap();
		hasher.update(contents.as_bytes());
		let mut content_hash = [0u8; 64];
		hasher.finalize_variable(&mut content_hash).unwrap();

		let new_entry = Entry {
			name: format!(
				"{} ({})",
				Url::parse(&record.url).unwrap().host_str().unwrap(),
				record
					.username
					.clone()
					.unwrap_or(String::from("no username"))
			),
			id: Uuid::now_v7(),
			hash: content_hash.to_vec(),
			last_modified: chrono::DateTime::<Utc>::from_utc(
				NaiveDateTime::from_timestamp_millis(
					record.time_password_changed.try_into().unwrap(),
				)
				.unwrap(),
				Utc,
			),
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
