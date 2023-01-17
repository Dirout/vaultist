use crate::{generate_nonce, Entry, Secret};
use alloc::borrow::ToOwned;
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
/// A record in a Google Chrome vault
pub struct ChromeRecord {
	/// The name of the record
	pub name: Option<String>,
	/// The URL of the record
	pub url: String,
	/// The username of the record
	pub username: Option<String>,
	/// The password of the record
	pub password: String,
}

/// Gets a list of secrets from an exported Google Chrome vault.
///
/// # Arguments
///
/// * `path` - The path to the exported Google Chrome vault.
pub fn get_secrets_from_chrome(path: PathBuf) -> Vec<Secret> {
	let file = std::fs::File::open(path).unwrap();
	let reader = std::io::BufReader::new(file);

	let mut secrets: Vec<Secret> = Vec::new();

	let mut csv_reader = csv::Reader::from_reader(reader);
	for result in csv_reader.deserialize() {
		let record: ChromeRecord = result.unwrap();

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

		let record_name = if let Some(name) = &record.name {
			name.to_owned()
		} else {
			format!(
				"{} ({})",
				Url::parse(&record.url).unwrap().host_str().unwrap(),
				record
					.username
					.clone()
					.unwrap_or(String::from("no username"))
			)
		};

		let new_entry = Entry {
			name: record_name,
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
