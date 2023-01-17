use crate::{generate_nonce, Entry, Secret};
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use blake2::digest::Update;
use blake2::digest::VariableOutput;
use blake2::Blake2bVar;
use core::fmt::Display;
use core::fmt::Formatter;
use core::str;
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
/// A record in a Bitwarden vault exported in CSV format
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
	fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
		write!(
			f,
			"Title: {}\nFirst name: {}\nLast name: {}\nAddress 1: {}\nAddress 2: {}\nAddress 3: {}\nCity: {}\nState: {}\nPostal code: {}\nCountry: {}\nCompany: {}\nEmail: {}\nPhone: {}\nSSN: {}\nUsername: {}\nPassport number: {}\nLicense number: {}",
			self.title.clone().unwrap_or(String::from("None")), self.first_name.clone().unwrap_or(String::from("None")), self.last_name.clone().unwrap_or(String::from("None")), self.address1.clone().unwrap_or(String::from("None")), self.address2.clone().unwrap_or(String::from("None")), self.address3.clone().unwrap_or(String::from("None")), self.city.clone().unwrap_or(String::from("None")), self.state.clone().unwrap_or(String::from("None")), self.postal_code.clone().unwrap_or(String::from("None")), self.country.clone().unwrap_or(String::from("None")), self.company.clone().unwrap_or(String::from("None")), self.email.clone().unwrap_or(String::from("None")), self.phone.clone().unwrap_or(String::from("None")), self.ssn.clone().unwrap_or(String::from("None")), self.username.clone().unwrap_or(String::from("None")), self.passport_number.clone().unwrap_or(String::from("None")), self.license_number.clone().unwrap_or(String::from("None"))
		)
	}
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
