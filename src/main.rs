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
	html_logo_url = "https://github.com/Dirout/vaultist/raw/master/branding/icon.png",
	html_favicon_url = "https://github.com/Dirout/vaultist/raw/master/branding/icon.png"
)]
#![feature(panic_info_message)]
#![feature(drain_filter)]
#![feature(exclusive_range_pattern)]
#![feature(int_roundings)]

use ansi_term::Colour;
use argon2::{PasswordHash, PasswordVerifier};
use blake2::digest::Update;
use blake2::digest::VariableOutput;
use blake2::Blake2bVar;
use clap::{arg, crate_version, value_parser, ArgMatches, Command};
use dialoguer::console::Term;
use dialoguer::theme::ColorfulTheme;
use dialoguer::{FuzzySelect, Input};
use filenamify::filenamify;
use itertools::Itertools;
use lazy_static::lazy_static;
use miette::miette;
use mimalloc::MiMalloc;
use passwords::{analyzer, scorer, PasswordGenerator};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use stopwatch::Stopwatch;
use tantivy::collector::TopDocs;
use tantivy::directory::MmapDirectory;
use tantivy::query::QueryParser;
use tantivy::schema::{Schema, STORED, TEXT};
use tantivy::{doc, DocAddress, Index, Score};
use uuid::Uuid;
use zxcvbn::zxcvbn;

#[global_allocator]
/// The global memory allocator
static GLOBAL: MiMalloc = MiMalloc;

lazy_static! {
	/// The command-line interface (CLI) of Vaultist
	static ref MATCHES: ArgMatches = Command::new("Vaultist")
	.version(crate_version!())
	.author("Emil Sayahi")
	.about("Vaultist is a tool to store your secrets in a vault, able to be opened by one password as the key.")
	.subcommand(Command::new("show")
		.about("Shows information regarding the usage and handling of this software")
		.arg(arg!(-w --warranty "Prints warranty information"))
		.arg(arg!(-c --conditions "Prints conditions information")))
	.subcommand(Command::new("new").about("Create a new vault using a user-supplied password.")
		.arg(arg!(PATH: "Where to store the vault in the filesystem").required(true).value_parser(value_parser!(PathBuf))))
	.subcommand(Command::new("add").about("Adds a new item to a vault")
		.arg(arg!(PATH: "Path to a vault in the filesystem").required(true).value_parser(value_parser!(PathBuf))))
	.subcommand(Command::new("see").about("View an item in the vault")
		.arg(arg!(PATH: "Path to a vault in the filesystem").required(true).value_parser(value_parser!(PathBuf))))
	.subcommand(Command::new("change").about("Modify an item in the vault")
		.arg(arg!(PATH: "Path to a vault in the filesystem").required(true).value_parser(value_parser!(PathBuf))))
	.subcommand(Command::new("remove").about("Removes an item in the vault")
		.arg(arg!(PATH: "Path to a vault in the filesystem").required(true).value_parser(value_parser!(PathBuf))))
	.subcommand(Command::new("deduplicate").about("Removes all duplicate entries in the vault")
		.arg(arg!(PATH: "Path to a vault in the filesystem").required(true).value_parser(value_parser!(PathBuf)))
		.arg(arg!(-n --ignore_names "Whether or not to ignore common names in addition to common contents when deduplicating").required(false).value_parser(value_parser!(bool))))
	.subcommand(Command::new("generate").about("Generates at least one password")
		.arg(arg!(count: "The number of passwords to generate").required(false).default_value("1").allow_negative_numbers(false).value_parser(value_parser!(usize)))
		.arg(arg!(length: "The length of the generated passwords").required(false).default_value("8").allow_negative_numbers(false).value_parser(value_parser!(usize)))
		.arg(arg!(-n --numbers "Passwords are allowed to, or must if `strict` is true, contain at least one number").required(false).value_parser(value_parser!(bool)))
		.arg(arg!(-o --lowercase_letters "Passwords are allowed to, or must if `strict` is true, contain at least one lowercase letter").required(false).value_parser(value_parser!(bool)))
		.arg(arg!(-u --uppercase_letters "Passwords are allowed to, or must if `strict` is true, contain at least one uppercase letter").required(false).value_parser(value_parser!(bool)))
		.arg(arg!(-m --symbols "Passwords are allowed to, or must if `strict` is true, contain at least one special character").required(false).value_parser(value_parser!(bool)))
		.arg(arg!(-s --spaces "Passwords are allowed to, or must if `strict` is true, contain at least one space").required(false).value_parser(value_parser!(bool)))
		.arg(arg!(-e --exclude_similar_characters "Whether or not to exclude similar looking ASCII characters (iI1loO0\"'`|)").required(false).value_parser(value_parser!(bool)))
		.arg(arg!(-t --strict "Whether or not the password rules are strictly followed for each generated password").required(false).value_parser(value_parser!(bool))))
	.subcommand(Command::new("analyse").about("Analyses a password")
		.arg(arg!(password: "The password to be analysed").required(false).value_parser(value_parser!(String))))
	.get_matches_from(wild::args());
}

/// The main function of Vaultist's CLI
fn main() {
	let stdout = std::io::stdout();
	let lock = stdout.lock();
	let mut buf_out = BufWriter::new(lock);

	std::panic::set_hook(Box::new(|e| {
		println!(
			"{}",
			miette!(
				"{}\nDefined in: {}:{}:{}",
				format!("{}", e.message().unwrap())
					.replace("called `Result::unwrap()` on an `Err` value", "Error"),
				e.location().unwrap().file(),
				e.location().unwrap().line(),
				e.location().unwrap().column()
			)
			.to_string()
		);
	}));
	// miette::set_hook(Box::new(|_| {
	// 	Box::new(
	// 		miette::MietteHandlerOpts::new()
	// 			.terminal_links(true)
	// 			.unicode(true)
	// 			.context_lines(3)
	// 			.tab_width(4)
	// 			.with_cause_chain()
	// 			.graphical_theme(miette::GraphicalTheme::unicode())
	// 			.build(),
	// 	)
	// }))
	// .unwrap();

	writeln!(
		buf_out,
		"
    Vaultist  Copyright (C) 2022-2023  Emil Sayahi
    This program comes with ABSOLUTELY NO WARRANTY; for details type `vaultist show -w'.
    This is free software, and you are welcome to redistribute it
    under certain conditions; type `vaultist show -c' for details.
    "
	)
	.unwrap();

	match MATCHES.subcommand() {
		Some(("show", show_matches)) => {
			show(show_matches);
		}
		Some(("new", new_matches)) => {
			new_vault(new_matches);
		}
		Some(("add", add_matches)) => {
			add_item(add_matches);
		}
		Some(("see", see_matches)) => {
			see_item(see_matches);
		}
		Some(("change", change_matches)) => {
			change_item(change_matches);
		}
		Some(("remove", remove_matches)) => {
			remove_item(remove_matches);
		}
		Some(("deduplicate", deduplicate_matches)) => {
			deduplicate_items(deduplicate_matches);
		}
		Some(("generate", generate_matches)) => {
			generate_passwords(generate_matches);
		}
		Some(("analyse", analyse_matches)) => {
			analyse_password(analyse_matches);
		}
		None => writeln!(buf_out, "Vaultist {}", crate_version!()).unwrap(),
		_ => unreachable!(), // If all subcommands are defined above, anything else is unreachable!()
	}
}

/// Create a new vault using a user-supplied password.
///
/// # Arguments
///
/// * `PATH` - Where to store the vault in the filesystem (required).
fn new_vault(matches: &clap::ArgMatches) {
	let stdin = std::io::stdin();
	let stdout = std::io::stdout();
	let stdin_lock = stdin.lock();
	let stdout_lock = stdout.lock();
	let mut buf_in = BufReader::new(stdin_lock);
	let mut buf_out = BufWriter::new(stdout_lock);

	let path_buf_input = matches
		.get_one::<PathBuf>("PATH")
		.ok_or(miette!("❌ No path was given"))
		.unwrap();
	let path_buf = match std::fs::canonicalize(path_buf_input) {
		Ok(p) => p,
		Err(_) => std::env::current_dir()
			.unwrap()
			.join(path_clean::clean(path_buf_input.to_str().unwrap())),
	};

	let init_attempt_password = rpassword::prompt_password_from_bufread(
		&mut buf_in,
		&mut buf_out,
		"🔑 Enter a password for your new vault: ",
	)
	.unwrap();
	let confirm_attempt_password = rpassword::prompt_password_from_bufread(
		&mut buf_in,
		&mut buf_out,
		"🔑 Enter your password again to confirm it: ",
	)
	.unwrap();
	assert!(
		init_attempt_password == confirm_attempt_password,
		"❌ Password could not be confirmed."
	);
	let password_feedback = vaultist::get_password_feedback(init_attempt_password);
	assert!(password_feedback.0, "{}", password_feedback.1);

	let new_vault = vaultist::create_vault_from_password(confirm_attempt_password);
	let verify_attempt_password = rpassword::prompt_password_from_bufread(
		&mut buf_in,
		&mut buf_out,
		"🔑 Enter your password again to verify that it can unlock the vault: ",
	)
	.unwrap();
	assert!(
		argon2::Argon2::default()
			.verify_password(
				verify_attempt_password.as_bytes(),
				&PasswordHash::new(&new_vault.key).unwrap()
			)
			.is_ok(),
		"❌ Could not create a secure vault with that password."
	);

	let mut timer = Stopwatch::start_new(); // Start the stopwatch

	write_file(
		path_buf.join(".vaultist-vault"),
		&bincode::serialize(&new_vault).unwrap(),
	);

	// Show how long it took to perform operation
	timer.stop();
	writeln!(
		buf_out,
		"\n⏰ Created new vault in {} seconds.",
		(timer.elapsed_ms() as f32 / 1000.0)
	)
	.unwrap();
}

/// Adds a new item to a vault.
///
/// # Arguments
///
/// * `PATH` - Path to a vault in the filesystem (required).
fn add_item(matches: &clap::ArgMatches) {
	let stdin = std::io::stdin();
	let stdout = std::io::stdout();
	let stdin_lock = stdin.lock();
	let stdout_lock = stdout.lock();
	let mut buf_in = BufReader::new(stdin_lock);
	let mut buf_out = BufWriter::new(stdout_lock);

	let path_buf_input = matches
		.get_one::<PathBuf>("PATH")
		.ok_or(miette!("❌ No path was given"))
		.unwrap();
	let path_buf = match std::fs::canonicalize(path_buf_input) {
		Ok(p) => p,
		Err(_) => std::env::current_dir()
			.unwrap()
			.join(path_clean::clean(path_buf_input.to_str().unwrap())),
	};

	let mut deserialised_vault: vaultist::Vault =
		bincode::deserialize(&read_file(path_buf.join(".vaultist-vault"))).unwrap();
	let verify_password = rpassword::prompt_password_from_bufread(
		&mut buf_in,
		&mut buf_out,
		"🔑 Enter your vault password: ",
	)
	.unwrap();
	assert!(
		argon2::Argon2::default()
			.verify_password(
				verify_password.as_bytes(),
				&PasswordHash::new(&deserialised_vault.key).unwrap()
			)
			.is_ok(),
		"❌ Could not access vault with that password."
	);

	let entry_name: String = Input::new()
		.with_prompt("❓ Provide a name for your new secret")
		.allow_empty(false)
		.interact_text_on(&Term::buffered_stdout())
		.unwrap();
	println!("📝 Provide the value of \'{entry_name}\' … ");
	let secret_contents = edit::edit("").unwrap();

	let mut timer = Stopwatch::start_new(); // Start the stopwatch

	let mut hasher = Blake2bVar::new(64).unwrap();
	hasher.update(secret_contents.as_bytes());
	let mut content_hash = [0u8; 64];
	hasher.finalize_variable(&mut content_hash).unwrap();

	let new_entry = vaultist::Entry {
		name: entry_name,
		hash: content_hash.to_vec(),
		id: Uuid::new_v4(),
		last_modified: chrono::offset::Utc::now(),
	};
	let nonce = vaultist::generate_nonce();
	let mut new_secret = vaultist::Secret {
		entry: new_entry.clone(),
		contents: secret_contents.into_bytes(),
		nonce: nonce.to_vec(),
	};
	let encrypted_secret = deserialised_vault.encrypt_secret(&mut new_secret);
	write_file(
		path_buf.join(filenamify(new_entry.id.to_string() + ".vaultist")),
		&encrypted_secret,
	);

	write_file(
		path_buf.join(".vaultist-vault"),
		&bincode::serialize(&deserialised_vault).unwrap(),
	);

	let mut schema_builder = Schema::builder();
	let name = schema_builder.add_text_field("title", TEXT | STORED);
	let id = schema_builder.add_text_field("id", TEXT | STORED);
	let last_modified = schema_builder.add_text_field("last_modified", TEXT | STORED);
	let schema = schema_builder.build();
	let index = Index::open_or_create(MmapDirectory::open(path_buf).unwrap(), schema).unwrap();
	let mut index_writer = index.writer(100_000_000).unwrap();
	index_writer
		.add_document(doc!(
			name => new_entry.clone().name,
			id => new_entry.id.to_string(),
			last_modified => new_entry.last_modified.to_rfc2822(),
		))
		.unwrap();
	index_writer.commit().unwrap();

	// Show how long it took to perform operation
	timer.stop();
	writeln!(
		buf_out,
		"\n⏰ Added new entry to vault in {} seconds.",
		(timer.elapsed_ms() as f32 / 1000.0)
	)
	.unwrap();
}

/// View an item in the vault.
///
/// # Arguments
///
/// * `PATH` - Path to a vault in the filesystem (required).
fn see_item(matches: &clap::ArgMatches) {
	let stdin = std::io::stdin();
	let stdout = std::io::stdout();
	let stdin_lock = stdin.lock();
	let stdout_lock = stdout.lock();
	let mut buf_in = BufReader::new(stdin_lock);
	let mut buf_out = BufWriter::new(stdout_lock);

	let path_buf_input = matches
		.get_one::<PathBuf>("PATH")
		.ok_or(miette!("❌ No path was given"))
		.unwrap();
	let path_buf = match std::fs::canonicalize(path_buf_input) {
		Ok(p) => p,
		Err(_) => std::env::current_dir()
			.unwrap()
			.join(path_clean::clean(path_buf_input.to_str().unwrap())),
	};

	let deserialised_vault: vaultist::Vault =
		bincode::deserialize(&read_file(path_buf.join(".vaultist-vault"))).unwrap();
	let verify_password = rpassword::prompt_password_from_bufread(
		&mut buf_in,
		&mut buf_out,
		"🔑 Enter your vault password: ",
	)
	.unwrap();
	assert!(
		argon2::Argon2::default()
			.verify_password(
				verify_password.as_bytes(),
				&PasswordHash::new(&deserialised_vault.key).unwrap()
			)
			.is_ok(),
		"❌ Could not access vault with that password."
	);

	let mut schema_builder = Schema::builder();
	let name = schema_builder.add_text_field("title", TEXT | STORED);
	let id = schema_builder.add_text_field("id", TEXT | STORED);
	let last_modified = schema_builder.add_text_field("last_modified", TEXT | STORED);
	let schema = schema_builder.build();
	let index =
		Index::open_or_create(MmapDirectory::open(path_buf.clone()).unwrap(), schema).unwrap();
	let reader = index.reader().unwrap();
	let searcher = reader.searcher();
	let query_parser = QueryParser::for_index(&index, vec![name, id, last_modified]);

	let search_query: String = Input::new()
		.with_prompt("❓ Search for the secret you're trying to view")
		.allow_empty(false)
		.interact_text_on(&Term::buffered_stdout())
		.unwrap();
	let query = query_parser.parse_query(&search_query).unwrap();
	let results: Vec<(Score, DocAddress)> = searcher
		.search(&query, &TopDocs::with_limit(deserialised_vault.items.len()))
		.unwrap();

	let mut result_options: HashMap<String, Uuid> = HashMap::new();
	let mut i = 1;
	for (_score, doc_address) in results {
		let retrieved_doc = searcher.doc(doc_address).unwrap();
		let retrieved_id = retrieved_doc.get_first(id).unwrap().as_text().unwrap();
		let retrieved_date = retrieved_doc
			.get_first(last_modified)
			.unwrap()
			.as_text()
			.unwrap();
		result_options.insert(
			format!(
				"{}. {} ({}; {})",
				i,
				retrieved_doc.get_first(name).unwrap().as_text().unwrap(),
				retrieved_id,
				retrieved_date
			),
			Uuid::parse_str(retrieved_id).unwrap(),
		);
		i += 1;
	}

	let result_options_keys: Vec<&String> = result_options.keys().collect();
	let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
		.items(&result_options_keys)
		.with_prompt("Select the secret you're trying to view: ")
		.report(true)
		.highlight_matches(true)
		.interact_on_opt(&Term::buffered_stderr())
		.unwrap()
		.unwrap();

	let deserialised_vault_items_clone = deserialised_vault.items.clone();
	let selected_item = deserialised_vault_items_clone
		.iter()
		.filter_map(|val| {
			if val.0.id == *result_options.values().nth(selection).unwrap() {
				Some(val)
			} else {
				None
			}
		})
		.last()
		.unwrap();

	let mut timer = Stopwatch::start_new(); // Start the stopwatch
	let entry_nonce_map: HashMap<vaultist::Entry, Vec<u8>> =
		deserialised_vault.items.clone().into_iter().collect();
	let item_nonce = entry_nonce_map.get(&selected_item.0).unwrap();
	let encrypted_secret =
		read_file(path_buf.join(filenamify(selected_item.0.id.to_string() + ".vaultist")));
	let decrypted_secret = vaultist::decrypt_secret(
		deserialised_vault.key.clone(),
		encrypted_secret,
		item_nonce.to_owned(),
	);
	writeln!(
		buf_out,
		"\n{} ({}):\n\n{}\n\n{} {}\n",
		Colour::Yellow
			.bold()
			.paint(decrypted_secret.entry.name.clone()),
		Colour::Fixed(7).paint(decrypted_secret.entry.id.to_string()),
		Colour::Cyan.paint(String::from_utf8(decrypted_secret.contents.clone()).unwrap()),
		Colour::Yellow.bold().paint("Last modified:"),
		Colour::Fixed(7).paint(decrypted_secret.entry.last_modified.to_rfc2822())
	)
	.unwrap();

	// Show how long it took to perform operation
	timer.stop();
	writeln!(
		buf_out,
		"\n⏰ Decrypted vault entry in {} seconds.",
		(timer.elapsed_ms() as f32 / 1000.0)
	)
	.unwrap();
}

/// Modify an item in the vault.
///
/// # Arguments
///
/// * `PATH` - Path to a vault in the filesystem (required).
fn change_item(matches: &clap::ArgMatches) {
	let stdin = std::io::stdin();
	let stdout = std::io::stdout();
	let stdin_lock = stdin.lock();
	let stdout_lock = stdout.lock();
	let mut buf_in = BufReader::new(stdin_lock);
	let mut buf_out = BufWriter::new(stdout_lock);

	let path_buf_input = matches
		.get_one::<PathBuf>("PATH")
		.ok_or(miette!("❌ No path was given"))
		.unwrap();
	let path_buf = match std::fs::canonicalize(path_buf_input) {
		Ok(p) => p,
		Err(_) => std::env::current_dir()
			.unwrap()
			.join(path_clean::clean(path_buf_input.to_str().unwrap())),
	};

	let mut deserialised_vault: vaultist::Vault =
		bincode::deserialize(&read_file(path_buf.join(".vaultist-vault"))).unwrap();
	let verify_password = rpassword::prompt_password_from_bufread(
		&mut buf_in,
		&mut buf_out,
		"🔑 Enter your vault password: ",
	)
	.unwrap();
	assert!(
		argon2::Argon2::default()
			.verify_password(
				verify_password.as_bytes(),
				&PasswordHash::new(&deserialised_vault.key).unwrap()
			)
			.is_ok(),
		"❌ Could not access vault with that password."
	);

	let mut schema_builder = Schema::builder();
	let name = schema_builder.add_text_field("title", TEXT | STORED);
	let id = schema_builder.add_text_field("id", TEXT | STORED);
	let last_modified = schema_builder.add_text_field("last_modified", TEXT | STORED);
	let schema = schema_builder.build();
	let index =
		Index::open_or_create(MmapDirectory::open(path_buf.clone()).unwrap(), schema).unwrap();
	let reader = index.reader().unwrap();
	let searcher = reader.searcher();
	let query_parser = QueryParser::for_index(&index, vec![name, id, last_modified]);

	let search_query: String = Input::new()
		.with_prompt("❓ Search for the secret you're trying to modify")
		.allow_empty(false)
		.interact_text_on(&Term::buffered_stdout())
		.unwrap();
	let query = query_parser.parse_query(&search_query).unwrap();
	let results: Vec<(Score, DocAddress)> = searcher
		.search(&query, &TopDocs::with_limit(deserialised_vault.items.len()))
		.unwrap();

	let mut result_options: HashMap<String, Uuid> = HashMap::new();
	let mut i = 1;
	for (_score, doc_address) in results {
		let retrieved_doc = searcher.doc(doc_address).unwrap();
		let retrieved_id = retrieved_doc.get_first(id).unwrap().as_text().unwrap();
		let retrieved_date = retrieved_doc
			.get_first(last_modified)
			.unwrap()
			.as_text()
			.unwrap();
		result_options.insert(
			format!(
				"{}. {} ({}; {})",
				i,
				retrieved_doc.get_first(name).unwrap().as_text().unwrap(),
				retrieved_id,
				retrieved_date
			),
			Uuid::parse_str(retrieved_id).unwrap(),
		);
		i += 1;
	}

	let result_options_keys: Vec<&String> = result_options.keys().collect();
	let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
		.items(&result_options_keys)
		.with_prompt("Select the secret you're trying to modify: ")
		.report(true)
		.highlight_matches(true)
		.interact_on_opt(&Term::buffered_stderr())
		.unwrap()
		.unwrap();

	let selected_item = deserialised_vault
		.items
		.iter()
		.filter_map(|val| {
			if val.0.id == *result_options.values().nth(selection).unwrap() {
				Some(val)
			} else {
				None
			}
		})
		.last()
		.unwrap();

	let encrypted_secret = read_file(path_buf.join(filenamify(
		selected_item.clone().0.id.to_string() + ".vaultist",
	)));
	let decrypted_secret = vaultist::decrypt_secret(
		deserialised_vault.clone().key.clone(),
		encrypted_secret,
		selected_item.clone().1,
	);

	writeln!(
		buf_out,
		"📝 Provide the new name of \'{}\' … ",
		decrypted_secret.entry.name
	)
	.unwrap();
	let new_entry_name = edit::edit(decrypted_secret.clone().entry.name.clone())
		.unwrap()
		.replace('\n', "");

	writeln!(
		buf_out,
		"📝 Provide the new contents of \'{}\' … ",
		decrypted_secret.entry.name
	)
	.unwrap();
	let new_secret_contents = edit::edit(decrypted_secret.clone().contents.clone()).unwrap();

	let mut hasher = Blake2bVar::new(64).unwrap();
	hasher.update(new_secret_contents.as_bytes());
	let mut secret_hash = [0u8; 64];
	hasher.finalize_variable(&mut secret_hash).unwrap();

	let new_entry = vaultist::Entry {
		name: new_entry_name,
		hash: secret_hash.to_vec(),
		id: decrypted_secret.entry.id,
		last_modified: chrono::offset::Utc::now(),
	};
	let entry_nonce_map: HashMap<vaultist::Entry, Vec<u8>> =
		deserialised_vault.items.clone().into_iter().collect();
	let entry_nonce = entry_nonce_map
		.get(&decrypted_secret.clone().entry.clone())
		.unwrap();
	let mut new_secret = vaultist::Secret {
		entry: new_entry.clone(),
		contents: new_secret_contents.into_bytes(),
		nonce: entry_nonce.to_owned(),
	};

	let mut timer = Stopwatch::start_new(); // Start the stopwatch

	deserialised_vault.remove_item(&decrypted_secret.entry.clone());
	write_file(
		path_buf.join(filenamify(new_entry.id.clone().to_string() + ".vaultist")),
		&deserialised_vault.encrypt_secret(&mut new_secret),
	);

	let secret_id_term =
		tantivy::schema::Term::from_field_text(id, &new_entry.id.clone().to_string());
	let mut index_writer = index.writer(100_000_000).unwrap();
	index_writer.delete_term(secret_id_term);
	index_writer
		.add_document(doc!(
			name => new_entry.clone().name,
			id => new_entry.id.to_string(),
			last_modified => new_entry.last_modified.to_rfc2822(),
		))
		.unwrap();
	index_writer.commit().unwrap();

	// Show how long it took to perform operation
	timer.stop();
	writeln!(
		buf_out,
		"\n⏰ Updated vault entry in {} seconds.",
		(timer.elapsed_ms() as f32 / 1000.0)
	)
	.unwrap();
}

/// Removes an item in the vault.
///
/// # Arguments
///
/// * `PATH` - Path to a vault in the filesystem (required)
fn remove_item(matches: &clap::ArgMatches) {
	let stdin = std::io::stdin();
	let stdout = std::io::stdout();
	let stdin_lock = stdin.lock();
	let stdout_lock = stdout.lock();
	let mut buf_in = BufReader::new(stdin_lock);
	let mut buf_out = BufWriter::new(stdout_lock);

	let path_buf_input = matches
		.get_one::<PathBuf>("PATH")
		.ok_or(miette!("❌ No path was given"))
		.unwrap();
	let path_buf = match std::fs::canonicalize(path_buf_input) {
		Ok(p) => p,
		Err(_) => std::env::current_dir()
			.unwrap()
			.join(path_clean::clean(path_buf_input.to_str().unwrap())),
	};

	let mut deserialised_vault: vaultist::Vault =
		bincode::deserialize(&read_file(path_buf.join(".vaultist-vault"))).unwrap();
	let verify_password = rpassword::prompt_password_from_bufread(
		&mut buf_in,
		&mut buf_out,
		"🔑 Enter your vault password: ",
	)
	.unwrap();
	assert!(
		argon2::Argon2::default()
			.verify_password(
				verify_password.as_bytes(),
				&PasswordHash::new(&deserialised_vault.key).unwrap()
			)
			.is_ok(),
		"❌ Could not access vault with that password."
	);

	let mut schema_builder = Schema::builder();
	let name = schema_builder.add_text_field("title", TEXT | STORED);
	let id = schema_builder.add_text_field("id", TEXT | STORED);
	let last_modified = schema_builder.add_text_field("last_modified", TEXT | STORED);
	let schema = schema_builder.build();
	let index =
		Index::open_or_create(MmapDirectory::open(path_buf.clone()).unwrap(), schema).unwrap();
	let reader = index.reader().unwrap();
	let searcher = reader.searcher();
	let query_parser = QueryParser::for_index(&index, vec![name, id, last_modified]);

	let search_query: String = Input::new()
		.with_prompt("❓ Search for the secret you're trying to remove")
		.allow_empty(false)
		.interact_text_on(&Term::buffered_stdout())
		.unwrap();
	let query = query_parser.parse_query(&search_query).unwrap();
	let results: Vec<(Score, DocAddress)> = searcher
		.search(&query, &TopDocs::with_limit(deserialised_vault.items.len()))
		.unwrap();

	let mut result_options: HashMap<String, Uuid> = HashMap::new();
	let mut i = 1;
	for (_score, doc_address) in results {
		let retrieved_doc = searcher.doc(doc_address).unwrap();
		let retrieved_id = retrieved_doc.get_first(id).unwrap().as_text().unwrap();
		let retrieved_date = retrieved_doc
			.get_first(last_modified)
			.unwrap()
			.as_text()
			.unwrap();
		result_options.insert(
			format!(
				"{}. {} ({}; {})",
				i,
				retrieved_doc.get_first(name).unwrap().as_text().unwrap(),
				retrieved_id,
				retrieved_date
			),
			Uuid::parse_str(retrieved_id).unwrap(),
		);
		i += 1;
	}

	let result_options_keys: Vec<&String> = result_options.keys().collect();
	let selection = FuzzySelect::with_theme(&ColorfulTheme::default())
		.items(&result_options_keys)
		.with_prompt("Select the secret you're trying to remove: ")
		.report(true)
		.highlight_matches(true)
		.interact_on_opt(&Term::buffered_stderr())
		.unwrap()
		.unwrap();

	let copy_of_items = deserialised_vault.items.clone();
	let selected_item = copy_of_items
		.iter()
		.filter_map(|val| {
			if val.0.id == *result_options.values().nth(selection).unwrap() {
				Some(val)
			} else {
				None
			}
		})
		.last()
		.unwrap();

	let mut timer = Stopwatch::start_new(); // Start the stopwatch

	deserialised_vault.remove_item(&selected_item.0);
	std::fs::remove_file(path_buf.join(filenamify(
		selected_item.clone().0.id.to_string() + ".vaultist",
	)))
	.unwrap();

	let secret_id_term =
		tantivy::schema::Term::from_field_text(id, &selected_item.clone().0.id.to_string());
	let mut index_writer = index.writer(100_000_000).unwrap();
	index_writer.delete_term(secret_id_term);
	index_writer.commit().unwrap();

	// Show how long it took to perform operation
	timer.stop();
	writeln!(
		buf_out,
		"\n⏰ Removed vault entry in {} seconds.",
		(timer.elapsed_ms() as f32 / 1000.0)
	)
	.unwrap();
}

/// Removes all duplicate items in the vault.
///
/// # Arguments
///
/// * `PATH` - Path to a vault in the filesystem (required)
///
/// * `ignore_names` - Whether or not to ignore common names in addition to common contents when deduplicating.
fn deduplicate_items(matches: &clap::ArgMatches) {
	let stdin = std::io::stdin();
	let stdout = std::io::stdout();
	let stdin_lock = stdin.lock();
	let stdout_lock = stdout.lock();
	let mut buf_in = BufReader::new(stdin_lock);
	let mut buf_out = BufWriter::new(stdout_lock);

	let ignore_names = match matches.get_one::<bool>("ignore_names") {
		Some(b) => *b,
		None => false,
	};

	let path_buf_input = matches
		.get_one::<PathBuf>("PATH")
		.ok_or(miette!("❌ No path was given"))
		.unwrap();
	let path_buf = match std::fs::canonicalize(path_buf_input) {
		Ok(p) => p,
		Err(_) => std::env::current_dir()
			.unwrap()
			.join(path_clean::clean(path_buf_input.to_str().unwrap())),
	};

	let mut deserialised_vault: vaultist::Vault =
		bincode::deserialize(&read_file(path_buf.join(".vaultist-vault"))).unwrap();
	let verify_password = rpassword::prompt_password_from_bufread(
		&mut buf_in,
		&mut buf_out,
		"🔑 Enter your vault password: ",
	)
	.unwrap();
	assert!(
		argon2::Argon2::default()
			.verify_password(
				verify_password.as_bytes(),
				&PasswordHash::new(&deserialised_vault.key).unwrap()
			)
			.is_ok(),
		"❌ Could not access vault with that password."
	);

	let mut timer = Stopwatch::start_new(); // Start the stopwatch

	let duplicate_items = deserialised_vault.deduplicate_items(ignore_names);
	for item in duplicate_items {
		std::fs::remove_file(path_buf.join(filenamify(item.0.id.to_string() + ".vaultist")))
			.unwrap();
	}

	// Show how long it took to perform operation
	timer.stop();
	writeln!(
		buf_out,
		"\n⏰ Removed duplicate vault items in {} seconds.",
		(timer.elapsed_ms() as f32 / 1000.0)
	)
	.unwrap();
}

/// Generates at least one password.
///
/// # Arguments
///
/// * `count` - The number of passwords to generate (default: 1).
///
/// * `length` - The length of the generated passwords (default: 8).
///
/// * `numbers` - Passwords are allowed to, or must if `strict` is true, contain at least one number.
///
/// * `lowercase_letters` - Passwords are allowed to, or must if `strict` is true, contain at least one lowercase letter.
///
/// * `uppercase_letters` - Passwords are allowed to, or must if `strict` is true, contain at least one uppercase letter.
///
/// * `symbols` - Passwords are allowed to, or must if `strict` is true, contain at least one special character.
///
/// * `spaces` - Passwords are allowed to, or must if `strict` is true, contain at least one space.
///
/// * `exclude_similar_characters` - Whether or not to exclude similar looking ASCII characters (``iI1loO0"'`|``).
///
/// * `strict` - Whether or not the password rules are strictly followed for each generated password.
fn generate_passwords(matches: &clap::ArgMatches) {
	let stdout = std::io::stdout();
	let stdout_lock = stdout.lock();
	let mut buf_out = BufWriter::new(stdout_lock);

	let count = match matches.get_one::<usize>("count") {
		Some(s) => *s,
		None => 1,
	};

	let length = match matches.get_one::<usize>("length") {
		Some(s) => *s,
		None => 8,
	};

	let numbers = match matches.get_one::<bool>("numbers") {
		Some(b) => *b,
		None => false,
	};

	let lowercase_letters = match matches.get_one::<bool>("lowercase_letters") {
		Some(b) => *b,
		None => false,
	};

	let uppercase_letters = match matches.get_one::<bool>("uppercase_letters") {
		Some(b) => *b,
		None => false,
	};

	let symbols = match matches.get_one::<bool>("symbols") {
		Some(b) => *b,
		None => false,
	};

	let spaces = match matches.get_one::<bool>("spaces") {
		Some(b) => *b,
		None => false,
	};

	let exclude_similar_characters = match matches.get_one::<bool>("exclude_similar_characters") {
		Some(b) => *b,
		None => false,
	};

	let strict = match matches.get_one::<bool>("strict") {
		Some(b) => *b,
		None => false,
	};

	let mut timer = Stopwatch::start_new(); // Start the stopwatch

	let pg = PasswordGenerator {
		length,
		numbers,
		lowercase_letters,
		uppercase_letters,
		symbols,
		spaces,
		exclude_similar_characters,
		strict,
	};

	let num_generations = count.div_ceil(2);
	let generations = pg.generate(num_generations).unwrap();
	for password in generations {
		writeln!(buf_out, "{}", Colour::Blue.bold().paint(password)).unwrap();
	}
	let xkcd_generations = vaultist::correct_horse_battery_staple(
		count - num_generations,
		length,
		numbers,
		lowercase_letters,
		uppercase_letters,
		symbols,
		spaces,
		exclude_similar_characters,
	);
	for password in xkcd_generations {
		writeln!(buf_out, "{}", Colour::Blue.bold().paint(password)).unwrap();
	}

	// Show how long it took to perform operation
	timer.stop();
	writeln!(
		buf_out,
		"\n⏰ Generated password(s) in {} seconds.",
		(timer.elapsed_ms() as f32 / 1000.0)
	)
	.unwrap();
}

/// Analyses a password.
///
/// # Arguments
///
/// * `password` - The password to be analysed.
fn analyse_password(matches: &clap::ArgMatches) {
	let stdin = std::io::stdin();
	let stdout = std::io::stdout();
	let stdin_lock = stdin.lock();
	let stdout_lock = stdout.lock();
	let mut buf_in = BufReader::new(stdin_lock);
	let mut buf_out = BufWriter::new(stdout_lock);

	let password_match = matches.get_one::<String>("password");
	let password = match password_match {
		Some(p) => p.to_owned(),
		None => rpassword::prompt_password_from_bufread(
			&mut buf_in,
			&mut buf_out,
			"🔑 Enter a password to analyse: ",
		)
		.unwrap(),
	};

	let mut timer = Stopwatch::start_new(); // Start the stopwatch

	let analysed_password = analyzer::analyze(&password);
	let score = scorer::score(&analysed_password);
	let score_string = match Some(score.trunc() as usize) {
		Some(_x @ 0..20) => Colour::Red.paint("⚠️ very vulnerable"),
		Some(_x @ 20..40) => Colour::Red.paint("⚠️ vulnerable"),
		Some(_x @ 40..60) => Colour::Red.paint("⚠️ very weak"),
		Some(_x @ 60..80) => Colour::Red.paint("⚠️ weak"),
		Some(_x @ 80..90) => Colour::Yellow.paint("➖ good"),
		Some(_x @ 90..95) => Colour::Green.paint("✔️ strong"),
		Some(_x @ 95..99) => Colour::Cyan.paint("✔️ very strong"),
		Some(_x @ 99..100) => Colour::Blue.paint("✔️ ideal"),
		Some(_) => Colour::Fixed(7).paint("❌ error during scoring"),
		None => Colour::Fixed(7).paint("❌ error during scoring"),
	};

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
		format!(
			"\n{}{}{}",
			Colour::Red
				.bold()
				.paint("❌ This password is insecure and should not be used."),
			warning_string,
			suggestions_string
		)
	} else if strength_estimate.score() >= 3 && score >= 80.0 {
		format!(
			"\n{}",
			Colour::Green
				.bold()
				.paint("✔️ This password is sufficiently safe to use.")
		)
	} else {
		format!(
			"\n{}{}{}",
			Colour::Yellow
				.bold()
				.paint("⚠️ This password may not be secure."),
			warning_string,
			suggestions_string
		)
	};

	writeln!(buf_out, "Strength: {:.2}% ({})\nEstimated guesses to crack: {}\nOrder of magnitude of estimated guesses: {:.2}\nTime to crack in online attack with rate limiting: {}\nTime to crack in online attack without rate limiting: {}\nTime to crack in offline attack with secure hashing: {}\nTime to crack in offline attack with insecure hashing: {}\nEasy to crack?: {}\nIs common?: {}\nLength: {}\nNumber of lowercase characters: {}\nNumber of uppercase characters: {}\nNumber of numbers: {}\nNumber of symbols: {}\nNumber of other characters: {}\nNumber of spaces: {}\nNumber of non-consecutively repeated characters: {}\nNumber of consecutively repeated characters: {}\nNumber of characters in progressive sequences with at least a length of three: {}\n{}", score, score_string, strength_estimate.guesses(), strength_estimate.guesses_log10(), strength_estimate.crack_times().online_throttling_100_per_hour(), strength_estimate.crack_times().online_no_throttling_10_per_second(), strength_estimate.crack_times().offline_slow_hashing_1e4_per_second(), strength_estimate.crack_times().offline_fast_hashing_1e10_per_second(), if strength_estimate.score() < 3 { "yes" } else { "no" }, if analyzer::is_common_password(password) { "yes" } else { "no" }, analysed_password.length(), analysed_password.lowercase_letters_count(), analysed_password.uppercase_letters_count(), analysed_password.numbers_count(), analysed_password.symbols_count(), analysed_password.other_characters_count(), analysed_password.spaces_count(), analysed_password.non_consecutive_count(), analysed_password.consecutive_count(), analysed_password.progressive_count(), feedback).unwrap();

	// Show how long it took to perform operation
	timer.stop();
	writeln!(
		buf_out,
		"\n⏰ Analysed password in {} seconds.",
		(timer.elapsed_ms() as f32 / 1000.0)
	)
	.unwrap();
}

/// Write a file to the filesystem
///
/// # Arguments
///
/// * `path` - The path to write the file to
///
/// * `bytes_to_write` - The data to write to the filesystem
#[inline(always)]
fn write_file(path: PathBuf, bytes_to_write: &[u8]) {
	fs::create_dir_all(path.parent().unwrap()).unwrap(); // Create output path, write to file
	let file = File::create(path).unwrap(); // Create file which we will write to
	let mut buffered_writer = BufWriter::new(file); // Create a buffered writer, allowing us to modify the file we've just created
	buffered_writer.write_all(bytes_to_write).unwrap(); // Write bytes to file
	buffered_writer.flush().unwrap(); // Empty out the data in memory after we've written to the file
}

/// Read a file from the filesystem
///
/// # Arguments
///
/// * `path` - The path to read the file from
#[inline(always)]
fn read_file(path: PathBuf) -> Vec<u8> {
	let file = File::open(path).unwrap(); // Open file which we will read from
	let mut buffer: Vec<u8> = Vec::new();
	let mut buffered_reader = BufReader::new(file); // Create a buffered reader, allowing us to read the file we've just opened
	buffered_reader.read_to_end(&mut buffer).unwrap(); // Write bytes that were read into buffer
	buffer
}

/// Shows information regarding the usage and handling of this software
///
/// # Arguments
///
/// * `warranty` - Prints warranty information
///
/// * `conditions` - Prints conditions information
fn show(matches: &clap::ArgMatches) {
	let stdout = std::io::stdout();
	let lock = stdout.lock();
	let mut buf_out = BufWriter::new(lock);

	if matches.contains_id("warranty") {
		// "vaultist show -w" was run
		writeln!(
			buf_out,
			"
    15. Disclaimer of Warranty.

    THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
  APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
  HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM \"AS IS\" WITHOUT WARRANTY
  OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
  PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
  IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
  ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
  
    16. Limitation of Liability.
  
    IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
  WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS
  THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY
  GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE
  USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF
  DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD
  PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS),
  EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
  SUCH DAMAGES.
  
    17. Interpretation of Sections 15 and 16.
  
    If the disclaimer of warranty and limitation of liability provided
  above cannot be given local legal effect according to their terms,
  reviewing courts shall apply local law that most closely approximates
  an absolute waiver of all civil liability in connection with the
  Program, unless a warranty or assumption of liability accompanies a
  copy of the Program in return for a fee.
  "
		)
		.unwrap();
	} else if matches.contains_id("conditions") {
		// "vaultist show -c" was run
		writeln!(
			buf_out,
			"
        TERMS AND CONDITIONS

        0. Definitions.
      
        \"This License\" refers to version 3 of the GNU Affero General Public License.
      
        \"Copyright\" also means copyright-like laws that apply to other kinds of
      works, such as semiconductor masks.
      
        \"The Program\" refers to any copyrightable work licensed under this
      License.  Each licensee is addressed as \"you\".  \"Licensees\" and
      \"recipients\" may be individuals or organizations.
      
        To \"modify\" a work means to copy from or adapt all or part of the work
      in a fashion requiring copyright permission, other than the making of an
      exact copy.  The resulting work is called a \"modified version\" of the
      earlier work or a work \"based on\" the earlier work.
      
        A \"covered work\" means either the unmodified Program or a work based
      on the Program.
      
        To \"propagate\" a work means to do anything with it that, without
      permission, would make you directly or secondarily liable for
      infringement under applicable copyright law, except executing it on a
      computer or modifying a private copy.  Propagation includes copying,
      distribution (with or without modification), making available to the
      public, and in some countries other activities as well.
      
        To \"convey\" a work means any kind of propagation that enables other
      parties to make or receive copies.  Mere interaction with a user through
      a computer network, with no transfer of a copy, is not conveying.
      
        An interactive user interface displays \"Appropriate Legal Notices\"
      to the extent that it includes a convenient and prominently visible
      feature that (1) displays an appropriate copyright notice, and (2)
      tells the user that there is no warranty for the work (except to the
      extent that warranties are provided), that licensees may convey the
      work under this License, and how to view a copy of this License.  If
      the interface presents a list of user commands or options, such as a
      menu, a prominent item in the list meets this criterion.
      
        1. Source Code.
      
        The \"source code\" for a work means the preferred form of the work
      for making modifications to it.  \"Object code\" means any non-source
      form of a work.
      
        A \"Standard Interface\" means an interface that either is an official
      standard defined by a recognized standards body, or, in the case of
      interfaces specified for a particular programming language, one that
      is widely used among developers working in that language.
      
        The \"System Libraries\" of an executable work include anything, other
      than the work as a whole, that (a) is included in the normal form of
      packaging a Major Component, but which is not part of that Major
      Component, and (b) serves only to enable use of the work with that
      Major Component, or to implement a Standard Interface for which an
      implementation is available to the public in source code form.  A
      \"Major Component\", in this context, means a major essential component
      (kernel, window system, and so on) of the specific operating system
      (if any) on which the executable work runs, or a compiler used to
      produce the work, or an object code interpreter used to run it.
      
        The \"Corresponding Source\" for a work in object code form means all
      the source code needed to generate, install, and (for an executable
      work) run the object code and to modify the work, including scripts to
      control those activities.  However, it does not include the work's
      System Libraries, or general-purpose tools or generally available free
      programs which are used unmodified in performing those activities but
      which are not part of the work.  For example, Corresponding Source
      includes interface definition files associated with source files for
      the work, and the source code for shared libraries and dynamically
      linked subprograms that the work is specifically designed to require,
      such as by intimate data communication or control flow between those
      subprograms and other parts of the work.
      
        The Corresponding Source need not include anything that users
      can regenerate automatically from other parts of the Corresponding
      Source.
      
        The Corresponding Source for a work in source code form is that
      same work.
      
        2. Basic Permissions.
      
        All rights granted under this License are granted for the term of
      copyright on the Program, and are irrevocable provided the stated
      conditions are met.  This License explicitly affirms your unlimited
      permission to run the unmodified Program.  The output from running a
      covered work is covered by this License only if the output, given its
      content, constitutes a covered work.  This License acknowledges your
      rights of fair use or other equivalent, as provided by copyright law.
      
        You may make, run and propagate covered works that you do not
      convey, without conditions so long as your license otherwise remains
      in force.  You may convey covered works to others for the sole purpose
      of having them make modifications exclusively for you, or provide you
      with facilities for running those works, provided that you comply with
      the terms of this License in conveying all material for which you do
      not control copyright.  Those thus making or running the covered works
      for you must do so exclusively on your behalf, under your direction
      and control, on terms that prohibit them from making any copies of
      your copyrighted material outside their relationship with you.
      
        Conveying under any other circumstances is permitted solely under
      the conditions stated below.  Sublicensing is not allowed; section 10
      makes it unnecessary.
      
        3. Protecting Users' Legal Rights From Anti-Circumvention Law.
      
        No covered work shall be deemed part of an effective technological
      measure under any applicable law fulfilling obligations under article
      11 of the WIPO copyright treaty adopted on 20 December 1996, or
      similar laws prohibiting or restricting circumvention of such
      measures.
      
        When you convey a covered work, you waive any legal power to forbid
      circumvention of technological measures to the extent such circumvention
      is effected by exercising rights under this License with respect to
      the covered work, and you disclaim any intention to limit operation or
      modification of the work as a means of enforcing, against the work's
      users, your or third parties' legal rights to forbid circumvention of
      technological measures.
      
        4. Conveying Verbatim Copies.
      
        You may convey verbatim copies of the Program's source code as you
      receive it, in any medium, provided that you conspicuously and
      appropriately publish on each copy an appropriate copyright notice;
      keep intact all notices stating that this License and any
      non-permissive terms added in accord with section 7 apply to the code;
      keep intact all notices of the absence of any warranty; and give all
      recipients a copy of this License along with the Program.
      
        You may charge any price or no price for each copy that you convey,
      and you may offer support or warranty protection for a fee.
      
        5. Conveying Modified Source Versions.
      
        You may convey a work based on the Program, or the modifications to
      produce it from the Program, in the form of source code under the
      terms of section 4, provided that you also meet all of these conditions:
      
          a) The work must carry prominent notices stating that you modified
          it, and giving a relevant date.
      
          b) The work must carry prominent notices stating that it is
          released under this License and any conditions added under section
          7.  This requirement modifies the requirement in section 4 to
          \"keep intact all notices\".
      
          c) You must license the entire work, as a whole, under this
          License to anyone who comes into possession of a copy.  This
          License will therefore apply, along with any applicable section 7
          additional terms, to the whole of the work, and all its parts,
          regardless of how they are packaged.  This License gives no
          permission to license the work in any other way, but it does not
          invalidate such permission if you have separately received it.
      
          d) If the work has interactive user interfaces, each must display
          Appropriate Legal Notices; however, if the Program has interactive
          interfaces that do not display Appropriate Legal Notices, your
          work need not make them do so.
      
        A compilation of a covered work with other separate and independent
      works, which are not by their nature extensions of the covered work,
      and which are not combined with it such as to form a larger program,
      in or on a volume of a storage or distribution medium, is called an
      \"aggregate\" if the compilation and its resulting copyright are not
      used to limit the access or legal rights of the compilation's users
      beyond what the individual works permit.  Inclusion of a covered work
      in an aggregate does not cause this License to apply to the other
      parts of the aggregate.
      
        6. Conveying Non-Source Forms.
      
        You may convey a covered work in object code form under the terms
      of sections 4 and 5, provided that you also convey the
      machine-readable Corresponding Source under the terms of this License,
      in one of these ways:
      
          a) Convey the object code in, or embodied in, a physical product
          (including a physical distribution medium), accompanied by the
          Corresponding Source fixed on a durable physical medium
          customarily used for software interchange.
      
          b) Convey the object code in, or embodied in, a physical product
          (including a physical distribution medium), accompanied by a
          written offer, valid for at least three years and valid for as
          long as you offer spare parts or customer support for that product
          model, to give anyone who possesses the object code either (1) a
          copy of the Corresponding Source for all the software in the
          product that is covered by this License, on a durable physical
          medium customarily used for software interchange, for a price no
          more than your reasonable cost of physically performing this
          conveying of source, or (2) access to copy the
          Corresponding Source from a network server at no charge.
      
          c) Convey individual copies of the object code with a copy of the
          written offer to provide the Corresponding Source.  This
          alternative is allowed only occasionally and noncommercially, and
          only if you received the object code with such an offer, in accord
          with subsection 6b.
      
          d) Convey the object code by offering access from a designated
          place (gratis or for a charge), and offer equivalent access to the
          Corresponding Source in the same way through the same place at no
          further charge.  You need not require recipients to copy the
          Corresponding Source along with the object code.  If the place to
          copy the object code is a network server, the Corresponding Source
          may be on a different server (operated by you or a third party)
          that supports equivalent copying facilities, provided you maintain
          clear directions next to the object code saying where to find the
          Corresponding Source.  Regardless of what server hosts the
          Corresponding Source, you remain obligated to ensure that it is
          available for as long as needed to satisfy these requirements.
      
          e) Convey the object code using peer-to-peer transmission, provided
          you inform other peers where the object code and Corresponding
          Source of the work are being offered to the general public at no
          charge under subsection 6d.
      
        A separable portion of the object code, whose source code is excluded
      from the Corresponding Source as a System Library, need not be
      included in conveying the object code work.
      
        A \"User Product\" is either (1) a \"consumer product\", which means any
      tangible personal property which is normally used for personal, family,
      or household purposes, or (2) anything designed or sold for incorporation
      into a dwelling.  In determining whether a product is a consumer product,
      doubtful cases shall be resolved in favor of coverage.  For a particular
      product received by a particular user, \"normally used\" refers to a
      typical or common use of that class of product, regardless of the status
      of the particular user or of the way in which the particular user
      actually uses, or expects or is expected to use, the product.  A product
      is a consumer product regardless of whether the product has substantial
      commercial, industrial or non-consumer uses, unless such uses represent
      the only significant mode of use of the product.
      
        \"Installation Information\" for a User Product means any methods,
      procedures, authorization keys, or other information required to install
      and execute modified versions of a covered work in that User Product from
      a modified version of its Corresponding Source.  The information must
      suffice to ensure that the continued functioning of the modified object
      code is in no case prevented or interfered with solely because
      modification has been made.
      
        If you convey an object code work under this section in, or with, or
      specifically for use in, a User Product, and the conveying occurs as
      part of a transaction in which the right of possession and use of the
      User Product is transferred to the recipient in perpetuity or for a
      fixed term (regardless of how the transaction is characterized), the
      Corresponding Source conveyed under this section must be accompanied
      by the Installation Information.  But this requirement does not apply
      if neither you nor any third party retains the ability to install
      modified object code on the User Product (for example, the work has
      been installed in ROM).
      
        The requirement to provide Installation Information does not include a
      requirement to continue to provide support service, warranty, or updates
      for a work that has been modified or installed by the recipient, or for
      the User Product in which it has been modified or installed.  Access to a
      network may be denied when the modification itself materially and
      adversely affects the operation of the network or violates the rules and
      protocols for communication across the network.
      
        Corresponding Source conveyed, and Installation Information provided,
      in accord with this section must be in a format that is publicly
      documented (and with an implementation available to the public in
      source code form), and must require no special password or key for
      unpacking, reading or copying.
      
        7. Additional Terms.
      
        \"Additional permissions\" are terms that supplement the terms of this
      License by making exceptions from one or more of its conditions.
      Additional permissions that are applicable to the entire Program shall
      be treated as though they were included in this License, to the extent
      that they are valid under applicable law.  If additional permissions
      apply only to part of the Program, that part may be used separately
      under those permissions, but the entire Program remains governed by
      this License without regard to the additional permissions.
      
        When you convey a copy of a covered work, you may at your option
      remove any additional permissions from that copy, or from any part of
      it.  (Additional permissions may be written to require their own
      removal in certain cases when you modify the work.)  You may place
      additional permissions on material, added by you to a covered work,
      for which you have or can give appropriate copyright permission.
      
        Notwithstanding any other provision of this License, for material you
      add to a covered work, you may (if authorized by the copyright holders of
      that material) supplement the terms of this License with terms:
      
          a) Disclaiming warranty or limiting liability differently from the
          terms of sections 15 and 16 of this License; or
      
          b) Requiring preservation of specified reasonable legal notices or
          author attributions in that material or in the Appropriate Legal
          Notices displayed by works containing it; or
      
          c) Prohibiting misrepresentation of the origin of that material, or
          requiring that modified versions of such material be marked in
          reasonable ways as different from the original version; or
      
          d) Limiting the use for publicity purposes of names of licensors or
          authors of the material; or
      
          e) Declining to grant rights under trademark law for use of some
          trade names, trademarks, or service marks; or
      
          f) Requiring indemnification of licensors and authors of that
          material by anyone who conveys the material (or modified versions of
          it) with contractual assumptions of liability to the recipient, for
          any liability that these contractual assumptions directly impose on
          those licensors and authors.
      
        All other non-permissive additional terms are considered \"further
      restrictions\" within the meaning of section 10.  If the Program as you
      received it, or any part of it, contains a notice stating that it is
      governed by this License along with a term that is a further
      restriction, you may remove that term.  If a license document contains
      a further restriction but permits relicensing or conveying under this
      License, you may add to a covered work material governed by the terms
      of that license document, provided that the further restriction does
      not survive such relicensing or conveying.
      
        If you add terms to a covered work in accord with this section, you
      must place, in the relevant source files, a statement of the
      additional terms that apply to those files, or a notice indicating
      where to find the applicable terms.
      
        Additional terms, permissive or non-permissive, may be stated in the
      form of a separately written license, or stated as exceptions;
      the above requirements apply either way.
      
        8. Termination.
      
        You may not propagate or modify a covered work except as expressly
      provided under this License.  Any attempt otherwise to propagate or
      modify it is void, and will automatically terminate your rights under
      this License (including any patent licenses granted under the third
      paragraph of section 11).
      
        However, if you cease all violation of this License, then your
      license from a particular copyright holder is reinstated (a)
      provisionally, unless and until the copyright holder explicitly and
      finally terminates your license, and (b) permanently, if the copyright
      holder fails to notify you of the violation by some reasonable means
      prior to 60 days after the cessation.
      
        Moreover, your license from a particular copyright holder is
      reinstated permanently if the copyright holder notifies you of the
      violation by some reasonable means, this is the first time you have
      received notice of violation of this License (for any work) from that
      copyright holder, and you cure the violation prior to 30 days after
      your receipt of the notice.
      
        Termination of your rights under this section does not terminate the
      licenses of parties who have received copies or rights from you under
      this License.  If your rights have been terminated and not permanently
      reinstated, you do not qualify to receive new licenses for the same
      material under section 10.
      
        9. Acceptance Not Required for Having Copies.
      
        You are not required to accept this License in order to receive or
      run a copy of the Program.  Ancillary propagation of a covered work
      occurring solely as a consequence of using peer-to-peer transmission
      to receive a copy likewise does not require acceptance.  However,
      nothing other than this License grants you permission to propagate or
      modify any covered work.  These actions infringe copyright if you do
      not accept this License.  Therefore, by modifying or propagating a
      covered work, you indicate your acceptance of this License to do so.
      
        10. Automatic Licensing of Downstream Recipients.
      
        Each time you convey a covered work, the recipient automatically
      receives a license from the original licensors, to run, modify and
      propagate that work, subject to this License.  You are not responsible
      for enforcing compliance by third parties with this License.
      
        An \"entity transaction\" is a transaction transferring control of an
      organization, or substantially all assets of one, or subdividing an
      organization, or merging organizations.  If propagation of a covered
      work results from an entity transaction, each party to that
      transaction who receives a copy of the work also receives whatever
      licenses to the work the party's predecessor in interest had or could
      give under the previous paragraph, plus a right to possession of the
      Corresponding Source of the work from the predecessor in interest, if
      the predecessor has it or can get it with reasonable efforts.
      
        You may not impose any further restrictions on the exercise of the
      rights granted or affirmed under this License.  For example, you may
      not impose a license fee, royalty, or other charge for exercise of
      rights granted under this License, and you may not initiate litigation
      (including a cross-claim or counterclaim in a lawsuit) alleging that
      any patent claim is infringed by making, using, selling, offering for
      sale, or importing the Program or any portion of it.
      
        11. Patents.
      
        A \"contributor\" is a copyright holder who authorizes use under this
      License of the Program or a work on which the Program is based.  The
      work thus licensed is called the contributor's \"contributor version\".
      
        A contributor's \"essential patent claims\" are all patent claims
      owned or controlled by the contributor, whether already acquired or
      hereafter acquired, that would be infringed by some manner, permitted
      by this License, of making, using, or selling its contributor version,
      but do not include claims that would be infringed only as a
      consequence of further modification of the contributor version.  For
      purposes of this definition, \"control\" includes the right to grant
      patent sublicenses in a manner consistent with the requirements of
      this License.
      
        Each contributor grants you a non-exclusive, worldwide, royalty-free
      patent license under the contributor's essential patent claims, to
      make, use, sell, offer for sale, import and otherwise run, modify and
      propagate the contents of its contributor version.
      
        In the following three paragraphs, a \"patent license\" is any express
      agreement or commitment, however denominated, not to enforce a patent
      (such as an express permission to practice a patent or covenant not to
      sue for patent infringement).  To \"grant\" such a patent license to a
      party means to make such an agreement or commitment not to enforce a
      patent against the party.
      
        If you convey a covered work, knowingly relying on a patent license,
      and the Corresponding Source of the work is not available for anyone
      to copy, free of charge and under the terms of this License, through a
      publicly available network server or other readily accessible means,
      then you must either (1) cause the Corresponding Source to be so
      available, or (2) arrange to deprive yourself of the benefit of the
      patent license for this particular work, or (3) arrange, in a manner
      consistent with the requirements of this License, to extend the patent
      license to downstream recipients.  \"Knowingly relying\" means you have
      actual knowledge that, but for the patent license, your conveying the
      covered work in a country, or your recipient's use of the covered work
      in a country, would infringe one or more identifiable patents in that
      country that you have reason to believe are valid.
      
        If, pursuant to or in connection with a single transaction or
      arrangement, you convey, or propagate by procuring conveyance of, a
      covered work, and grant a patent license to some of the parties
      receiving the covered work authorizing them to use, propagate, modify
      or convey a specific copy of the covered work, then the patent license
      you grant is automatically extended to all recipients of the covered
      work and works based on it.
      
        A patent license is \"discriminatory\" if it does not include within
      the scope of its coverage, prohibits the exercise of, or is
      conditioned on the non-exercise of one or more of the rights that are
      specifically granted under this License.  You may not convey a covered
      work if you are a party to an arrangement with a third party that is
      in the business of distributing software, under which you make payment
      to the third party based on the extent of your activity of conveying
      the work, and under which the third party grants, to any of the
      parties who would receive the covered work from you, a discriminatory
      patent license (a) in connection with copies of the covered work
      conveyed by you (or copies made from those copies), or (b) primarily
      for and in connection with specific products or compilations that
      contain the covered work, unless you entered into that arrangement,
      or that patent license was granted, prior to 28 March 2007.
      
        Nothing in this License shall be construed as excluding or limiting
      any implied license or other defenses to infringement that may
      otherwise be available to you under applicable patent law.
      
        12. No Surrender of Others' Freedom.
      
        If conditions are imposed on you (whether by court order, agreement or
      otherwise) that contradict the conditions of this License, they do not
      excuse you from the conditions of this License.  If you cannot convey a
      covered work so as to satisfy simultaneously your obligations under this
      License and any other pertinent obligations, then as a consequence you may
      not convey it at all.  For example, if you agree to terms that obligate you
      to collect a royalty for further conveying from those to whom you convey
      the Program, the only way you could satisfy both those terms and this
      License would be to refrain entirely from conveying the Program.
      
        13. Remote Network Interaction; Use with the GNU General Public License.
      
        Notwithstanding any other provision of this License, if you modify the
      Program, your modified version must prominently offer all users
      interacting with it remotely through a computer network (if your version
      supports such interaction) an opportunity to receive the Corresponding
      Source of your version by providing access to the Corresponding Source
      from a network server at no charge, through some standard or customary
      means of facilitating copying of software.  This Corresponding Source
      shall include the Corresponding Source for any work covered by version 3
      of the GNU General Public License that is incorporated pursuant to the
      following paragraph.
      
        Notwithstanding any other provision of this License, you have
      permission to link or combine any covered work with a work licensed
      under version 3 of the GNU General Public License into a single
      combined work, and to convey the resulting work.  The terms of this
      License will continue to apply to the part which is the covered work,
      but the work with which it is combined will remain governed by version
      3 of the GNU General Public License.
      
        14. Revised Versions of this License.
      
        The Free Software Foundation may publish revised and/or new versions of
      the GNU Affero General Public License from time to time.  Such new versions
      will be similar in spirit to the present version, but may differ in detail to
      address new problems or concerns.
      
        Each version is given a distinguishing version number.  If the
      Program specifies that a certain numbered version of the GNU Affero General
      Public License \"or any later version\" applies to it, you have the
      option of following the terms and conditions either of that numbered
      version or of any later version published by the Free Software
      Foundation.  If the Program does not specify a version number of the
      GNU Affero General Public License, you may choose any version ever published
      by the Free Software Foundation.
      
        If the Program specifies that a proxy can decide which future
      versions of the GNU Affero General Public License can be used, that proxy's
      public statement of acceptance of a version permanently authorizes you
      to choose that version for the Program.
      
        Later license versions may give you additional or different
      permissions.  However, no additional obligations are imposed on any
      author or copyright holder as a result of your choosing to follow a
      later version.
      
        15. Disclaimer of Warranty.
      
        THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
      APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
      HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM \"AS IS\" WITHOUT WARRANTY
      OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
      THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
      PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
      IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
      ALL NECESSARY SERVICING, REPAIR OR CORRECTION.
      
        16. Limitation of Liability.
      
        IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
      WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS
      THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY
      GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE
      USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF
      DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD
      PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS),
      EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
      SUCH DAMAGES.
      
        17. Interpretation of Sections 15 and 16.
      
        If the disclaimer of warranty and limitation of liability provided
      above cannot be given local legal effect according to their terms,
      reviewing courts shall apply local law that most closely approximates
      an absolute waiver of all civil liability in connection with the
      Program, unless a warranty or assumption of liability accompanies a
      copy of the Program in return for a fee.
      
                          END OF TERMS AND CONDITIONS
      "
		)
		.unwrap();
	}
}
