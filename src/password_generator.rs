use alloc::str;
use alloc::vec;
use alloc::{
	borrow::ToOwned,
	format,
	string::{String, ToString},
	vec::Vec,
};
use convert_case::{Case, Casing};
use derive_more::From;
use itertools::Itertools;
use lazy_static::lazy_static;
use passwords::{analyzer, scorer};
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use yansi::Paint;
use zxcvbn::zxcvbn;

extern crate alloc;

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
			Some(w) => format!("\nWarning: {}", Paint::red(w.to_string()).bold()),
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
				Paint::yellow("Suggestions").bold(),
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
			Paint::red("❌ This password is insecure and should not be used.").bold(),
			warning_string,
			suggestions_string
		)
	} else if strength_estimate.score() >= 3 && score >= 80.0 {
		is_ok = true;
		format!(
			"\n{}",
			Paint::green("✔️ This password is sufficiently safe to use.").bold()
		)
	} else {
		is_ok = false;
		format!(
			"\n{}{}{}",
			Paint::yellow("⚠️ This password may not be secure.").bold(),
			warning_string,
			suggestions_string
		)
	};

	(is_ok, feedback)
}
