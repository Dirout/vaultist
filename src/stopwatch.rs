use std::{
	fmt::{Display, Formatter},
	time::{Duration, Instant},
};

#[cfg(feature = "derive_more")]
use derive_more::{Div, DivAssign, From, Into, Mul, MulAssign, Rem, Shl, Shr};

#[cfg_attr(
	feature = "derive_more",
	derive(From, Into, Mul, MulAssign, Div, DivAssign, Rem, Shr, Shl,)
)]
#[derive(Ord, Eq, PartialEq, PartialOrd, Clone, Copy, Debug, Hash)]
/// A simple stopwatch implementation.
pub struct Stopwatch {
	/// The total elapsed time.
	elapsed: Duration,
	/// The time at which the stopwatch was last started.
	timer: Instant,
	/// Whether the stopwatch is currently running.
	is_running: bool,
}

impl Default for Stopwatch {
	fn default() -> Self {
		Self {
			elapsed: Duration::new(0, 0),
			timer: Instant::now(),
			is_running: false,
		}
	}
}

impl Display for Stopwatch {
	fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
		let elapsed_ms = self.clone().elapsed_ms();
		write!(f, "{}ms", elapsed_ms)
	}
}

impl Stopwatch {
	/// Creates a new stopwatch.
	pub fn new() -> Stopwatch {
		Stopwatch::default()
	}

	/// Creates a new stopwatch and starts it.
	pub fn start_new() -> Stopwatch {
		let mut sw = Stopwatch::new();
		sw.start();
		sw
	}

	/// Starts (or resumes) the stopwatch.
	pub fn start(&mut self) {
		self.timer = Instant::now();
		self.is_running = true;
	}

	/// Stops (or pauses) the stopwatch.
	pub fn stop(&mut self) {
		self.elapsed += self.timer.elapsed();
		self.is_running = false;
	}

	/// Resets the stopwatch.
	pub fn reset(&mut self) {
		*self = Stopwatch::new();
	}

	/// Resets and starts the stopwatch.
	pub fn restart(&mut self) {
		self.reset();
		self.start();
	}

	/// Returns true if the stopwatch is running, and false if not.
	pub fn is_running(&mut self) -> bool {
		self.is_running
	}

	/// Returns the total elapsed time.
	pub fn elapsed(&self) -> Duration {
		match self.is_running {
			true => self.elapsed + self.timer.elapsed(),
			false => self.elapsed,
		}
	}

	/// Returns the total elapsed time in milliseconds.
	pub fn elapsed_ms(&mut self) -> u128 {
		self.elapsed().as_millis()
	}

	/// Returns the total elapsed time in microseconds.
	pub fn elapsed_us(&mut self) -> u128 {
		self.elapsed().as_micros()
	}

	/// Returns the total elapsed time in nanoseconds.
	pub fn elapsed_ns(&mut self) -> u128 {
		self.elapsed().as_nanos()
	}

	/// Returns the total elapsed time in fractional seconds.
	pub fn elapsed_s(&mut self) -> f64 {
		self.elapsed().as_secs_f64()
	}

	/// Returns the total elapsed time in whole seconds.
	pub fn elapsed_s_whole(&self) -> u64 {
		self.elapsed().as_secs()
	}
}
