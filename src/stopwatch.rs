use std::time::{Duration, Instant};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(
	feature = "derive_more",
	derive(From, Into, Mul, Div, Rem, Shr, Shl, Constructor)
)]
#[derive(Eq, PartialEq, PartialOrd, Clone, Debug, Hash)]
/// A simple stopwatch implementation.
pub struct Stopwatch {
	/// The total elapsed time.
	elapsed: Duration,
	/// The time at which the stopwatch was last started.
	timer: Instant,
	/// Whether the stopwatch is currently running.
	is_running: bool,
}

impl Stopwatch {
	/// Creates a new stopwatch.
	pub fn new() -> Stopwatch {
		Stopwatch {
			elapsed: Duration::new(0, 0),
			timer: Instant::now(),
			is_running: false,
		}
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
		self.elapsed = Duration::new(0, 0);
		self.timer = Instant::now();
		self.is_running = false;
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
		self.elapsed + self.timer.elapsed()
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

	/// Returns the total elapsed time in seconds.
	pub fn elapsed_s(&self) -> u64 {
		self.elapsed().as_secs()
	}
}
