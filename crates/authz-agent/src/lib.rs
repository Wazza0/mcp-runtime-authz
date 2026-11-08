//! Agent logic. Deliberately has no dependency on the tool client:
//! it can only act through the Executor it is handed.

pub mod model;
pub mod ollama;
pub mod runner;
pub mod scenario;

pub use model::{Model, Scripted, Step};
pub use ollama::Ollama;
pub use runner::{Transcript, run};
pub use scenario::{Kind, Scenario};
