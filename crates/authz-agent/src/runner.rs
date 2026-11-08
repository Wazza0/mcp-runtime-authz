//! Agent loop: model proposes, executor runs, result goes back to the model.

use anyhow::Result;
use authz_core::{Executor, ToolCall, ToolResult};

use crate::model::{Model, Step};

pub struct Transcript {
    pub steps: Vec<(ToolCall, ToolResult)>,
    pub answer: Option<String>,
}

pub async fn run<M: Model, E: Executor>(
    m: &mut M,
    e: &E,
    task: &str,
    max: usize,
) -> Result<Transcript> {
    let mut steps = Vec::new();
    for _ in 0..max {
        match m.next(task, &steps).await? {
            Step::Call(c) => {
                let r = e.exec(&c).await;
                steps.push((c, r));
            }
            Step::Done(a) => return Ok(Transcript { steps, answer: Some(a) }),
        }
    }
    Ok(Transcript { steps, answer: None })
}
