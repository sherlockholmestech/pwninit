use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

use colored::Colorize;
use serde_json::json;

static QUIET: AtomicBool = AtomicBool::new(false);
static JSON: AtomicBool = AtomicBool::new(false);
static VERBOSE: AtomicU8 = AtomicU8::new(0);
static WARNINGS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

#[derive(Debug, Clone)]
pub enum StepStatus {
    Completed,
    Skipped,
    Failed,
}

impl StepStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Step {
    pub name: String,
    pub status: StepStatus,
    pub detail: String,
    pub required: bool,
}

impl Step {
    pub fn completed(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: StepStatus::Completed,
            detail: detail.into(),
            required: false,
        }
    }

    pub fn skipped(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: StepStatus::Skipped,
            detail: detail.into(),
            required: false,
        }
    }

    pub fn failed(name: impl Into<String>, detail: impl Into<String>, required: bool) -> Self {
        Self {
            name: name.into(),
            status: StepStatus::Failed,
            detail: detail.into(),
            required,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Summary {
    pub command: &'static str,
    pub steps: Vec<Step>,
}

impl Summary {
    pub fn new(command: &'static str) -> Self {
        Self {
            command,
            steps: Vec::new(),
        }
    }

    pub fn success(&self) -> bool {
        !self
            .steps
            .iter()
            .any(|step| step.required && matches!(step.status, StepStatus::Failed))
    }

    pub fn push(&mut self, step: Step) {
        self.steps.push(step);
    }
}

pub fn configure(quiet: bool, verbose: u8, json_mode: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
    VERBOSE.store(verbose, Ordering::Relaxed);
    JSON.store(json_mode, Ordering::Relaxed);
    if quiet || json_mode {
        colored::control::set_override(false);
    }
    warnings().lock().expect("warnings lock").clear();
}

fn warnings() -> &'static Mutex<Vec<String>> {
    WARNINGS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn is_json() -> bool {
    JSON.load(Ordering::Relaxed)
}

pub fn progress(message: impl std::fmt::Display) {
    if !QUIET.load(Ordering::Relaxed) && !is_json() {
        println!("{message}");
    }
}

pub fn verbose(message: impl std::fmt::Display) {
    if VERBOSE.load(Ordering::Relaxed) > 0 && !is_json() {
        eprintln!("{message}");
    }
}

pub fn warning(message: impl Into<String>) {
    let message = message.into();
    if is_json() {
        warnings().lock().expect("warnings lock").push(message);
    } else {
        eprintln!("{}", format!("warning: {message}").magenta().bold());
    }
}

pub fn error(message: impl AsRef<str>) {
    if is_json() {
        println!(
            "{}",
            json!({
                "success": false,
                "error": message.as_ref(),
                "warnings": warnings().lock().expect("warnings lock").clone(),
            })
        );
    } else {
        eprintln!("{}", format!("error: {}", message.as_ref()).red().bold());
    }
}

pub fn render_summary(summary: &Summary) {
    if is_json() {
        let warnings = warnings().lock().expect("warnings lock").clone();
        let steps = summary
            .steps
            .iter()
            .map(|step| {
                json!({
                    "name": step.name,
                    "status": step.status.as_str(),
                    "detail": step.detail,
                    "required": step.required,
                })
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            json!({
                "command": summary.command,
                "success": summary.success(),
                "steps": steps,
                "warnings": warnings,
            })
        );
        return;
    }

    if !QUIET.load(Ordering::Relaxed) {
        println!();
        println!("{}", "summary".bold());
        for step in &summary.steps {
            let marker = match step.status {
                StepStatus::Completed => "✓".green(),
                StepStatus::Skipped => "-".yellow(),
                StepStatus::Failed => "✗".red(),
            };
            println!("{} {}: {}", marker, step.name, step.detail);
        }
    } else {
        let completed = summary
            .steps
            .iter()
            .filter(|step| matches!(step.status, StepStatus::Completed))
            .count();
        let skipped = summary
            .steps
            .iter()
            .filter(|step| matches!(step.status, StepStatus::Skipped))
            .count();
        let failed = summary
            .steps
            .iter()
            .filter(|step| matches!(step.status, StepStatus::Failed))
            .count();
        println!("completed: {completed}, skipped: {skipped}, failed: {failed}");
    }
}
