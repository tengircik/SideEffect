mod html;
mod inspect_text;
mod summary;
mod text;

pub use html::write_html_diff;
pub use inspect_text::{write_trace_evidence_text, write_trace_text};
pub use summary::{RedactedDiffSummary, summarize_diff, write_html_summary};
pub use text::write_text_diff;
