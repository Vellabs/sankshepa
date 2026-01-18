pub mod rfc3164;
pub mod rfc5424;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogMessage {
    pub priority: u8,
    pub facility: u8,
    pub severity: u8,
    pub timestamp: Option<DateTime<Utc>>,
    pub hostname: Option<String>,
    pub app_name: Option<String>,
    pub procid: Option<String>,
    pub msgid: Option<String>,
    pub structured_data: Option<String>,
    pub message: String,
    pub is_rfc5424: bool,
}

pub struct UnifiedParser;

impl UnifiedParser {
    pub fn parse(input: &str) -> anyhow::Result<SyslogMessage> {
        let input = input.trim();
        if input.is_empty() {
            return Err(anyhow::anyhow!("Empty input"));
        }

        // Simple heuristic: if the char after > is a digit, it's likely RFC 5424
        let is_rfc5424 = input
            .find('>')
            .and_then(|pos| input.chars().nth(pos + 1))
            .is_some_and(|c| c.is_ascii_digit());

        if is_rfc5424 {
            debug!("Attempting RFC 5424 parse");
            return rfc5424::RFC5424Parser::parse(input);
        }
        debug!("Attempting RFC 3164 parse");
        rfc3164::RFC3164Parser::parse(input)
    }
}
