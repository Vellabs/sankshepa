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
    pub node_id: Option<String>,
}

pub struct UnifiedParser;

impl UnifiedParser {
    pub fn parse(input: &str) -> anyhow::Result<SyslogMessage> {
        let mut input = input.trim();
        if input.is_empty() {
            return Err(anyhow::anyhow!("Empty input"));
        }

        // Heuristic: Strip common grep/search prefixes like 'filename:line:'
        // e.g. "loghub/Android.log:1210639: ..."
        if let Some(first_colon) = input.find(':') {
            let possible_prefix = &input[..first_colon];
            if possible_prefix.contains('/') || possible_prefix.contains('.') {
                // It looks like a path. Check if there's a second colon for line number.
                if let Some(second_colon) = input[first_colon + 1..].find(':') {
                    input = input[first_colon + 1 + second_colon + 1..].trim();
                }
            }
        }

        // Simple heuristic: if the char after > is a digit, it's likely RFC 5424
        let is_rfc5424 = input
            .find('>')
            .and_then(|pos| input.chars().nth(pos + 1))
            .is_some_and(|c| c.is_ascii_digit());

        if is_rfc5424 {
            debug!("Attempting RFC 5424 parse");
            if let Ok(msg) = rfc5424::RFC5424Parser::parse(input) {
                return Ok(msg);
            }
        } else {
            debug!("Attempting RFC 3164 parse");
            if let Ok(msg) = rfc3164::RFC3164Parser::parse(input) {
                return Ok(msg);
            }
        }

        // Fallback for non-compliant logs: Convert into a synthetic RFC 5424 message
        debug!("Non-RFC log detected, applying synthetic transformation");

        // Try to identify if it's a LogHub-style message (Android) with a timestamp
        // Format: "12-18 15:28:53.604  9659  9724 D fingerprint: ..."
        let mut timestamp = None;
        if input.len() > 18 && input.chars().nth(2).is_some_and(|c| c == '-') {
            // Basic attempt to see if start looks like date: MM-DD HH:MM:SS
            // We'll just use current Utc but mark it as "parsed" if we had a real parser
            timestamp = Some(Utc::now());
        }

        Ok(SyslogMessage {
            priority: 13, // user.notice
            facility: 1,
            severity: 5,
            timestamp: timestamp.or(Some(Utc::now())),
            hostname: Some("log-transformed".to_string()),
            app_name: None,
            procid: None,
            msgid: None,
            structured_data: None,
            message: input.to_string(),
            is_rfc5424: true,
            node_id: None,
        })
    }
}
