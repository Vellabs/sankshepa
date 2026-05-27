use crate::SyslogMessage;
use chrono::Utc;
use nom::{
    IResult,
    bytes::complete::{tag, take_while},
    character::complete::{digit1, space1},
    combinator::map_res,
    sequence::delimited,
};

pub struct RFC3164Parser;

impl RFC3164Parser {
    pub fn parse(input: &str) -> anyhow::Result<SyslogMessage> {
        let (_, (pri, timestamp, hostname, msg)) =
            parse_rfc3164(input).map_err(|e| anyhow::anyhow!("Parse error: {}", e))?;

        let priority = pri;
        let facility = priority >> 3;
        let severity = priority & 0x07;

        Ok(SyslogMessage {
            priority,
            facility,
            severity,
            timestamp,
            hostname: Some(hostname.to_string()),
            app_name: None,
            procid: None,
            msgid: None,
            structured_data: None,
            message: msg.to_string(),
            is_rfc5424: false,
            node_id: None,
        })
    }
}

fn parse_pri(input: &str) -> IResult<&str, u8> {
    delimited(
        tag("<"),
        map_res(digit1, |s: &str| s.parse::<u8>()),
        tag(">"),
    )(input)
}

type RFC3164Header<'a> = (u8, Option<chrono::DateTime<Utc>>, &'a str, &'a str);

fn parse_rfc3164(input: &str) -> IResult<&str, RFC3164Header<'_>> {
    let (input, pri) = parse_pri(input)?;

    // BSD Timestamp: Mmm dd hh:mm:ss
    let (input, _month) = take_while(|c: char| c != ' ')(input)?; // Month
    let (input, _) = space1(input)?;
    let (input, _day) = take_while(|c: char| c != ' ')(input)?; // Day
    let (input, _) = space1(input)?;
    let (input, _time) = take_while(|c: char| c != ' ')(input)?; // Time
    let (input, _) = space1(input)?;

    // For now, let's just return current time for simplicity or try to parse
    // RFC 3164 timestamps lack a year.
    let timestamp = Utc::now();

    let (input, hostname) = take_while(|c: char| c != ' ')(input)?;
    let (input, _) = space1(input)?;
    let msg = input;

    Ok(("", (pri, Some(timestamp), hostname, msg)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rfc3164_basic() {
        let raw = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";
        let msg = RFC3164Parser::parse(raw).unwrap();
        assert_eq!(msg.priority, 34);
        assert_eq!(msg.facility, 4);
        assert_eq!(msg.severity, 2);
        assert_eq!(msg.hostname, Some("mymachine".to_string()));
        assert_eq!(
            msg.message,
            "su: 'su root' failed for lonvick on /dev/pts/8"
        );
        assert!(!msg.is_rfc5424);
    }

    #[test]
    fn test_parse_rfc3164_priority_zero() {
        let raw = "<0>Jan  1 00:00:00 host kernel: boot";
        let msg = RFC3164Parser::parse(raw).unwrap();
        assert_eq!(msg.priority, 0);
        assert_eq!(msg.facility, 0);
        assert_eq!(msg.severity, 0);
    }

    #[test]
    fn test_parse_rfc3164_high_priority() {
        let raw = "<191>Dec 31 23:59:59 host proc: message";
        let msg = RFC3164Parser::parse(raw).unwrap();
        assert_eq!(msg.priority, 191);
        assert_eq!(msg.facility, 23); // 191 >> 3 = 23
        assert_eq!(msg.severity, 7); // 191 & 7 = 7
    }

    #[test]
    fn test_parse_rfc3164_multiword_message() {
        let raw = "<13>Feb 28 12:00:00 myserver sshd: Connection from 10.0.0.1 port 22 rejected";
        let msg = RFC3164Parser::parse(raw).unwrap();
        assert_eq!(msg.hostname, Some("myserver".to_string()));
        assert_eq!(
            msg.message,
            "sshd: Connection from 10.0.0.1 port 22 rejected"
        );
    }

    #[test]
    fn test_parse_rfc3164_sets_timestamp() {
        let raw = "<34>Oct 11 22:14:15 host message";
        let msg = RFC3164Parser::parse(raw).unwrap();
        assert!(msg.timestamp.is_some());
    }

    #[test]
    fn test_parse_rfc3164_is_not_rfc5424() {
        let raw = "<34>Oct 11 22:14:15 host message";
        let msg = RFC3164Parser::parse(raw).unwrap();
        assert!(!msg.is_rfc5424);
    }

    #[test]
    fn test_parse_rfc3164_invalid_input() {
        let raw = "not a valid syslog message";
        assert!(RFC3164Parser::parse(raw).is_err());
    }

    #[test]
    fn test_parse_rfc3164_missing_bracket() {
        let raw = "34>Oct 11 22:14:15 host message";
        assert!(RFC3164Parser::parse(raw).is_err());
    }
}
