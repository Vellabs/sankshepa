use crate::SyslogMessage;
use chrono::{DateTime, Utc};
use nom::{
    IResult,
    bytes::complete::{tag, take_until, take_while},
    character::complete::{digit1, space0, space1},
    combinator::map_res,
    sequence::delimited,
};

pub struct RFC5424Parser;

impl RFC5424Parser {
    pub fn parse(input: &str) -> anyhow::Result<SyslogMessage> {
        let (_, (pri, _version, timestamp, hostname, app_name, procid, msgid, sd, msg)) =
            parse_rfc5424(input).map_err(|e| anyhow::anyhow!("Parse error: {}", e))?;

        let priority = pri;
        let facility = priority >> 3;
        let severity = priority & 0x07;

        Ok(SyslogMessage {
            priority,
            facility,
            severity,
            timestamp,
            hostname,
            app_name,
            procid,
            msgid,
            structured_data: sd,
            message: msg.to_string(),
            is_rfc5424: true,
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

fn parse_timestamp(input: &str) -> IResult<&str, Option<DateTime<Utc>>> {
    let (input, ts_str) = take_while(|c: char| !c.is_whitespace())(input)?;
    if ts_str == "-" {
        Ok((input, None))
    } else {
        // Simple timestamp parsing, RFC 5424 uses RFC 3339
        match DateTime::parse_from_rfc3339(ts_str) {
            Ok(dt) => Ok((input, Some(dt.with_timezone(&Utc)))),
            Err(_) => Ok((input, None)),
        }
    }
}

fn parse_string_or_nil(input: &str) -> IResult<&str, Option<String>> {
    let (input, s) = take_while(|c: char| !c.is_whitespace())(input)?;
    if s == "-" {
        Ok((input, None))
    } else {
        Ok((input, Some(s.to_string())))
    }
}

type RFC5424Header<'a> = (
    u8, // pri
    u8, // version
    Option<DateTime<Utc>>,
    Option<String>, // hostname
    Option<String>, // app_name
    Option<String>, // procid
    Option<String>, // msgid
    Option<String>, // sd
    &'a str,        // msg
);

fn parse_rfc5424(input: &str) -> IResult<&str, RFC5424Header<'_>> {
    let (input, pri) = parse_pri(input)?;
    let (input, version) = map_res(digit1, |s: &str| s.parse::<u8>())(input)?;
    let (input, _) = space1(input)?;
    let (input, timestamp) = parse_timestamp(input)?;
    let (input, _) = space1(input)?;
    let (input, hostname) = parse_string_or_nil(input)?;
    let (input, _) = space1(input)?;
    let (input, app_name) = parse_string_or_nil(input)?;
    let (input, _) = space1(input)?;
    let (input, procid) = parse_string_or_nil(input)?;
    let (input, _) = space1(input)?;
    let (input, msgid) = parse_string_or_nil(input)?;
    let (input, _) = space1(input)?;

    // Structured data: either "-" or bracketed content
    let (input, sd) = if input.starts_with("-") {
        let (input, _) = tag("-")(input)?;
        (input, None)
    } else {
        let (input, _) = tag("[")(input)?;
        let (input, content) = take_until("]")(input)?;
        let (input, _) = tag("]")(input)?;
        (input, Some(content.to_string()))
    };

    let (input, _) = space0(input)?;
    let msg = input;

    Ok((
        "",
        (
            pri, version, timestamp, hostname, app_name, procid, msgid, sd, msg,
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rfc5424_basic() {
        let input = "<34>1 2003-10-11T22:14:15.003Z myhost myapp 1234 ID47 - Message content";
        let msg = RFC5424Parser::parse(input).unwrap();
        assert_eq!(msg.priority, 34);
        assert_eq!(msg.facility, 4);
        assert_eq!(msg.severity, 2);
        assert_eq!(msg.hostname.unwrap(), "myhost");
        assert_eq!(msg.app_name.unwrap(), "myapp");
        assert_eq!(msg.message, "Message content");
        assert!(msg.is_rfc5424);
    }

    #[test]
    fn test_parse_rfc5424_structured_data() {
        let input = "<34>1 2003-10-11T22:14:15.003Z myhost myapp 1234 ID47 [exampleSDID@32473 iut=\"3\"] Message with SD";
        let msg = RFC5424Parser::parse(input).unwrap();
        assert_eq!(msg.structured_data.unwrap(), "exampleSDID@32473 iut=\"3\"");
        assert_eq!(msg.message, "Message with SD");
    }

    #[test]
    fn test_parse_rfc5424_nil_hostname() {
        let input = "<34>1 2003-10-11T22:14:15.003Z - myapp 1234 ID47 - No hostname";
        let msg = RFC5424Parser::parse(input).unwrap();
        assert!(msg.hostname.is_none());
        assert_eq!(msg.app_name.unwrap(), "myapp");
    }

    #[test]
    fn test_parse_rfc5424_all_nil_optional_fields() {
        let input = "<13>1 2003-10-11T22:14:15.003Z - - - - - Minimal message";
        let msg = RFC5424Parser::parse(input).unwrap();
        assert!(msg.hostname.is_none());
        assert!(msg.app_name.is_none());
        assert!(msg.procid.is_none());
        assert!(msg.msgid.is_none());
        assert!(msg.structured_data.is_none());
        assert_eq!(msg.message, "Minimal message");
    }

    #[test]
    fn test_parse_rfc5424_nil_timestamp() {
        let input = "<34>1 - myhost myapp 1234 ID47 - Message";
        let msg = RFC5424Parser::parse(input).unwrap();
        assert!(msg.timestamp.is_none());
    }

    #[test]
    fn test_parse_rfc5424_procid_and_msgid() {
        let input = "<34>1 2003-10-11T22:14:15.003Z myhost myapp 9876 MSGID47 - Test";
        let msg = RFC5424Parser::parse(input).unwrap();
        assert_eq!(msg.procid.unwrap(), "9876");
        assert_eq!(msg.msgid.unwrap(), "MSGID47");
    }

    #[test]
    fn test_parse_rfc5424_invalid_input() {
        let input = "not a syslog message at all";
        assert!(RFC5424Parser::parse(input).is_err());
    }

    #[test]
    fn test_parse_rfc5424_facility_severity_calculation() {
        // priority 165 -> facility = 165 >> 3 = 20, severity = 165 & 7 = 5
        let input = "<165>1 2003-10-11T22:14:15.003Z host app - - - msg";
        let msg = RFC5424Parser::parse(input).unwrap();
        assert_eq!(msg.priority, 165);
        assert_eq!(msg.facility, 20);
        assert_eq!(msg.severity, 5);
    }
}
