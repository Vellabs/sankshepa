pub mod logshrink;

use logshrink::{LogChunk, LogRecord, Template};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use zstd::stream::{decode_all, encode_all};

#[derive(Serialize, Deserialize)]
pub struct CompressedChunk {
    pub templates: Vec<Template>,
    pub timestamp_block: Vec<u8>,
    pub priority_block: Vec<u8>,
    pub hostname_block: Vec<u8>,
    pub app_name_block: Vec<u8>,
    pub procid_block: Vec<u8>,
    pub msgid_block: Vec<u8>,
    pub sd_block: Vec<u8>,
    pub template_id_block: Vec<u8>,
    pub variable_block: Vec<u8>,
    pub is_rfc5424_block: Vec<u8>,
}

pub struct StorageEngine;

impl StorageEngine {
    pub fn save_chunk(chunk: LogChunk, path: &str) -> anyhow::Result<()> {
        let mut templates = Vec::new();
        for (pattern, &id) in &chunk.templates {
            templates.push(Template {
                id,
                pattern: pattern.clone(),
            });
        }

        // Columnar extraction
        let mut timestamps = Vec::new();
        let mut priorities = Vec::new();
        let mut hostnames = Vec::new();
        let mut app_names = Vec::new();
        let mut procids = Vec::new();
        let mut msgids = Vec::new();
        let mut sds = Vec::new();
        let mut ids = Vec::new();
        let mut variables = Vec::new();
        let mut is_rfc5424s = Vec::new();

        for record in chunk.records {
            timestamps.push(record.timestamp);
            priorities.push(record.priority);
            hostnames.push(record.hostname);
            app_names.push(record.app_name);
            procids.push(record.procid);
            msgids.push(record.msgid);
            sds.push(record.structured_data);
            ids.push(record.template_id);
            variables.push(record.variables);
            is_rfc5424s.push(record.is_rfc5424);
        }

        // Delta encoding for timestamps
        let mut delta_ts = Vec::new();
        if !timestamps.is_empty() {
            delta_ts.push(timestamps[0]);
            for i in 1..timestamps.len() {
                delta_ts.push(timestamps[i] - timestamps[i - 1]);
            }
        }

        let ts_data = bincode::serialize(&delta_ts)?;
        let pri_data = priorities;
        let host_data = bincode::serialize(&hostnames)?;
        let app_data = bincode::serialize(&app_names)?;
        let proc_data = bincode::serialize(&procids)?;
        let msgid_data = bincode::serialize(&msgids)?;
        let sd_data = bincode::serialize(&sds)?;
        let id_data = bincode::serialize(&ids)?;
        let var_data = bincode::serialize(&variables)?;
        let rfc_data = bincode::serialize(&is_rfc5424s)?;

        let compressed = CompressedChunk {
            templates,
            timestamp_block: encode_all(&ts_data[..], 3)?,
            priority_block: encode_all(&pri_data[..], 3)?,
            hostname_block: encode_all(&host_data[..], 3)?,
            app_name_block: encode_all(&app_data[..], 3)?,
            procid_block: encode_all(&proc_data[..], 3)?,
            msgid_block: encode_all(&msgid_data[..], 3)?,
            sd_block: encode_all(&sd_data[..], 3)?,
            template_id_block: encode_all(&id_data[..], 3)?,
            variable_block: encode_all(&var_data[..], 3)?,
            is_rfc5424_block: encode_all(&rfc_data[..], 3)?,
        };

        let mut file = File::create(path)?;
        let serialized = bincode::serialize(&compressed)?;
        file.write_all(&serialized)?;

        Ok(())
    }

    pub fn load_chunk(path: &str) -> anyhow::Result<LogChunk> {
        let mut file = File::open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let compressed: CompressedChunk = bincode::deserialize(&buf)?;

        let ts_data = decode_all(&compressed.timestamp_block[..])?;
        let delta_ts: Vec<i64> = bincode::deserialize(&ts_data)?;

        let mut timestamps = Vec::new();
        if !delta_ts.is_empty() {
            let mut current = delta_ts[0];
            timestamps.push(current);
            for delta in delta_ts.iter().skip(1) {
                current += delta;
                timestamps.push(current);
            }
        }

        let priorities = decode_all(&compressed.priority_block[..])?;

        let host_data = decode_all(&compressed.hostname_block[..])?;
        let hostnames: Vec<Option<String>> = bincode::deserialize(&host_data)?;

        let app_data = decode_all(&compressed.app_name_block[..])?;
        let app_names: Vec<Option<String>> = bincode::deserialize(&app_data)?;

        let proc_data = decode_all(&compressed.procid_block[..])?;
        let procids: Vec<Option<String>> = bincode::deserialize(&proc_data)?;

        let msgid_data = decode_all(&compressed.msgid_block[..])?;
        let msgids: Vec<Option<String>> = bincode::deserialize(&msgid_data)?;

        let sd_data = decode_all(&compressed.sd_block[..])?;
        let sds: Vec<Option<String>> = bincode::deserialize(&sd_data)?;

        let id_data = decode_all(&compressed.template_id_block[..])?;
        let ids: Vec<u32> = bincode::deserialize(&id_data)?;

        let var_data = decode_all(&compressed.variable_block[..])?;
        let variables: Vec<Vec<String>> = bincode::deserialize(&var_data)?;

        let rfc_data = decode_all(&compressed.is_rfc5424_block[..])?;
        let is_rfc5424s: Vec<bool> = bincode::deserialize(&rfc_data)?;

        let mut chunk = LogChunk::new();
        for t in compressed.templates {
            chunk.templates.insert(t.pattern, t.id);
        }
        chunk.next_template_id = chunk.templates.len() as u32;

        for i in 0..ids.len() {
            chunk.records.push(LogRecord {
                timestamp: timestamps[i],
                priority: priorities[i],
                hostname: hostnames[i].clone(),
                app_name: app_names[i].clone(),
                procid: procids[i].clone(),
                msgid: msgids[i].clone(),
                structured_data: sds[i].clone(),
                template_id: ids[i],
                variables: variables[i].clone(),
                is_rfc5424: is_rfc5424s[i],
            });
        }

        Ok(chunk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::SyslogMessage;
    use crate::storage::logshrink::LogChunk;
    use chrono::Utc;
    use std::fs;

    #[test]
    fn test_storage_save_load() {
        let mut chunk = LogChunk::new();
        let msg = SyslogMessage {
            priority: 34,
            facility: 4,
            severity: 2,
            timestamp: Some(Utc::now()),
            hostname: Some("testhost".to_string()),
            app_name: Some("testapp".to_string()),
            procid: None,
            msgid: None,
            structured_data: None,
            message: "Something happened".to_string(),
            is_rfc5424: true,
        };
        chunk.add_message(msg);
        chunk.finish_and_process();

        let path = "test_chunk.lshrink";

        StorageEngine::save_chunk(chunk, path).unwrap();

        let loaded_chunk = StorageEngine::load_chunk(path).unwrap();

        assert_eq!(loaded_chunk.records.len(), 1);
        assert_eq!(
            loaded_chunk.records[0].hostname,
            Some("testhost".to_string())
        );
        assert_eq!(
            loaded_chunk.records[0].app_name,
            Some("testapp".to_string())
        );
        assert_eq!(loaded_chunk.templates.len(), 1);

        fs::remove_file(path).unwrap();
    }
}
