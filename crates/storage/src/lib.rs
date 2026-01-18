pub mod logshrink;

use logshrink::{LogChunk, LogRecord, Template};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use zstd::stream::{decode_all, encode_all};

#[derive(Serialize, Deserialize)]
pub struct CompressedChunk {
    pub templates: Vec<Template>,
    pub string_pool: Vec<String>,
    pub timestamp_block: Vec<u8>,
    pub priority_block: Vec<u8>,
    pub hostname_id_block: Vec<u8>,
    pub app_name_id_block: Vec<u8>,
    pub procid_id_block: Vec<u8>,
    pub msgid_id_block: Vec<u8>,
    pub sd_id_block: Vec<u8>,
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
        let mut hostname_ids = Vec::new();
        let mut app_name_ids = Vec::new();
        let mut procid_ids = Vec::new();
        let mut msgid_ids = Vec::new();
        let mut sd_ids = Vec::new();
        let mut ids = Vec::new();
        let mut variables = Vec::new();
        let mut is_rfc5424s = Vec::new();

        for record in chunk.records {
            timestamps.push(record.timestamp);
            priorities.push(record.priority);
            hostname_ids.push(record.hostname_id);
            app_name_ids.push(record.app_name_id);
            procid_ids.push(record.procid_id);
            msgid_ids.push(record.msgid_id);
            sd_ids.push(record.structured_data_id);
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

        let ts_data = postcard::to_allocvec(&delta_ts)?;
        let pri_data = priorities;
        let host_data = postcard::to_allocvec(&hostname_ids)?;
        let app_data = postcard::to_allocvec(&app_name_ids)?;
        let proc_data = postcard::to_allocvec(&procid_ids)?;
        let msgid_data = postcard::to_allocvec(&msgid_ids)?;
        let sd_data = postcard::to_allocvec(&sd_ids)?;
        let id_data = postcard::to_allocvec(&ids)?;
        let var_data = postcard::to_allocvec(&variables)?;
        let rfc_data = postcard::to_allocvec(&is_rfc5424s)?;

        let compressed = CompressedChunk {
            templates,
            string_pool: chunk.string_pool,
            timestamp_block: encode_all(&ts_data[..], 3)?,
            priority_block: encode_all(&pri_data[..], 3)?,
            hostname_id_block: encode_all(&host_data[..], 3)?,
            app_name_id_block: encode_all(&app_data[..], 3)?,
            procid_id_block: encode_all(&proc_data[..], 3)?,
            msgid_id_block: encode_all(&msgid_data[..], 3)?,
            sd_id_block: encode_all(&sd_data[..], 3)?,
            template_id_block: encode_all(&id_data[..], 3)?,
            variable_block: encode_all(&var_data[..], 3)?,
            is_rfc5424_block: encode_all(&rfc_data[..], 3)?,
        };

        let mut file = File::create(path)?;
        let serialized = postcard::to_allocvec(&compressed)?;
        file.write_all(&serialized)?;

        Ok(())
    }

    pub fn load_chunk(path: &str) -> anyhow::Result<LogChunk> {
        let mut file = File::open(path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        let compressed: CompressedChunk = postcard::from_bytes(&buf)?;

        let ts_data = decode_all(&compressed.timestamp_block[..])?;
        let delta_ts: Vec<i64> = postcard::from_bytes(&ts_data)?;

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

        let host_data = decode_all(&compressed.hostname_id_block[..])?;
        let hostname_ids: Vec<Option<u32>> = postcard::from_bytes(&host_data)?;

        let app_data = decode_all(&compressed.app_name_id_block[..])?;
        let app_name_ids: Vec<Option<u32>> = postcard::from_bytes(&app_data)?;

        let proc_data = decode_all(&compressed.procid_id_block[..])?;
        let procid_ids: Vec<Option<u32>> = postcard::from_bytes(&proc_data)?;

        let msgid_data = decode_all(&compressed.msgid_id_block[..])?;
        let msgid_ids: Vec<Option<u32>> = postcard::from_bytes(&msgid_data)?;

        let sd_data = decode_all(&compressed.sd_id_block[..])?;
        let sd_ids: Vec<Option<u32>> = postcard::from_bytes(&sd_data)?;

        let id_data = decode_all(&compressed.template_id_block[..])?;
        let ids: Vec<u32> = postcard::from_bytes(&id_data)?;

        let var_data = decode_all(&compressed.variable_block[..])?;
        let variables: Vec<Vec<String>> = postcard::from_bytes(&var_data)?;

        let rfc_data = decode_all(&compressed.is_rfc5424_block[..])?;
        let is_rfc5424s: Vec<bool> = postcard::from_bytes(&rfc_data)?;

        let mut chunk = LogChunk::new();
        chunk.string_pool = compressed.string_pool;
        for t in compressed.templates {
            chunk.templates.insert(t.pattern, t.id);
        }
        chunk.next_template_id = chunk.templates.len() as u32;

        for i in 0..ids.len() {
            chunk.records.push(LogRecord {
                timestamp: timestamps[i],
                priority: priorities[i],
                hostname_id: hostname_ids[i],
                app_name_id: app_name_ids[i],
                procid_id: procid_ids[i],
                msgid_id: msgid_ids[i],
                structured_data_id: sd_ids[i],
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
    use sankshepa_protocol::SyslogMessage;
    use crate::logshrink::LogChunk;
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
        let hostname = loaded_chunk.records[0]
            .hostname_id
            .and_then(|id| loaded_chunk.string_pool.get(id as usize))
            .unwrap();
        assert_eq!(hostname, "testhost");
        let app_name = loaded_chunk.records[0]
            .app_name_id
            .and_then(|id| loaded_chunk.string_pool.get(id as usize))
            .unwrap();
        assert_eq!(app_name, "testapp");
        assert_eq!(loaded_chunk.templates.len(), 1);

        fs::remove_file(path).unwrap();
    }
}
