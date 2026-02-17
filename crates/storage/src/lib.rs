pub mod backend;
pub mod logshrink;
pub mod manager;

use logshrink::{LogChunk, LogRecord, Template};
pub use manager::StorageManager;
use serde::{Deserialize, Serialize};
use std::fs;
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
    pub node_id_id_block: Vec<u8>,
}

pub struct StorageEngine;

impl StorageEngine {
    pub fn save_chunk(mut chunk: LogChunk, path: &str) -> anyhow::Result<u64> {
        // Sort records by template_id then timestamp for better locality/compression
        chunk.records.sort_by(|a, b| {
            a.template_id
                .cmp(&b.template_id)
                .then(a.timestamp.cmp(&b.timestamp))
        });

        let templates: Vec<Template> = chunk
            .templates
            .iter()
            .map(|(pattern, &id)| Template {
                id,
                pattern: pattern.clone(),
            })
            .collect();

        // Columnar extraction
        let mut timestamps = Vec::with_capacity(chunk.records.len());
        let mut priorities = Vec::with_capacity(chunk.records.len());
        let mut hostname_ids = Vec::with_capacity(chunk.records.len());
        let mut app_name_ids = Vec::with_capacity(chunk.records.len());
        let mut procid_ids = Vec::with_capacity(chunk.records.len());
        let mut msgid_ids = Vec::with_capacity(chunk.records.len());
        let mut sd_ids = Vec::with_capacity(chunk.records.len());
        let mut ids = Vec::with_capacity(chunk.records.len());
        let mut variables = Vec::with_capacity(chunk.records.len());
        let mut is_rfc5424s = Vec::with_capacity(chunk.records.len());
        let mut node_id_ids = Vec::with_capacity(chunk.records.len());

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
            node_id_ids.push(record.node_id_id);
        }

        // Delta encoding for timestamps
        let mut delta_ts = Vec::with_capacity(timestamps.len());
        if !timestamps.is_empty() {
            delta_ts.push(timestamps[0]);
            for i in 1..timestamps.len() {
                delta_ts.push(timestamps[i] - timestamps[i - 1]);
            }
        }

        let compressed = CompressedChunk {
            templates,
            string_pool: chunk.string_pool,
            timestamp_block: Self::compress(&delta_ts)?,
            priority_block: encode_all(&priorities[..], 3)?,
            hostname_id_block: Self::compress(&hostname_ids)?,
            app_name_id_block: Self::compress(&app_name_ids)?,
            procid_id_block: Self::compress(&procid_ids)?,
            msgid_id_block: Self::compress(&msgid_ids)?,
            sd_id_block: Self::compress(&sd_ids)?,
            template_id_block: Self::compress(&ids)?,
            variable_block: Self::compress(&variables)?,
            is_rfc5424_block: Self::compress(&is_rfc5424s)?,
            node_id_id_block: Self::compress(&node_id_ids)?,
        };

        let serialized = postcard::to_allocvec(&compressed)?;
        let size = serialized.len() as u64;
        fs::write(path, serialized)?;

        Ok(size)
    }

    fn compress<T: Serialize>(data: &T) -> anyhow::Result<Vec<u8>> {
        let serialized = postcard::to_allocvec(data)?;
        Ok(encode_all(&serialized[..], 3)?)
    }

    fn decompress<T: for<'de> Deserialize<'de>>(block: &[u8]) -> anyhow::Result<T> {
        let decompressed = decode_all(block)?;
        Ok(postcard::from_bytes(&decompressed)?)
    }

    pub fn load_chunk(path: &str) -> anyhow::Result<LogChunk> {
        let buf = fs::read(path)?;
        let compressed: CompressedChunk = postcard::from_bytes(&buf)?;

        let delta_ts: Vec<i64> = Self::decompress(&compressed.timestamp_block)?;

        let mut timestamps = Vec::with_capacity(delta_ts.len());
        if !delta_ts.is_empty() {
            let mut current = delta_ts[0];
            timestamps.push(current);
            for delta in delta_ts.iter().skip(1) {
                current += delta;
                timestamps.push(current);
            }
        }

        let priorities = decode_all(&compressed.priority_block[..])?;

        let hostname_ids: Vec<Option<u32>> = Self::decompress(&compressed.hostname_id_block)?;
        let app_name_ids: Vec<Option<u32>> = Self::decompress(&compressed.app_name_id_block)?;
        let procid_ids: Vec<Option<u32>> = Self::decompress(&compressed.procid_id_block)?;
        let msgid_ids: Vec<Option<u32>> = Self::decompress(&compressed.msgid_id_block)?;
        let sd_ids: Vec<Option<u32>> = Self::decompress(&compressed.sd_id_block)?;
        let ids: Vec<u32> = Self::decompress(&compressed.template_id_block)?;
        let variables: Vec<Vec<String>> = Self::decompress(&compressed.variable_block)?;
        let is_rfc5424s: Vec<bool> = Self::decompress(&compressed.is_rfc5424_block)?;
        let node_id_ids: Vec<Option<u32>> = Self::decompress(&compressed.node_id_id_block)?;

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
                node_id_id: node_id_ids[i],
            });
        }

        Ok(chunk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logshrink::LogChunk;
    use chrono::Utc;
    use sankshepa_protocol::SyslogMessage;
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
            node_id: None,
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
