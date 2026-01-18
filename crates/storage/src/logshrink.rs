use chrono::Utc;
use sankshepa_protocol::SyslogMessage;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    pub id: u32,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRecord {
    pub timestamp: i64,
    pub priority: u8,
    pub hostname_id: Option<u32>,
    pub app_name_id: Option<u32>,
    pub procid_id: Option<u32>,
    pub msgid_id: Option<u32>,
    pub structured_data_id: Option<u32>,
    pub template_id: u32,
    pub variables: Vec<String>,
    pub is_rfc5424: bool,
    pub node_id_id: Option<u32>,
}

pub struct LogChunk {
    pub raw_messages: Vec<SyslogMessage>,
    pub templates: HashMap<String, u32>,
    pub string_pool: Vec<String>,
    pub string_map: HashMap<String, u32>,
    pub records: Vec<LogRecord>,
    pub next_template_id: u32,
}

impl LogChunk {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for LogChunk {
    fn default() -> Self {
        Self {
            raw_messages: Vec::with_capacity(10),
            templates: HashMap::new(),
            string_pool: Vec::new(),
            string_map: HashMap::new(),
            records: Vec::with_capacity(10),
            next_template_id: 0,
        }
    }
}

impl LogChunk {
    fn intern_string(&mut self, s: Option<String>) -> Option<u32> {
        let s = s?;
        if let Some(&id) = self.string_map.get(&s) {
            Some(id)
        } else {
            let id = self.string_pool.len() as u32;
            self.string_map.insert(s.clone(), id);
            self.string_pool.push(s);
            Some(id)
        }
    }

    pub fn add_message(&mut self, msg: SyslogMessage) {
        self.raw_messages.push(msg);
    }

    pub fn import_template(&mut self, pattern: String) {
        if !self.templates.contains_key(&pattern) {
            let id = self.next_template_id;
            self.templates.insert(pattern, id);
            self.next_template_id += 1;
        }
    }

    pub fn finish_and_process(&mut self) -> Vec<String> {
        let mut new_templates = Vec::new();
        let old_templates: HashSet<String> = self.templates.keys().cloned().collect();

        if self.raw_messages.is_empty() {
            return new_templates;
        }

        let mut groups: HashMap<usize, Vec<usize>> = HashMap::new();
        for (idx, msg) in self.raw_messages.iter().enumerate() {
            let token_count = msg.message.split_whitespace().count();
            groups.entry(token_count).or_default().push(idx);
        }

        let mut group_keys: Vec<usize> = groups.keys().cloned().collect();
        group_keys.sort();

        for len in group_keys {
            if let Some(indices) = groups.get(&len) {
                self.process_group(indices);
            }
        }

        for pattern in self.templates.keys() {
            if !old_templates.contains(pattern) {
                new_templates.push(pattern.clone());
            }
        }

        self.raw_messages.clear();
        new_templates
    }

    fn process_group(&mut self, indices: &[usize]) {
        let mut group_templates: Vec<(Vec<String>, Vec<usize>)> = Vec::new();

        for &idx in indices {
            let msg_text = &self.raw_messages[idx].message;
            let tokens: Vec<String> = msg_text.split_whitespace().map(|s| s.to_string()).collect();

            let mut found_match = false;
            for (template_tokens, member_indices) in &mut group_templates {
                if self.is_similar(template_tokens, &tokens) {
                    self.merge_into_template(template_tokens, &tokens);
                    member_indices.push(idx);
                    found_match = true;
                    break;
                }
            }

            if !found_match {
                group_templates.push((tokens, vec![idx]));
            }
        }

        for (tokens, member_indices) in group_templates {
            let template_str = tokens.join(" ");
            let template_id = if let Some(&id) = self.templates.get(&template_str) {
                id
            } else {
                let id = self.next_template_id;
                self.templates.insert(template_str.clone(), id);
                self.next_template_id += 1;
                id
            };

            for &idx in &member_indices {
                let msg = self.raw_messages[idx].clone();
                let msg_tokens: Vec<&str> = msg.message.split_whitespace().collect();
                let mut variables = Vec::new();

                for (i, token) in tokens.iter().enumerate() {
                    if token == "<*>" && i < msg_tokens.len() {
                        variables.push(msg_tokens[i].to_string());
                    }
                }

                let hostname_id = self.intern_string(msg.hostname);
                let app_name_id = self.intern_string(msg.app_name);
                let procid_id = self.intern_string(msg.procid);
                let msgid_id = self.intern_string(msg.msgid);
                let structured_data_id = self.intern_string(msg.structured_data);
                let node_id_id = self.intern_string(msg.node_id);

                self.records.push(LogRecord {
                    timestamp: msg.timestamp.unwrap_or_else(Utc::now).timestamp_millis(),
                    priority: msg.priority,
                    hostname_id,
                    app_name_id,
                    procid_id,
                    msgid_id,
                    structured_data_id,
                    template_id,
                    variables,
                    is_rfc5424: msg.is_rfc5424,
                    node_id_id,
                });
            }
        }
    }

    fn is_similar(&self, template: &[String], tokens: &[String]) -> bool {
        if template.len() != tokens.len() {
            return false;
        }
        if template.is_empty() {
            return true;
        }

        let mut sim_count = 0;
        for (t, s) in template.iter().zip(tokens.iter()) {
            if t == s || t == "<*>" {
                sim_count += 1;
            }
        }

        sim_count as f32 / template.len() as f32 >= 0.5
    }

    fn merge_into_template(&self, template: &mut [String], tokens: &[String]) {
        for i in 0..template.len() {
            if template[i] != tokens[i] && template[i] != "<*>" {
                template[i] = "<*>".to_string();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sankshepa_protocol::SyslogMessage;

    fn create_msg(text: &str) -> SyslogMessage {
        SyslogMessage {
            priority: 34,
            facility: 4,
            severity: 2,
            timestamp: Some(Utc::now()),
            hostname: Some("host".to_string()),
            app_name: None,
            procid: None,
            msgid: None,
            structured_data: None,
            message: text.to_string(),
            is_rfc5424: false,
        }
    }

    #[test]
    fn test_template_discovery() {
        let mut chunk = LogChunk::new();
        chunk.add_message(create_msg("User alice logged in from 192.168.1.1"));
        chunk.add_message(create_msg("User bob logged in from 192.168.1.2"));
        chunk.add_message(create_msg("System restart"));

        chunk.finish_and_process();

        assert_eq!(chunk.templates.len(), 2);

        let patterns: Vec<String> = chunk.templates.keys().cloned().collect();
        assert!(patterns.iter().any(|p| p == "User <*> logged in from <*>"));
        assert!(patterns.iter().any(|p| p == "System restart"));

        assert_eq!(chunk.records.len(), 3);

        // Find the record for alice
        let alice_record = chunk
            .records
            .iter()
            .find(|r| r.variables.contains(&"alice".to_string()))
            .expect("Should find alice record");
        assert_eq!(
            alice_record.variables,
            vec!["alice".to_string(), "192.168.1.1".to_string()]
        );
    }
}
