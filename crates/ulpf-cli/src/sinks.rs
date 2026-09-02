//! Output sinks for normalized OCSF events.
//!
//! The NDJSON writer remains the default because it is easy to inspect and
//! stream. Optional sinks are deliberately dependency-light: OpenSearch and
//! Splunk HEC use bounded HTTP/1.1 batches over a local/trusted endpoint, while
//! the Parquet writer emits a standards-compliant four-column event archive
//! without requiring Python or a runtime plugin.

use std::io::{Read, Seek, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context};
use ulpf_ocsf::OcsfEvent;

const MAX_HTTP_RESPONSE: usize = 64 * 1024;

pub struct SinkSet {
    parquet: Option<ParquetSink>,
    opensearch: Option<OpenSearchSink>,
    splunk: Option<SplunkHecSink>,
}

pub struct AsyncSinkSet {
    sender: Option<std::sync::mpsc::SyncSender<OcsfEvent>>,
    thread: Option<std::thread::JoinHandle<anyhow::Result<()>>>,
}

impl AsyncSinkSet {
    pub fn new(
        parquet: Option<&Path>,
        opensearch: Option<&str>,
        opensearch_index: &str,
        splunk_hec: Option<&str>,
        splunk_token_env: &str,
        batch_size: usize,
    ) -> anyhow::Result<Self> {
        let mut inner = SinkSet::new(
            parquet,
            opensearch,
            opensearch_index,
            splunk_hec,
            splunk_token_env,
            batch_size,
        )?;

        if inner.is_empty() {
            return Ok(Self {
                sender: None,
                thread: None,
            });
        }

        let (tx, rx) = std::sync::mpsc::sync_channel(5000);
        let thread = std::thread::spawn(move || -> anyhow::Result<()> {
            for event in rx {
                inner.write(&event)?;
            }
            inner.finish()?;
            Ok(())
        });

        Ok(Self {
            sender: Some(tx),
            thread: Some(thread),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.sender.is_none()
    }

    pub fn write(&mut self, event: &OcsfEvent) -> anyhow::Result<()> {
        if let Some(tx) = &self.sender {
            // Blocks if the channel is full, applying backpressure to the ingest thread
            let _ = tx.send(event.clone());
        }
        Ok(())
    }

    pub fn finish(mut self) -> anyhow::Result<()> {
        if let Some(tx) = self.sender.take() {
            drop(tx);
        }
        if let Some(thread) = self.thread.take() {
            match thread.join() {
                Ok(res) => res?,
                Err(_) => bail!("sink thread panicked"),
            }
        }
        Ok(())
    }
}

impl SinkSet {
    pub fn new(
        parquet: Option<&Path>,
        opensearch: Option<&str>,
        opensearch_index: &str,
        splunk_hec: Option<&str>,
        splunk_token_env: &str,
        batch_size: usize,
    ) -> anyhow::Result<Self> {
        let batch_size = batch_size.max(1);
        Ok(Self {
            parquet: parquet
                .map(|path| ParquetSink::create(path, batch_size))
                .transpose()?,
            opensearch: opensearch
                .map(|url| OpenSearchSink::new(url, opensearch_index, batch_size))
                .transpose()?,
            splunk: splunk_hec
                .map(|url| SplunkHecSink::new(url, splunk_token_env, batch_size))
                .transpose()?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.parquet.is_none() && self.opensearch.is_none() && self.splunk.is_none()
    }

    pub fn write(&mut self, event: &OcsfEvent) -> anyhow::Result<()> {
        if let Some(sink) = &mut self.parquet {
            sink.write(event)?;
        }
        if let Some(sink) = &mut self.opensearch {
            sink.write(event)?;
        }
        if let Some(sink) = &mut self.splunk {
            sink.write(event)?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> anyhow::Result<()> {
        if let Some(sink) = &mut self.parquet {
            sink.flush()?;
        }
        if let Some(sink) = &mut self.opensearch {
            sink.flush()?;
        }
        if let Some(sink) = &mut self.splunk {
            sink.flush()?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> anyhow::Result<()> {
        self.flush()?;
        if let Some(sink) = self.parquet.take() {
            sink.finish()?;
        }
        Ok(())
    }
}

struct HttpEndpoint {
    host: String,
    port: u16,
    path: String,
}

impl HttpEndpoint {
    fn parse(url: &str) -> anyhow::Result<Self> {
        let Some(rest) = url.strip_prefix("http://") else {
            bail!("sink URL must use http://; terminate TLS at a trusted local proxy (got {url})");
        };
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        if authority.is_empty() {
            bail!("sink URL has no host: {url}");
        }
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if port.parse::<u16>().is_ok() => {
                (host.trim_matches(['[', ']']).to_string(), port.parse()?)
            }
            _ => (authority.to_string(), 80),
        };
        if host.is_empty() {
            bail!("sink URL has no host: {url}");
        }
        if host
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            bail!("sink URL host contains whitespace or control characters");
        }
        if path.bytes().any(|byte| byte.is_ascii_control()) {
            bail!("sink URL path contains control characters");
        }
        Ok(Self {
            host,
            port,
            path: format!("/{}", path.trim_start_matches('/')),
        })
    }

    fn post(
        &self,
        body: &[u8],
        content_type: &str,
        authorization: Option<&str>,
    ) -> anyhow::Result<Vec<u8>> {
        let address = if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        };
        let socket = address
            .to_socket_addrs()
            .with_context(|| format!("resolving sink host {}", self.host))?
            .next()
            .ok_or_else(|| anyhow::anyhow!("could not resolve sink host {}", self.host))?;
        let mut stream = TcpStream::connect_timeout(&socket, Duration::from_secs(5))
            .with_context(|| format!("connecting to sink {address}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let host_header = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        write!(
            stream,
            "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            if self.path == "/" { "/" } else { &self.path },
            host_header,
            content_type,
            body.len()
        )?;
        if let Some(value) = authorization {
            write!(stream, "Authorization: {value}\r\n")?;
        }
        write!(stream, "\r\n")?;
        stream.write_all(body)?;
        stream.flush()?;

        let mut response = Vec::with_capacity(512);
        stream
            .take(MAX_HTTP_RESPONSE as u64)
            .read_to_end(&mut response)?;
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap_or(response.len());
        let status = response
            .split(|byte| *byte == b' ')
            .nth(1)
            .and_then(|part| std::str::from_utf8(part).ok())
            .and_then(|part| part.parse::<u16>().ok())
            .unwrap_or(0);
        if !(200..300).contains(&status) {
            let body_start = header_end.saturating_add(4).min(response.len());
            let detail = String::from_utf8_lossy(&response[body_start..]);
            bail!("sink returned HTTP {status}: {}", detail.trim());
        }
        let body_start = header_end.saturating_add(4).min(response.len());
        Ok(response[body_start..].to_vec())
    }
}

struct BatchHttp {
    endpoint: HttpEndpoint,
    content_type: &'static str,
    authorization: Option<String>,
    body: Vec<u8>,
    count: usize,
    batch_size: usize,
}

impl BatchHttp {
    fn push(&mut self, line: &[u8]) -> anyhow::Result<()> {
        self.body.extend_from_slice(line);
        self.body.push(b'\n');
        self.count += 1;
        Ok(())
    }

    fn flush(&mut self) -> anyhow::Result<Vec<u8>> {
        if self.count == 0 {
            return Ok(Vec::new());
        }
        let response =
            self.endpoint
                .post(&self.body, self.content_type, self.authorization.as_deref())?;
        self.body.clear();
        self.count = 0;
        Ok(response)
    }
}

pub struct OpenSearchSink {
    batch: BatchHttp,
    index: String,
}

impl OpenSearchSink {
    fn new(url: &str, index: &str, batch_size: usize) -> anyhow::Result<Self> {
        let mut endpoint = HttpEndpoint::parse(url)?;
        endpoint.path = format!("{}/_bulk", endpoint.path.trim_end_matches('/'));
        let token = std::env::var("ULPF_OPENSEARCH_TOKEN").ok();
        Ok(Self {
            batch: BatchHttp {
                endpoint,
                content_type: "application/x-ndjson",
                authorization: token.map(|value| format!("Bearer {value}")),
                body: Vec::new(),
                count: 0,
                batch_size: batch_size.saturating_mul(2).max(2),
            },
            index: index.to_string(),
        })
    }

    fn write(&mut self, event: &OcsfEvent) -> anyhow::Result<()> {
        let mut target = serde_json::Map::new();
        target.insert(
            "_index".into(),
            serde_json::Value::String(self.index.clone()),
        );
        if let Some(uid) = event.uid() {
            // A stable document id makes a replay after a destination outage
            // idempotent for OpenSearch, even though the source vault remains
            // the authoritative delivery record.
            target.insert("_id".into(), serde_json::Value::String(uid.to_string()));
        }
        let action = serde_json::json!({"index": target});
        self.batch
            .push(serde_json::to_string(&action)?.as_bytes())?;
        self.batch.push(event.to_json().as_bytes())?;
        if self.batch.count >= self.batch.batch_size {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        if self.batch.count == 0 {
            return Ok(());
        }
        let response = self.batch.flush()?;
        if response.is_empty() {
            bail!("OpenSearch bulk sink returned an empty response");
        }
        let value: serde_json::Value = serde_json::from_slice(&response)
            .context("OpenSearch bulk sink returned a non-JSON response")?;
        if value.get("errors").and_then(serde_json::Value::as_bool) == Some(true) {
            let detail = value
                .get("items")
                .and_then(serde_json::Value::as_array)
                .and_then(|items| {
                    items.iter().find(|item| {
                        item.get("index")
                            .and_then(|index| index.get("error"))
                            .is_some()
                    })
                })
                .map(serde_json::Value::to_string)
                .unwrap_or_else(|| "bulk item failed".into());
            bail!("OpenSearch bulk response reported an item error: {detail}");
        }
        Ok(())
    }
}

pub struct SplunkHecSink {
    batch: BatchHttp,
}

impl SplunkHecSink {
    fn new(url: &str, token_env: &str, batch_size: usize) -> anyhow::Result<Self> {
        let endpoint = HttpEndpoint::parse(url)?;
        let token = std::env::var(token_env).with_context(|| {
            format!("Splunk HEC token environment variable {token_env} is not set")
        })?;
        Ok(Self {
            batch: BatchHttp {
                endpoint,
                content_type: "application/json",
                authorization: Some(format!("Splunk {token}")),
                body: Vec::new(),
                count: 0,
                batch_size,
            },
        })
    }

    fn write(&mut self, event: &OcsfEvent) -> anyhow::Result<()> {
        let payload = serde_json::json!({
            "event": event.to_value(),
            "source": "ulpf",
            "sourcetype": "ocsf",
        });
        self.batch
            .push(serde_json::to_string(&payload)?.as_bytes())?;
        if self.batch.count >= self.batch.batch_size {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        let response = self.batch.flush()?;
        if response.is_empty() {
            return Ok(());
        }
        let value: serde_json::Value =
            serde_json::from_slice(&response).context("Splunk HEC returned a non-JSON response")?;
        if value.get("code").and_then(serde_json::Value::as_i64) != Some(0) {
            bail!("Splunk HEC reported an error: {value}");
        }
        Ok(())
    }
}

/// A minimal Parquet writer for a single required BYTE_ARRAY column named
/// `event_json`. Each flush creates one row group, so memory stays bounded by
/// the sink batch size. The JSON values remain complete OCSF documents.
pub struct ParquetSink {
    base_dir: std::path::PathBuf,
    active_partition: Option<String>,
    file: Option<std::fs::File>,
    rows: Vec<ParquetRow>,
    row_groups: Vec<RowGroupMeta>,
    batch_size: usize,
}

#[derive(Debug)]
struct ParquetRow {
    event_json: Vec<u8>,
    class_uid: i64,
    activity_id: i64,
    time: i64,
}

#[derive(Debug)]
struct RowGroupMeta {
    rows: i64,
    columns: Vec<ColumnMeta>,
}

#[derive(Debug)]
struct ColumnMeta {
    path: &'static str,
    type_id: i32,
    offset: i64,
    page_size: i64,
    rows: i64,
}

impl ParquetSink {
    fn create(path: &Path, batch_size: usize) -> anyhow::Result<Self> {
        std::fs::create_dir_all(path)?;
        Ok(Self {
            base_dir: path.to_path_buf(),
            active_partition: None,
            file: None,
            rows: Vec::new(),
            row_groups: Vec::new(),
            batch_size: batch_size.max(1),
        })
    }

    fn write(&mut self, event: &OcsfEvent) -> anyhow::Result<()> {
        let class_uid = event
            .class_uid()
            .ok_or_else(|| anyhow::anyhow!("event has no class_uid"))?;
        let activity_id = event
            .get_path("activity_id")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| anyhow::anyhow!("event has no activity_id"))?;
        let time = event
            .get_path("time")
            .and_then(serde_json::Value::as_i64)
            .ok_or_else(|| anyhow::anyhow!("event has no time"))?;

        use chrono::{DateTime, Utc};
        let timestamp = DateTime::from_timestamp_millis(time).unwrap_or_default();
        let partition = timestamp.format("dt=%Y-%m-%d").to_string();

        if self.active_partition.as_ref() != Some(&partition) {
            self.rotate_partition(&partition)?;
        }

        self.rows.push(ParquetRow {
            event_json: event.to_json().into_bytes(),
            class_uid,
            activity_id,
            time,
        });
        if self.rows.len() >= self.batch_size {
            self.flush()?;
        }
        Ok(())
    }

    fn rotate_partition(&mut self, new_partition: &str) -> anyhow::Result<()> {
        if self.file.is_some() {
            self.finish_file()?;
        }
        
        let part_dir = self.base_dir.join(new_partition);
        std::fs::create_dir_all(&part_dir)?;
        
        let filename = format!("events-{}.parquet", uuid::Uuid::now_v7());
        let file_path = part_dir.join(filename);
        
        let mut file = std::fs::File::create(&file_path)
            .with_context(|| format!("creating Parquet sink partition {}", file_path.display()))?;
        file.write_all(b"PAR1")?;
        
        self.file = Some(file);
        self.active_partition = Some(new_partition.to_string());
        
        Ok(())
    }

    fn finish_file(&mut self) -> anyhow::Result<()> {
        self.flush()?;
        if let Some(mut file) = self.file.take() {
            let total_rows: i64 = self.row_groups.iter().map(|group| group.rows).sum();
            let metadata = file_metadata(&self.row_groups, total_rows);
            file.write_all(&metadata)?;
            file.write_all(&(metadata.len() as u32).to_le_bytes())?;
            file.write_all(b"PAR1")?;
            file.flush()?;
        }
        self.row_groups.clear();
        Ok(())
    }

    fn flush(&mut self) -> anyhow::Result<()> {
        if self.rows.is_empty() {
            return Ok(());
        }
        if self.file.is_none() {
            return Ok(());
        }
        
        let rows = self.rows.len() as i64;
        let mut columns = Vec::with_capacity(4);
        let pages = [
            (
                "event_json",
                6,
                self.rows.iter().fold(Vec::new(), |mut body, row| {
                    body.extend_from_slice(&(row.event_json.len() as u32).to_le_bytes());
                    body.extend_from_slice(&row.event_json);
                    body
                }),
            ),
            (
                "class_uid",
                2,
                self.rows.iter().fold(Vec::new(), |mut body, row| {
                    body.extend_from_slice(&row.class_uid.to_le_bytes());
                    body
                }),
            ),
            (
                "activity_id",
                2,
                self.rows.iter().fold(Vec::new(), |mut body, row| {
                    body.extend_from_slice(&row.activity_id.to_le_bytes());
                    body
                }),
            ),
            (
                "time",
                2,
                self.rows.iter().fold(Vec::new(), |mut body, row| {
                    body.extend_from_slice(&row.time.to_le_bytes());
                    body
                }),
            ),
        ];
        
        let file = self.file.as_mut().unwrap();
        for (path, type_id, body) in pages {
            let header = page_header(body.len() as i32, body.len() as i32, rows as i32);
            let offset = file.stream_position()? as i64;
            file.write_all(&header)?;
            file.write_all(&body)?;
            columns.push(ColumnMeta {
                path,
                type_id,
                offset,
                page_size: (header.len() + body.len()) as i64,
                rows,
            });
        }
        self.row_groups.push(RowGroupMeta { rows, columns });
        self.rows.clear();
        Ok(())
    }

    fn finish(mut self) -> anyhow::Result<()> {
        if self.file.is_some() {
            self.finish_file()?;
        }
        Ok(())
    }
}

fn page_header(uncompressed: i32, compressed: i32, rows: i32) -> Vec<u8> {
    let mut out = Compact::default();
    out.field_i32(1, 0); // DATA_PAGE
    out.field_i32(2, uncompressed);
    out.field_i32(3, compressed);
    let mut data = Compact::default();
    data.field_i32(1, rows);
    data.field_i32(2, 0); // PLAIN
    data.field_i32(3, 3); // RLE definition levels (none because field is required)
    data.field_i32(4, 3); // RLE repetition levels (none because field is required)
    data.stop();
    out.field_struct_bytes(5, &data.bytes);
    out.stop();
    out.bytes
}

fn file_metadata(groups: &[RowGroupMeta], total_rows: i64) -> Vec<u8> {
    let mut out = Compact::default();
    out.field_i32(1, 1);
    let schema = vec![
        schema_element(None, "schema", Some(4), 0, false),
        schema_element(Some(6), "event_json", None, 0, true),
        schema_element(Some(2), "class_uid", None, 0, false),
        schema_element(Some(2), "activity_id", None, 0, false),
        schema_element(Some(2), "time", None, 0, false),
    ];
    out.header(2, 9);
    out.list_structs_value(&schema);
    out.field_i64(3, total_rows);
    let row_group_bytes: Vec<Vec<u8>> = groups.iter().map(row_group).collect();
    out.list_structs(4, &row_group_bytes);
    out.field_string(6, "ulpf parquet sink");
    out.stop();
    out.bytes
}

fn schema_element(
    type_id: Option<i32>,
    name: &str,
    num_children: Option<i32>,
    repetition: i32,
    utf8: bool,
) -> Vec<u8> {
    let mut element = Compact::default();
    if let Some(type_id) = type_id {
        element.field_i32(1, type_id);
    }
    element.field_i32(3, repetition);
    element.field_string(4, name);
    if let Some(num_children) = num_children {
        element.field_i32(5, num_children);
    }
    if utf8 {
        element.field_i32(6, 0); // ConvertedType.UTF8
    }
    element.stop();
    element.bytes
}

fn row_group(group: &RowGroupMeta) -> Vec<u8> {
    let mut row_group = Compact::default();
    let chunks: Vec<Vec<u8>> = group.columns.iter().map(column_chunk).collect();
    row_group.list_structs(1, &chunks);
    let total_size: i64 = group.columns.iter().map(|column| column.page_size).sum();
    row_group.field_i64(2, total_size);
    row_group.field_i64(3, group.rows);
    row_group.stop();
    row_group.bytes
}

fn column_chunk(column: &ColumnMeta) -> Vec<u8> {
    let mut metadata = Compact::default();
    metadata.field_i32(1, column.type_id);
    metadata.list_i32(2, &[0]); // PLAIN
    metadata.list_string(3, &[column.path]);
    metadata.field_i32(4, 0); // UNCOMPRESSED
    metadata.field_i64(5, column.rows);
    metadata.field_i64(6, column.page_size);
    metadata.field_i64(7, column.page_size);
    metadata.field_i64(9, column.offset);
    metadata.stop();

    let mut chunk = Compact::default();
    // ColumnChunk: file_offset is field 2 and ColumnMetaData is field 3.
    // Field 1 is the optional file_path and remains absent for an in-file
    // column chunk.
    chunk.field_i64(2, column.offset);
    chunk.field_struct_bytes(3, &metadata.bytes);
    chunk.stop();
    chunk.bytes
}

#[derive(Default)]
struct Compact {
    bytes: Vec<u8>,
    last_field: i16,
}

impl Compact {
    fn header(&mut self, field: i16, ty: u8) {
        let delta = field - self.last_field;
        if (1..=15).contains(&delta) {
            self.bytes.push(((delta as u8) << 4) | ty);
        } else {
            self.bytes.push(ty);
            self.i16(field);
        }
        self.last_field = field;
    }

    fn stop(&mut self) {
        self.bytes.push(0);
    }

    fn field_i32(&mut self, field: i16, value: i32) {
        self.header(field, 5);
        self.varint(zigzag_i32(value));
    }

    fn field_i64(&mut self, field: i16, value: i64) {
        self.header(field, 6);
        self.varint(zigzag_i64(value));
    }

    fn field_string(&mut self, field: i16, value: &str) {
        self.header(field, 8);
        self.binary(value.as_bytes());
    }

    fn field_struct_bytes(&mut self, field: i16, value: &[u8]) {
        self.header(field, 12);
        self.bytes.extend_from_slice(value);
    }

    fn list_structs(&mut self, field: i16, values: &[Vec<u8>]) {
        self.header(field, 9);
        self.list_header(values.len(), 12);
        for value in values {
            self.bytes.extend_from_slice(value);
        }
    }

    fn list_i32(&mut self, field: i16, values: &[i32]) {
        self.header(field, 9);
        self.list_header(values.len(), 5);
        for value in values {
            self.varint(zigzag_i32(*value));
        }
    }

    fn list_string(&mut self, field: i16, values: &[&str]) {
        self.header(field, 9);
        self.list_header(values.len(), 8);
        for value in values {
            self.binary(value.as_bytes());
        }
    }

    fn list_structs_value(&mut self, values: &[Vec<u8>]) {
        self.list_header(values.len(), 12);
        for value in values {
            self.bytes.extend_from_slice(value);
        }
    }

    fn list_header(&mut self, len: usize, ty: u8) {
        if len < 15 {
            self.bytes.push(((len as u8) << 4) | ty);
        } else {
            self.bytes.push(0xf0 | ty);
            self.varint(len as u64);
        }
    }

    fn binary(&mut self, value: &[u8]) {
        self.varint(value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    fn i16(&mut self, value: i16) {
        self.varint(zigzag_i32(value as i32));
    }

    fn varint(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.bytes.push((value as u8) | 0x80);
            value >>= 7;
        }
        self.bytes.push(value as u8);
    }
}

fn zigzag_i32(value: i32) -> u64 {
    ((value as i64) << 1 ^ (value as i64 >> 31)) as u64
}

fn zigzag_i64(value: i64) -> u64 {
    ((value << 1) ^ (value >> 63)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use ulpf_ocsf::types::{Metadata, Product, Severity};

    #[test]
    fn compact_varints_and_page_header_are_nonempty() {
        assert_eq!(zigzag_i32(-1), 1);
        assert_eq!(zigzag_i64(1), 2);
        assert!(!page_header(10, 10, 1).is_empty());
    }

    #[test]
    fn endpoint_parsing_keeps_path_and_rejects_implicit_tls() {
        let endpoint = HttpEndpoint::parse("http://127.0.0.1:9200/logs").unwrap();
        assert_eq!(endpoint.host, "127.0.0.1");
        assert_eq!(endpoint.port, 9200);
        assert_eq!(endpoint.path, "/logs");
        let ipv6 = HttpEndpoint::parse("http://[::1]:8080").unwrap();
        assert_eq!(ipv6.host, "::1");
        assert_eq!(ipv6.port, 8080);
        assert!(HttpEndpoint::parse("https://127.0.0.1:9200").is_err());
        assert!(HttpEndpoint::parse("http://bad host:9200").is_err());
    }

    #[test]
    fn parquet_output_has_magic_and_is_readable_by_parquet_tools() {
        let path = std::env::temp_dir().join(format!("ulpf-test-{}", std::process::id()));
        let mut sink = ParquetSink::create(&path, 250).unwrap();
        let event = ulpf_ocsf::EventBuilder::new()
            .class(4001)
            .activity(1)
            .time(1)
            .severity(Severity::Informational)
            .metadata(Metadata::new("1.9.0", Product::new("ULPF", "ULPF")))
            .build()
            .unwrap();
        sink.write(&event).unwrap();
        sink.finish().unwrap();

        // Find the generated parquet file in the partitioned directory
        let mut found_file = None;
        if let Ok(entries) = std::fs::read_dir(&path) {
            for entry in entries.flatten() {
                if let Ok(nested) = std::fs::read_dir(entry.path()) {
                    for file_entry in nested.flatten() {
                        if file_entry.path().extension().and_then(|s| s.to_str()) == Some("parquet") {
                            found_file = Some(file_entry.path());
                            break;
                        }
                    }
                }
            }
        }
        let parquet_file = found_file.expect("partitioned parquet file should exist");
        
        let bytes = fs::read(&parquet_file).unwrap();
        assert_eq!(&bytes[..4], b"PAR1");
        assert_eq!(&bytes[bytes.len() - 4..], b"PAR1");
        let _ = fs::remove_dir_all(path);
    }
}
