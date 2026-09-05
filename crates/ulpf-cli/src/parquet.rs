//! A small Parquet writer, driven by a column list.
//!
//! Hand-rolled on purpose. Pulling in `arrow` and `parquet` would add well over
//! a hundred transitive crates to a binary whose whole claim is that it builds
//! and runs air-gapped, to emit a file format that is a Thrift footer over
//! plain pages. What is here is the subset that produces a file `pyarrow`,
//! Spark and DuckDB all read: PLAIN encoding, uncompressed pages, every column
//! required.
//!
//! Required-only is a real limitation and a deliberate one. Definition levels
//! are what nullability costs, and a feature table wants dense columns anyway;
//! absence is carried as a documented sentinel instead. If an optional column
//! is ever genuinely needed, this is where the levels would go.

use std::io::{Seek, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnType {
    Int64,
    Utf8,
}

impl ColumnType {
    /// Parquet `Type` enum: 2 is INT64, 6 is BYTE_ARRAY.
    fn type_id(self) -> i32 {
        match self {
            ColumnType::Int64 => 2,
            ColumnType::Utf8 => 6,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ColumnSpec {
    pub name: &'static str,
    pub ty: ColumnType,
}

impl ColumnSpec {
    pub const fn new(name: &'static str, ty: ColumnType) -> Self {
        Self { name, ty }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Text(String),
}

/// Writes one Parquet file per UTC day, partitioned Hive-style.
pub struct ParquetWriter {
    base_dir: PathBuf,
    stem: &'static str,
    columns: &'static [ColumnSpec],
    /// Written into the Parquet footer, so a reader can tell what produced a
    /// file and which contract it follows without a side channel.
    created_by: String,
    batch_size: usize,
    active_partition: Option<String>,
    file: Option<std::fs::File>,
    rows: Vec<Vec<Value>>,
    row_groups: Vec<RowGroupMeta>,
    total_rows: i64,
}

struct RowGroupMeta {
    rows: i64,
    columns: Vec<ColumnMeta>,
}

struct ColumnMeta {
    path: &'static str,
    type_id: i32,
    offset: i64,
    page_size: i64,
    rows: i64,
}

impl ParquetWriter {
    pub fn create(
        dir: &Path,
        stem: &'static str,
        columns: &'static [ColumnSpec],
        created_by: impl Into<String>,
        batch_size: usize,
    ) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating {} for Parquet output", dir.display()))?;
        Ok(Self {
            base_dir: dir.to_path_buf(),
            stem,
            columns,
            created_by: created_by.into(),
            batch_size: batch_size.max(1),
            active_partition: None,
            file: None,
            rows: Vec::new(),
            row_groups: Vec::new(),
            total_rows: 0,
        })
    }

    pub fn push(&mut self, row: Vec<Value>) -> anyhow::Result<()> {
        if row.len() != self.columns.len() {
            anyhow::bail!(
                "row has {} values but the schema declares {} columns",
                row.len(),
                self.columns.len()
            );
        }
        // A value of the wrong kind would encode as the wrong Parquet type and
        // produce a file that only fails when something tries to read it.
        for (spec, value) in self.columns.iter().zip(&row) {
            match (spec.ty, value) {
                (ColumnType::Int64, Value::Int(_)) | (ColumnType::Utf8, Value::Text(_)) => {}
                _ => anyhow::bail!("column {} was given a value of the wrong type", spec.name),
            }
        }

        self.open_partition()?;
        self.rows.push(row);
        if self.rows.len() >= self.batch_size {
            self.flush()?;
        }
        Ok(())
    }

    /// Start a new file when the UTC day rolls over, so a reader can prune by
    /// partition without opening anything.
    fn open_partition(&mut self) -> anyhow::Result<()> {
        let today = chrono::Utc::now().format("dt=%Y-%m-%d").to_string();
        if self.active_partition.as_deref() == Some(today.as_str()) && self.file.is_some() {
            return Ok(());
        }
        if self.file.is_some() {
            self.finish_file()?;
        }

        let dir = self.base_dir.join(&today);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("creating partition {}", dir.display()))?;
        let path = dir.join(format!("{}-{}.parquet", self.stem, uuid::Uuid::now_v7()));
        let mut file =
            std::fs::File::create(&path).with_context(|| format!("creating {}", path.display()))?;
        file.write_all(b"PAR1")?;

        self.file = Some(file);
        self.active_partition = Some(today);
        self.row_groups.clear();
        self.total_rows = 0;
        Ok(())
    }

    pub fn flush(&mut self) -> anyhow::Result<()> {
        if self.rows.is_empty() || self.file.is_none() {
            return Ok(());
        }
        let rows = self.rows.len() as i64;
        let mut metas = Vec::with_capacity(self.columns.len());

        // One page per column, holding this batch. Buffering the whole page
        // before writing keeps its byte length known, which the footer needs.
        for (index, spec) in self.columns.iter().enumerate() {
            let mut body = Vec::new();
            for row in &self.rows {
                match &row[index] {
                    Value::Int(v) => body.extend_from_slice(&v.to_le_bytes()),
                    Value::Text(v) => {
                        body.extend_from_slice(&(v.len() as u32).to_le_bytes());
                        body.extend_from_slice(v.as_bytes());
                    }
                }
            }

            let file = self.file.as_mut().expect("partition is open");
            let header = page_header(body.len() as i32, body.len() as i32, rows as i32);
            let offset = file.stream_position()? as i64;
            file.write_all(&header)?;
            file.write_all(&body)?;
            metas.push(ColumnMeta {
                path: spec.name,
                type_id: spec.ty.type_id(),
                offset,
                page_size: (header.len() + body.len()) as i64,
                rows,
            });
        }

        self.total_rows += rows;
        self.row_groups.push(RowGroupMeta {
            rows,
            columns: metas,
        });
        self.rows.clear();
        Ok(())
    }

    fn finish_file(&mut self) -> anyhow::Result<()> {
        self.flush()?;
        if let Some(file) = self.file.as_mut() {
            let footer = file_metadata(
                self.columns,
                &self.row_groups,
                self.total_rows,
                &self.created_by,
            );
            file.write_all(&footer)?;
            file.write_all(&(footer.len() as u32).to_le_bytes())?;
            file.write_all(b"PAR1")?;
            file.flush()?;
        }
        self.file = None;
        self.row_groups.clear();
        self.total_rows = 0;
        Ok(())
    }

    pub fn finish(mut self) -> anyhow::Result<()> {
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
    data.field_i32(3, 3); // RLE definition levels, unused: every field required
    data.field_i32(4, 3); // RLE repetition levels, likewise
    data.stop();
    out.field_struct_bytes(5, &data.bytes);
    out.stop();
    out.bytes
}

fn file_metadata(
    columns: &[ColumnSpec],
    groups: &[RowGroupMeta],
    total_rows: i64,
    created_by: &str,
) -> Vec<u8> {
    let mut out = Compact::default();
    out.field_i32(1, 1); // format version

    let mut schema = vec![schema_element(
        None,
        "schema",
        Some(columns.len() as i32),
        0,
        false,
    )];
    for spec in columns {
        schema.push(schema_element(
            Some(spec.ty.type_id()),
            spec.name,
            None,
            0, // REQUIRED
            spec.ty == ColumnType::Utf8,
        ));
    }

    out.header(2, 9);
    out.list_structs_value(&schema);
    out.field_i64(3, total_rows);
    let row_group_bytes: Vec<Vec<u8>> = groups.iter().map(row_group).collect();
    out.list_structs(4, &row_group_bytes);
    out.field_string(6, created_by);
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
    // ColumnChunk: file_offset is field 2, ColumnMetaData field 3. Field 1 is
    // the optional file_path and stays absent for an in-file chunk.
    chunk.field_i64(2, column.offset);
    chunk.field_struct_bytes(3, &metadata.bytes);
    chunk.stop();
    chunk.bytes
}

/// Thrift compact protocol, only the pieces the Parquet footer uses.
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

    const COLS: &[ColumnSpec] = &[
        ColumnSpec::new("n", ColumnType::Int64),
        ColumnSpec::new("s", ColumnType::Utf8),
    ];

    #[test]
    fn zigzag_matches_the_thrift_definition() {
        assert_eq!(zigzag_i32(0), 0);
        assert_eq!(zigzag_i32(-1), 1);
        assert_eq!(zigzag_i32(1), 2);
        assert_eq!(zigzag_i64(1), 2);
        assert_eq!(zigzag_i64(-1), 1);
    }

    #[test]
    fn a_row_of_the_wrong_width_is_refused() {
        let dir = tempdir();
        let mut w = ParquetWriter::create(&dir, "t", COLS, "test", 8).unwrap();
        assert!(w.push(vec![Value::Int(1)]).is_err());
    }

    #[test]
    fn a_value_of_the_wrong_type_is_refused() {
        let dir = tempdir();
        let mut w = ParquetWriter::create(&dir, "t", COLS, "test", 8).unwrap();
        let err = w
            .push(vec![Value::Text("no".into()), Value::Text("yes".into())])
            .unwrap_err();
        assert!(err.to_string().contains("wrong type"), "{err}");
    }

    #[test]
    fn writing_produces_a_file_with_the_parquet_magic_at_both_ends() {
        let dir = tempdir();
        let mut w = ParquetWriter::create(&dir, "t", COLS, "test", 2).unwrap();
        for i in 0..5 {
            w.push(vec![Value::Int(i), Value::Text(format!("row-{i}"))])
                .unwrap();
        }
        w.finish().unwrap();

        let file = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .flat_map(|entry| std::fs::read_dir(entry.path()).unwrap())
            .filter_map(Result::ok)
            .next()
            .expect("a partition file was written");
        let bytes = std::fs::read(file.path()).unwrap();
        assert!(bytes.starts_with(b"PAR1"), "missing leading magic");
        assert!(bytes.ends_with(b"PAR1"), "missing trailing magic");
        assert!(bytes.len() > 8);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ulpf-parquet-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
