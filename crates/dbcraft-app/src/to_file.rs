//! "Execute to file": streams a query's rows straight into a file, for
//! results too large for the grid. On Oracle a task on the session reads
//! them; on the other databases the window fetches the result batch by
//! batch, as for the grid but with binary values whole (#204), and hands
//! each to a [`Sink`].

use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use dbcraft_data::{Format, Options, StreamWriter};
use dbcraft_db::oracle::Connection;
use dbcraft_db::{Cell, Column, DbError, Dialect};

/// Rows fetched per round trip and written per batch.
pub const BATCH: usize = 1000;

/// A running export, polled by the window for progress.
pub struct ToFile {
    pub id: u64,
    pub path: PathBuf,
    pub sql: String,
    pub rows: Arc<AtomicU64>,
    pub started: Instant,
}

/// Writes a query's rows into a file as they come: its columns first, then
/// batches of rows. They go into `<name>.part`, which becomes the file once
/// it is finished; dropped before, the sink removes it, and a DbCraft that
/// was killed leaves no file that looks whole.
pub struct Sink {
    path: PathBuf,
    part: PathBuf,
    format: Format,
    options: Options,
    out: Option<BufWriter<File>>,
    writer: Option<StreamWriter<BufWriter<File>>>,
    progress: Arc<AtomicU64>,
    done: bool,
}

impl Sink {
    /// Creates the file for the rows of `sql`; INSERT statements go into
    /// the table a one-table query reads (#158), in `dialect`'s SQL, and set
    /// the session's `time_zone` on MySQL (#213). `progress` counts the
    /// rows written.
    pub fn create(
        path: &Path,
        sql: &str,
        dialect: Dialect,
        time_zone: Option<String>,
        progress: Arc<AtomicU64>,
    ) -> Result<Self, DbError> {
        let format = format_for(path)?;
        let defaults = Options::default();
        let options = Options {
            table: crate::data_edit::single_table(dialect, sql).unwrap_or(defaults.table.clone()),
            dialect,
            time_zone,
            ..defaults
        };
        Self::new(path, format, options, progress)
    }

    /// Creates the file at `path` for rows written as `format` with
    /// `options` (*Export tables*).
    pub fn new(
        path: &Path,
        format: Format,
        options: Options,
        progress: Arc<AtomicU64>,
    ) -> Result<Self, DbError> {
        let part = part_path(path);
        let file =
            File::create(&part).map_err(|e| DbError::new(format!("{}: {e}", part.display())))?;
        Ok(Self {
            path: path.to_owned(),
            part,
            format,
            options,
            out: Some(BufWriter::with_capacity(1 << 20, file)),
            writer: None,
            progress,
            done: false,
        })
    }

    fn io(&self, e: dbcraft_data::Error) -> DbError {
        DbError::new(format!("{}: {e}", self.path.display()))
    }

    /// The result's columns: writes the header.
    pub fn columns(&mut self, columns: &[Column]) -> Result<(), DbError> {
        if let Some(out) = self.out.take() {
            let writer =
                StreamWriter::new(self.format, columns.to_vec(), self.options.clone(), out)
                    .map_err(|e| self.io(e))?;
            self.writer = Some(writer);
        }
        Ok(())
    }

    /// The columns' types changed, for the rows that come next (#482).
    pub fn retype(&mut self, columns: &[Column]) {
        if let Some(writer) = self.writer.as_mut() {
            writer.retype(columns.to_vec());
        }
    }

    /// Writes rows; returns how many were written so far.
    pub fn rows(&mut self, rows: &[Vec<Cell>]) -> Result<u64, DbError> {
        let Some(writer) = self.writer.as_mut() else {
            return Err(DbError::new("Rows before the columns"));
        };
        let written = writer.write(rows).map(|()| writer.rows());
        let written = written.map_err(|e| self.io(e))?;
        self.progress.store(written, Ordering::Relaxed);
        Ok(written)
    }

    /// Completes the file (a JSON array's end) and gives it its name.
    pub fn finish(mut self) -> Result<(), DbError> {
        if let Some(writer) = self.writer.take() {
            writer.finish().map_err(|e| self.io(e))?;
        }
        self.out = None;
        std::fs::rename(&self.part, &self.path)
            .map_err(|e| DbError::new(format!("{}: {e}", self.path.display())))?;
        self.done = true;
        Ok(())
    }

    /// Gives up: the incomplete file is removed.
    pub fn abandon(self) {}
}

impl Drop for Sink {
    fn drop(&mut self) {
        if !self.done {
            self.writer = None;
            self.out = None;
            let _ = std::fs::remove_file(&self.part);
        }
    }
}

impl dbcraft_db::RowSink for Sink {
    fn columns(&mut self, columns: &[Column]) -> Result<(), DbError> {
        Sink::columns(self, columns)
    }

    fn retype(&mut self, columns: &[Column]) {
        Sink::retype(self, columns)
    }

    fn rows(&mut self, rows: &[Vec<Cell>]) -> Result<u64, DbError> {
        Sink::rows(self, rows)
    }

    fn finish(self: Box<Self>) -> Result<(), DbError> {
        Sink::finish(*self)
    }
}

/// Where the rows for `path` go until they are all written.
pub fn part_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(".part");
    path.with_file_name(name)
}

/// The format for a file name; CSV when the extension is none of the
/// formats. Excel and HTML can't be written as rows come: a `.xlsx` given
/// CSV would be a file Excel calls broken.
pub fn format_for(path: &Path) -> Result<Format, DbError> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if let Some(format) = Format::STREAMING.iter().find(|f| f.extension() == ext) {
        return Ok(*format);
    }
    match Format::ALL.iter().find(|f| f.extension() == ext) {
        Some(format) => Err(DbError::new(format!(
            "{} can't be written as the rows come; choose {}, or export the grid's rows",
            format.label(),
            Format::STREAMING
                .iter()
                .map(|f| format!(".{}", f.extension()))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
        None => Ok(Format::Csv),
    }
}

/// Runs `sql` and writes every row to `path`; removes the file on failure
/// (including cancellation). Returns the number of rows written.
pub fn run(
    conn: &Connection,
    sql: &str,
    path: &Path,
    progress: Arc<AtomicU64>,
) -> Result<u64, DbError> {
    let mut sink = Sink::create(path, sql, Dialect::ORACLE, None, progress)?;
    let mut started = false;
    let streamed = dbcraft_db::stream_query(conn, sql, BATCH, |columns, rows| {
        if !started {
            sink.columns(columns)?;
            started = true;
        }
        sink.rows(rows)?;
        Ok(())
    });
    match streamed {
        Ok(count) => sink.finish().map(|()| count),
        Err(e) => {
            sink.abandon();
            Err(e)
        }
    }
}

/// Asks for the target file on a background thread (the dialog blocks).
pub fn pick_file() -> std::sync::mpsc::Receiver<Option<PathBuf>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut dialog = rfd::FileDialog::new().set_file_name("result.csv");
        for format in Format::STREAMING {
            dialog = dialog.add_filter(format.label(), &[format.extension()]);
        }
        let _ = tx.send(dialog.save_file());
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_format_from_extension() {
        let format = |name: &str| format_for(Path::new(name)).ok();
        assert_eq!(format("a.json"), Some(Format::Json));
        assert_eq!(format("a.SQL"), Some(Format::Insert));
        assert_eq!(format("a.txt"), Some(Format::Csv));
        // Not CSV under a name Excel opens as its own (it calls it broken).
        assert_eq!(format("a.xlsx"), None);
        assert_eq!(format("a.HTML"), None);
    }

    /// The rows as the window hands them over, batch by batch, in another
    /// database's SQL; a sink given up leaves no file.
    #[test]
    fn sink_writes_batches() {
        let path = std::env::temp_dir().join(format!("dbcraft-sink-{}.sql", std::process::id()));
        let columns = vec![
            Column {
                name: "id".into(),
                type_name: "INTEGER".into(),
                numeric: true,
            },
            Column {
                name: "note".into(),
                type_name: "TEXT".into(),
                numeric: false,
            },
        ];
        let mut sink = Sink::create(
            &path,
            "select id, note from notes",
            Dialect::SQLITE,
            None,
            Default::default(),
        )
        .unwrap();
        sink.columns(&columns).unwrap();
        assert_eq!(
            sink.rows(&[vec![Some("1".into()), Some("it's".into())]])
                .unwrap(),
            1
        );
        assert_eq!(sink.rows(&[vec![Some("2".into()), None]]).unwrap(), 2);
        sink.finish().unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text.lines().collect::<Vec<_>>(),
            [
                "insert into notes (id, note) values (1, 'it''s');",
                "insert into notes (id, note) values (2, NULL);"
            ]
        );
        std::fs::remove_file(&path).unwrap();

        // Until it is finished, the rows go into a file of another name,
        // removed when given up or dropped.
        let part = part_path(&path);
        let sink =
            Sink::create(&path, "select 1", Dialect::SQLITE, None, Default::default()).unwrap();
        assert!(part.exists() && !path.exists());
        sink.abandon();
        assert!(!part.exists() && !path.exists());
        let mut sink =
            Sink::create(&path, "select 1", Dialect::SQLITE, None, Default::default()).unwrap();
        sink.columns(&columns).unwrap();
        sink.rows(&[vec![Some("1".into()), None]]).unwrap();
        drop(sink);
        assert!(!part.exists() && !path.exists());
    }

    #[test]
    fn writes_query_to_file() {
        let Ok(spec) = std::env::var("DBCRAFT_TEST_DB") else {
            return;
        };
        let (cred, db) = spec.rsplit_once('@').unwrap();
        let (user, pw) = cred.split_once('/').unwrap();
        let conn = Connection::connect(user, pw, db).unwrap();
        let path = std::env::temp_dir().join(format!("dbcraft-to-file-{}.csv", std::process::id()));
        let progress = Arc::new(AtomicU64::new(0));
        let n = run(
            &conn,
            "select level as n, 'row ' || level as label from dual connect by level <= 2500",
            &path,
            progress.clone(),
        )
        .unwrap();
        assert_eq!(n, 2500);
        assert_eq!(progress.load(Ordering::Relaxed), 2500);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 2501);
        assert!(text.starts_with("N,LABEL\n1,row 1\n"));
        std::fs::remove_file(&path).unwrap();

        // INSERTs go into the table the query reads (#158).
        let sql_path = path.with_extension("sql");
        run(&conn, "select * from dual", &sql_path, progress.clone()).unwrap();
        let text = std::fs::read_to_string(&sql_path).unwrap();
        std::fs::remove_file(&sql_path).unwrap();
        assert!(
            text.starts_with("insert into dual (dummy) values ('X');"),
            "{text}"
        );

        // A `&` in a value comes back as it was, and the statement asks
        // for no substitution variable when it runs (#159).
        run(
            &conn,
            "select 'Missing (H&L) && &x.' as name from dual",
            &sql_path,
            progress.clone(),
        )
        .unwrap();
        let text = std::fs::read_to_string(&sql_path).unwrap();
        std::fs::remove_file(&sql_path).unwrap();
        assert!(
            crate::sql_window::find_substitutions(&text, dbcraft_plsql::Syntax::Oracle).is_empty(),
            "{text}"
        );
        let value = text
            .split_once("values (")
            .and_then(|(_, rest)| rest.trim_end().strip_suffix(");"))
            .unwrap();
        let back: String = conn
            .query_row_as(&format!("select {value} from dual"), &[])
            .unwrap();
        assert_eq!(back, "Missing (H&L) && &x.");

        // A failing query leaves no file behind.
        assert!(
            run(
                &conn,
                "select * from no_such_table_xyz",
                &path,
                progress.clone()
            )
            .is_err()
        );
        assert!(!path.exists());
    }

    /// The INSERTs of BLOBs over the 2000 bytes a `hextoraw` takes (#314),
    /// run back into a copy of their table, are the same values; they
    /// failed with ORA-01704.
    #[test]
    fn writes_long_binary_values() {
        let Some(conn) = crate::test_db::connect("DBCRAFT_TEST_DB") else {
            return;
        };
        for table in ["r65_lv", "r65_lv_copy"] {
            let _ = conn.execute(&format!("drop table {table} purge"), &[]);
            conn.execute(
                &format!("create table {table} (id number primary key, b blob)"),
                &[],
            )
            .unwrap();
        }
        conn.execute(
            "declare
               v blob;
               w blob;
             begin
               dbms_lob.createtemporary(v, true);
               for i in 1 .. 50 loop
                 dbms_lob.writeappend(v, 2000,
                   utl_raw.copies(utl_raw.cast_from_binary_integer(i), 500));
               end loop;
               insert into r65_lv values (1, v);
               insert into r65_lv values (2, empty_blob()) returning b into w;
               dbms_lob.copy(w, v, 3000);
               insert into r65_lv values (3, hextoraw('CAFE'));
               insert into r65_lv values (4, null);
             end;",
            &[],
        )
        .unwrap();
        let path =
            std::env::temp_dir().join(format!("dbcraft-long-binary-{}.sql", std::process::id()));
        let progress = Arc::new(AtomicU64::new(0));
        let n = run(
            &conn,
            "select * from r65_lv order by id",
            &path,
            progress.clone(),
        )
        .unwrap();
        assert_eq!(n, 4);
        let script = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let statements = dbcraft_plsql::split_statements(&script);
        assert_eq!(statements.len(), 4, "{script}");
        for statement in statements {
            let sql = statement.text(&script).replacen(
                "insert into r65_lv ",
                "insert into r65_lv_copy ",
                1,
            );
            conn.execute(&sql, &[])
                .unwrap_or_else(|e| panic!("{e}\n{sql}"));
        }
        let same: i64 = conn
            .query_row_as(
                "select count(*) from r65_lv a join r65_lv_copy c on c.id = a.id \
                  where dbms_lob.compare(a.b, c.b) = 0 or (a.b is null and c.b is null)",
                &[],
            )
            .unwrap();
        assert_eq!(same, 4);
        for table in ["r65_lv", "r65_lv_copy"] {
            conn.execute(&format!("drop table {table} purge"), &[])
                .unwrap();
        }
    }

    /// The INSERTs of CLOBs and NCLOBs over the 4000 bytes a literal
    /// holds (#317), with quotes, `&`, two-byte characters and pairs of
    /// surrogates, run back into a copy of their table, are the same
    /// values; they failed with ORA-01704.
    #[test]
    fn writes_long_text_values() {
        let Some(conn) = crate::test_db::connect("DBCRAFT_TEST_DB") else {
            return;
        };
        for table in ["r65_lt", "r65_lt_copy"] {
            let _ = conn.execute(&format!("drop table {table} purge"), &[]);
            conn.execute(
                &format!("create table {table} (id number primary key, c clob, n nclob)"),
                &[],
            )
            .unwrap();
        }
        conn.execute(
            "declare
               v clob;
             begin
               dbms_lob.createtemporary(v, true);
               for i in 1 .. 1000 loop
                 dbms_lob.writeappend(v, 11, 'it''s & \u{e9} \u{1F600}');
               end loop;
               insert into r65_lt values (1, v, v);
               insert into r65_lt values (2, rpad('x', 3000, 'x'), null);
               insert into r65_lt values (3, null, null);
             end;",
            &[],
        )
        .unwrap();
        let path =
            std::env::temp_dir().join(format!("dbcraft-long-text-{}.sql", std::process::id()));
        let progress = Arc::new(AtomicU64::new(0));
        let n = run(
            &conn,
            "select * from r65_lt order by id",
            &path,
            progress.clone(),
        )
        .unwrap();
        assert_eq!(n, 3);
        let script = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let statements = dbcraft_plsql::split_statements(&script);
        assert_eq!(statements.len(), 3, "{script}");
        for statement in statements {
            let sql = statement.text(&script).replacen(
                "insert into r65_lt ",
                "insert into r65_lt_copy ",
                1,
            );
            conn.execute(&sql, &[])
                .unwrap_or_else(|e| panic!("{e}\n{sql}"));
        }
        let same: i64 = conn
            .query_row_as(
                "select count(*) from r65_lt a join r65_lt_copy c on c.id = a.id \
                  where (dbms_lob.compare(a.c, c.c) = 0 or (a.c is null and c.c is null)) \
                    and (dbms_lob.compare(a.n, c.n) = 0 or (a.n is null and c.n is null))",
                &[],
            )
            .unwrap();
        assert_eq!(same, 3);
        let length: i64 = conn
            .query_row_as(
                "select dbms_lob.getlength(n) from r65_lt_copy where id = 1",
                &[],
            )
            .unwrap();
        assert_eq!(length, 11000);
        for table in ["r65_lt", "r65_lt_copy"] {
            conn.execute(&format!("drop table {table} purge"), &[])
                .unwrap();
        }
    }

    /// The rows of `sql` written to a file as INSERTs and run back into
    /// `copy` instead of `table`: how many statements there were.
    fn insert_into_copy(conn: &Connection, sql: &str, table: &str, copy: &str) -> usize {
        let path = std::env::temp_dir().join(format!("dbcraft-{copy}-{}.sql", std::process::id()));
        run(conn, sql, &path, Default::default()).unwrap();
        let script = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let statements = dbcraft_plsql::split_statements(&script);
        for statement in &statements {
            let sql = statement.text(&script).replacen(
                &format!("insert into {table} "),
                &format!("insert into {copy} "),
                1,
            );
            conn.execute(&sql, &[])
                .unwrap_or_else(|e| panic!("{e}\n{sql}"));
        }
        statements.len()
    }

    /// The rows of `sql` as the session shows them.
    fn texts(conn: &Connection, sql: &str) -> Vec<Vec<Cell>> {
        let mut rows = Vec::new();
        dbcraft_db::stream_query(conn, sql, 100, |_, batch| {
            rows.extend_from_slice(batch);
            Ok(())
        })
        .unwrap_or_else(|e| panic!("{e}\n{sql}"));
        rows
    }

    /// The INSERTs of BINARY_DOUBLE and BINARY_FLOAT values beyond
    /// NUMBER's range, the infinities and NaN (#339), run back into a copy
    /// of their table, are the same values: 1e300 failed with ORA-01426,
    /// -2e-300 was written as 0.
    #[test]
    fn writes_binary_floats() {
        let Some(conn) = crate::test_db::connect("DBCRAFT_TEST_DB") else {
            return;
        };
        for table in ["r76_bf", "r76_bf_copy"] {
            let _ = conn.execute(&format!("drop table {table} purge"), &[]);
            conn.execute(
                &format!(
                    "create table {table} (id number primary key, d binary_double, f binary_float)"
                ),
                &[],
            )
            .unwrap();
        }
        for values in [
            "1, 1e300d, 3.4028235e38f",
            "2, -2e-300d, 1e-40f",
            "3, binary_double_infinity, binary_float_infinity",
            "4, -binary_double_infinity, -binary_float_infinity",
            "5, binary_double_nan, binary_float_nan",
            "6, 0.1d, 0.1f",
            "7, null, null",
        ] {
            conn.execute(&format!("insert into r76_bf values ({values})"), &[])
                .unwrap();
        }
        let n = insert_into_copy(
            &conn,
            "select * from r76_bf order by id",
            "r76_bf",
            "r76_bf_copy",
        );
        assert_eq!(n, 7);
        let rows = texts(&conn, "select * from r76_bf order by id");
        assert_eq!(rows[0][1].as_deref(), Some("1e300"));
        assert_eq!(texts(&conn, "select * from r76_bf_copy order by id"), rows);
        for table in ["r76_bf", "r76_bf_copy"] {
            conn.execute(&format!("drop table {table} purge"), &[])
                .unwrap();
        }
    }

    /// `n` random finite, normal doubles and reals of any size (xorshift:
    /// the same each run), as Rust writes them shortest, with an exponent.
    fn random_floats(n: usize) -> Vec<(String, String)> {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut values = Vec::new();
        while values.len() < n {
            let (d, r) = (f64::from_bits(next()), f32::from_bits(next() as u32));
            if d.is_normal() && r.is_normal() {
                values.push((format!("{d:e}"), format!("{r:e}")));
            }
        }
        values
    }

    /// The INSERTs of VECTORs (#341), run back into a copy of their table,
    /// are the same vectors: FLOAT32 and FLOAT64 elements of any size and
    /// sparse vectors, which were written as `SparseVector {…}`
    /// (ORA-51804).
    #[test]
    fn writes_vectors() {
        let Some(conn) = crate::test_db::connect("DBCRAFT_TEST_DB") else {
            return;
        };
        for table in ["r76_vec", "r76_vec_copy"] {
            let _ = conn.execute(&format!("drop table {table} purge"), &[]);
            conn.execute(
                &format!(
                    "create table {table} (id number primary key, f vector(6, float32), \
                       d vector(6, float64), s vector(6, float64, sparse), \
                       i vector(2, int8), b vector(16, binary))"
                ),
                &[],
            )
            .unwrap();
        }
        let floats = random_floats(6 * 20);
        for (id, row) in floats.chunks(6).enumerate() {
            let (d, f): (Vec<String>, Vec<String>) = row.iter().cloned().unzip();
            conn.execute(
                &format!(
                    "insert into r76_vec values ({id}, '[{}]', '[{}]', '[6,[0,5],[{},{}]]', \
                       '[-128,127]', '[255,1]')",
                    f.join(","),
                    d.join(","),
                    d[0],
                    d[1]
                ),
                &[],
            )
            .unwrap();
        }
        conn.execute(
            "insert into r76_vec values (100, '[1e30,1e-30,0.1,100,-1.5,3.4028235e38]', \
               '[1e300,-1e-300,0.1,100,-1.5,1.7976931348623157e308]', '[6,[2],[1e-300]]', \
               null, null)",
            &[],
        )
        .unwrap();
        let n = insert_into_copy(
            &conn,
            "select * from r76_vec order by id",
            "r76_vec",
            "r76_vec_copy",
        );
        assert_eq!(n, 21);
        let mut rows = texts(&conn, "select * from r76_vec order by id");
        let mut copy = texts(&conn, "select * from r76_vec_copy order by id");
        // Oracle reads the text of a dense FLOAT64 vector a unit in the
        // last place off for about half of all doubles, its own text
        // too: those elements are only as close as that.
        let elements = |row: &mut Vec<Cell>| -> Vec<f64> {
            let text = row[2].take().unwrap();
            let list = text.trim_start_matches('[').trim_end_matches(']');
            list.split(',').map(|x| x.parse().unwrap()).collect()
        };
        for (row, copied) in rows.iter_mut().zip(&mut copy) {
            for (a, b) in elements(row).into_iter().zip(elements(copied)) {
                assert!((a - b).abs() <= a.abs() * 1e-15, "{a} {b}");
            }
        }
        assert_eq!(copy, rows);
        for table in ["r76_vec", "r76_vec_copy"] {
            conn.execute(&format!("drop table {table} purge"), &[])
                .unwrap();
        }
    }

    /// The INSERTs of a JSON and a VECTOR over the 4000 bytes a literal
    /// holds (#342), run back into a copy of their table, are the same
    /// values; they failed with ORA-01704.
    #[test]
    fn writes_long_json_and_vectors() {
        let Some(conn) = crate::test_db::connect("DBCRAFT_TEST_DB") else {
            return;
        };
        for table in ["r76_lj", "r76_lj_copy"] {
            let _ = conn.execute(&format!("drop table {table} purge"), &[]);
            conn.execute(
                &format!(
                    "create table {table} (id number primary key, j json, v vector(*, float32))"
                ),
                &[],
            )
            .unwrap();
        }
        for sql in [
            "insert into r76_lj (id, j, v) \
               select 1, json_arrayagg(json_object('k' value level, 's' value 'it''s & \u{e9}') \
                        returning json), \
                      to_vector(json_arrayagg(level / 7 returning clob), *, float32) \
                 from dual connect by level <= 1000",
            "insert into r76_lj values (2, '{\"a\":[1,2]}', '[1,2]')",
        ] {
            conn.execute(sql, &[]).unwrap();
        }
        let rows = texts(&conn, "select * from r76_lj order by id");
        assert!(rows[0][1].as_ref().unwrap().len() > 8000);
        assert!(rows[0][2].as_ref().unwrap().len() > 4000);
        let n = insert_into_copy(
            &conn,
            "select * from r76_lj order by id",
            "r76_lj",
            "r76_lj_copy",
        );
        assert_eq!(n, 2);
        assert_eq!(texts(&conn, "select * from r76_lj_copy order by id"), rows);
        for table in ["r76_lj", "r76_lj_copy"] {
            conn.execute(&format!("drop table {table} purge"), &[])
                .unwrap();
        }
    }

    /// The INSERTs of a JSON's dates, timestamps, intervals, binary values
    /// and binary numbers (#370), also in a JSON over 4000 bytes, run back
    /// into a copy of their table, are the same scalars; they were strings
    /// and NUMBERs, and NaN the string "Nan". An object MongoDB writes so,
    /// `{"$oid":…}`, stays an object.
    #[test]
    fn writes_json_extended_scalars() {
        let Some(conn) = crate::test_db::connect("DBCRAFT_TEST_DB") else {
            return;
        };
        for table in ["r84_jx", "r84_jx_copy"] {
            let _ = conn.execute(&format!("drop table {table} purge"), &[]);
            conn.execute(
                &format!("create table {table} (id number primary key, j json)"),
                &[],
            )
            .unwrap();
        }
        for sql in [
            "insert into r84_jx values (1, json{'a': date '2020-01-01', 'b': 1.5d, 'c': 2.5f, \
             'd': hextoraw('ABCD'), 'e': interval '-1 02:03:04.5' day to second, \
             'f': interval '1-2' year to month, 'n': binary_double_nan, \
             't': timestamp '2020-01-01 10:00:00.123456789', \
             'z': to_timestamp_tz('2020-01-01 10:00:00 -05:30', 'YYYY-MM-DD HH24:MI:SS TZH:TZM'), \
             'm': json('{\"$oid\":\"5f1b2c3d4e5f6a7b8c9d0e1f\",\"&\":1}'), \
             'o': json('{\"$oid\":\"5f1b2c3d4e5f6a7b8c9d0e1f\"}')})",
            "insert into r84_jx values (2, json_scalar(1e300d))",
            "insert into r84_jx (id, j) \
               select 3, json_arrayagg(json_object('d' value date '2020-01-01' + level, \
                        'k&' value level returning json) returning json) \
                 from dual connect by level <= 300",
        ] {
            conn.execute(sql, &[])
                .unwrap_or_else(|e| panic!("{e}\n{sql}"));
        }
        let rows = texts(&conn, "select * from r84_jx order by id");
        assert!(rows[2][1].as_ref().unwrap().len() > 8000);
        let n = insert_into_copy(
            &conn,
            "select * from r84_jx order by id",
            "r84_jx",
            "r84_jx_copy",
        );
        assert_eq!(n, 3);
        let stored = |table: &str| {
            texts(
                &conn,
                &format!(
                    "select id, json_serialize(j returning clob extended) from {table} order by id"
                ),
            )
        };
        let copied = stored("r84_jx_copy");
        assert_eq!(copied, stored("r84_jx"));
        assert!(
            copied[0][1]
                .as_deref()
                .unwrap()
                .contains(r#""o":{"$oid":"5f1b2c3d4e5f6a7b8c9d0e1f"}"#),
            "{copied:?}"
        );
        assert_eq!(texts(&conn, "select * from r84_jx_copy order by id"), rows);
        for table in ["r84_jx", "r84_jx_copy"] {
            conn.execute(&format!("drop table {table} purge"), &[])
                .unwrap();
        }
    }
}
