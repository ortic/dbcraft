//! Export tables: several tables at once, each with an optional WHERE
//! clause, one file per table (optionally with its DDL), streamed so table
//! size doesn't matter. Oracle's tables are read by a task on the session;
//! MySQL's and MariaDB's stream from the session itself ([`mysql`]).

mod mysql;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};

use dbcraft_data::{Format, Options, StreamWriter};
use dbcraft_db::oracle::Connection;
use dbcraft_db::{DbError, DbEvent, DbRequest, Dialect, ObjectType};
use egui::{RichText, Ui};
use serde::{Deserialize, Serialize};

use crate::documents::{DocContext, Effects, Target, quote_ident, request_id};

#[derive(Serialize, Deserialize)]
pub struct ExportTables {
    /// Schema to export from (empty: the current schema).
    pub owner: String,
    #[serde(default, with = "crate::serde_path::option")]
    pub folder: Option<PathBuf>,
    #[serde(with = "format_name")]
    pub format: Format,
    pub header: bool,
    pub delimiter: u8,
    pub null_text: String,
    pub include_ddl: bool,
    #[serde(default)]
    pub read: Read,
    #[serde(skip)]
    state: State,
}

/// How the tables are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Read {
    /// A large table in ROWID ranges, each a short query of its own: each
    /// needs undo for its own minutes only, and one that hits ORA-01555
    /// (snapshot too old) is read again. Each range reads its own moment.
    #[default]
    Chunks,
    /// All tables at one moment, in a read-only transaction: as the
    /// database was when the export began. The undo has to reach back to
    /// then until the last table is read.
    Consistent,
}

/// Formats are stored by extension.
mod format_name {
    use dbcraft_data::Format;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(f: &Format, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(f.extension())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Format, D::Error> {
        let ext = String::deserialize(d)?;
        Ok(Format::STREAMING
            .iter()
            .copied()
            .find(|f| f.extension() == ext)
            .unwrap_or(Format::Csv))
    }
}

impl Default for ExportTables {
    fn default() -> Self {
        Self {
            owner: String::new(),
            folder: None,
            format: Format::Csv,
            header: true,
            delimiter: b',',
            null_text: String::new(),
            include_ddl: false,
            read: Read::default(),
            state: State::default(),
        }
    }
}

#[derive(Default)]
struct State {
    /// The connection's database, as the window last drew (Oracle until it
    /// did).
    dialect: Option<Dialect>,
    /// The MySQL session's time zone, which INSERT scripts set (#213).
    time_zone: Option<String>,
    tables: Option<Result<Vec<Choice>, String>>,
    tables_request: Option<u64>,
    filter: String,
    picking: Option<Receiver<Option<PathBuf>>>,
    run: Option<Run>,
    message: Option<(bool, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct Choice {
    pub name: String,
    pub rows: Option<i64>,
    pub selected: bool,
    pub filter: String,
}

struct Run {
    /// The request running: the task, or on MySQL the table being read.
    id: u64,
    progress: Arc<Progress>,
    mysql: Option<MySqlRun>,
}

/// An export on MySQL: the tables' columns first, then one table after the
/// other.
struct MySqlRun {
    settings: Settings,
    jobs: Vec<Job>,
    prepared: Option<mysql::Prepared>,
    /// The table being read.
    next: usize,
}

#[derive(Default)]
pub struct Progress {
    pub tables_done: AtomicUsize,
    pub tables: AtomicUsize,
    pub rows: AtomicU64,
    pub current: Mutex<String>,
    pub stop: AtomicBool,
    /// The rows of the table being written, on MySQL; `rows` has the
    /// tables' before it.
    pub current_rows: Arc<AtomicU64>,
}

/// One table to export.
#[derive(Debug, Clone)]
pub struct Job {
    pub table: String,
    pub filter: String,
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub owner: String,
    pub folder: PathBuf,
    pub format: Format,
    pub options: Options,
    pub include_ddl: bool,
    pub read: Read,
    /// The bytes of a table's extents a range of rows holds ([`Read::Chunks`]).
    pub chunk_bytes: u64,
}

impl ExportTables {
    pub fn title(&self) -> String {
        "Export tables".into()
    }

    pub fn is_busy(&self) -> bool {
        self.state.run.is_some() || self.state.tables_request.is_some()
    }

    #[cfg(test)]
    pub fn set_tables(&mut self, tables: &[(&str, &str)]) {
        self.state.tables = Some(Ok(tables
            .iter()
            .map(|(name, filter)| Choice {
                name: (*name).to_owned(),
                rows: None,
                selected: true,
                filter: (*filter).to_owned(),
            })
            .collect()));
    }

    #[cfg(test)]
    pub fn set_filter(&mut self, filter: &str) {
        self.state.filter = filter.to_owned();
    }

    #[cfg(test)]
    pub fn message(&self) -> Option<&(bool, String)> {
        self.state.message.as_ref()
    }

    #[cfg(test)]
    pub fn start_now(&mut self) -> Effects {
        self.start()
    }

    fn dialect(&self) -> Dialect {
        self.state.dialect.unwrap_or(Dialect::ORACLE)
    }

    fn mysql(&self) -> bool {
        self.dialect() == Dialect::MYSQL
    }

    /// The schema as typed, as the database reads it: on Oracle
    /// `"my_schema"` as written, others in uppercase (#337); empty for the
    /// current one.
    fn owner(&self) -> String {
        self.dialect().typed_name(&self.owner)
    }

    fn load_tables(&mut self) -> Effects {
        let mut effects = Effects::default();
        let owner = self.owner();
        let id = request_id();
        self.state.tables_request = Some(id);
        if self.mysql() {
            let task = mysql::load_tables(owner);
            effects.request(Target::Own, DbRequest::Run { id, task });
            return effects;
        }
        let task: dbcraft_db::TaskFn = Box::new(move |conn: &Connection| {
            let owner = if owner.is_empty() {
                conn.query_row_as::<String>(
                    "select sys_context('USERENV', 'CURRENT_SCHEMA') from dual",
                    &[],
                )?
            } else {
                owner
            };
            let mut tables = Vec::new();
            for row in conn.query_as::<(String, Option<i64>)>(
                "select table_name, num_rows from all_tables
                  where owner = :1 and nested = 'NO' and secondary = 'N'
                    and table_name not like 'BIN$%'
                  order by table_name",
                &[&owner],
            )? {
                let (name, rows) = row?;
                tables.push(Choice {
                    name,
                    rows,
                    selected: false,
                    filter: String::new(),
                });
            }
            Ok(Box::new(tables) as Box<dyn std::any::Any + Send>)
        });
        effects.request(Target::Own, DbRequest::Task { id, task });
        effects
    }

    fn start(&mut self) -> Effects {
        let mut effects = Effects::default();
        let (Some(folder), Some(Ok(tables))) = (&self.folder, &self.state.tables) else {
            return effects;
        };
        let jobs: Vec<Job> = tables
            .iter()
            .filter(|t| t.selected)
            .map(|t| Job {
                table: t.name.clone(),
                filter: t.filter.trim().to_owned(),
            })
            .collect();
        if jobs.is_empty() {
            return effects;
        }
        let settings = Settings {
            owner: self.owner(),
            folder: folder.clone(),
            format: self.format,
            options: Options {
                header: self.header,
                delimiter: Some(self.delimiter),
                null_text: self.null_text.clone(),
                ..Options::default()
            },
            include_ddl: self.include_ddl,
            read: self.read,
            chunk_bytes: CHUNK_BYTES,
        };
        let progress = Arc::new(Progress::default());
        let id = request_id();
        self.state.message = None;
        if self.mysql() {
            let task = mysql::prepare(
                settings.owner.clone(),
                jobs.clone(),
                settings.folder.clone(),
                settings.include_ddl,
                settings.read == Read::Consistent,
            );
            self.state.run = Some(Run {
                id,
                progress,
                mysql: Some(MySqlRun {
                    settings,
                    jobs,
                    prepared: None,
                    next: 0,
                }),
            });
            effects.request(Target::Own, DbRequest::Run { id, task });
            return effects;
        }
        self.state.run = Some(Run {
            id,
            progress: progress.clone(),
            mysql: None,
        });
        let task: dbcraft_db::TaskFn = Box::new(move |conn: &Connection| {
            let rows = export(conn, &settings, &jobs, &progress)?;
            Ok(Box::new(rows) as Box<dyn std::any::Any + Send>)
        });
        effects.request(Target::Own, DbRequest::Task { id, task });
        effects
    }

    pub fn on_event(&mut self, event: DbEvent) -> Effects {
        let (id, result) = match event {
            DbEvent::TaskDone { id, result } => (id, result),
            DbEvent::TimeZone(zone) => {
                self.state.time_zone = Some(zone);
                return Effects::default();
            }
            _ => return Effects::default(),
        };
        if self
            .state
            .run
            .as_ref()
            .is_some_and(|r| r.id == id && r.mysql.is_some())
        {
            return self.mysql_step(result);
        }
        let s = &mut self.state;
        if s.tables_request == Some(id) {
            s.tables_request = None;
            s.tables = Some(match result.map(|a| a.downcast::<Vec<Choice>>()) {
                Ok(Ok(t)) => Ok(*t),
                Ok(Err(_)) => Err("unexpected result".into()),
                Err(e) => Err(e.to_string()),
            });
        } else if let Some(run) = s.run.take_if(|r| r.id == id) {
            let tables = run.progress.tables_done.load(Ordering::Relaxed);
            let stopped = run.progress.stop.load(Ordering::Relaxed);
            s.message = Some(match result.map(|a| a.downcast::<u64>()) {
                Ok(Ok(rows)) => (
                    false,
                    format!(
                        "Exported {rows} rows from {tables} table(s) to {}",
                        self.folder.as_deref().unwrap_or(Path::new("")).display()
                    ),
                ),
                Ok(Err(_)) => (true, "unexpected result".into()),
                Err(_) if stopped => (true, format!("Stopped after {tables} table(s)")),
                Err(e) => (true, e.to_string()),
            });
        }
        Effects::default()
    }

    /// A MySQL export's next step, once the one before is done: the first
    /// table once the columns were read, the next once a table is written.
    fn mysql_step(&mut self, result: dbcraft_db::TaskResult) -> Effects {
        let unexpected = || DbError::new("unexpected result");
        let Some(run) = self.state.run.as_mut() else {
            return Effects::default();
        };
        let progress = run.progress.clone();
        let Some(steps) = run.mysql.as_mut() else {
            return Effects::default();
        };
        let done = match &steps.prepared {
            None => result
                .and_then(|r| r.downcast::<mysql::Prepared>().map_err(|_| unexpected()))
                .map(|prepared| {
                    progress
                        .tables
                        .store(prepared.tables.len(), Ordering::Relaxed);
                    steps.prepared = Some(*prepared);
                }),
            Some(prepared) => {
                let table = &prepared.tables[steps.next].name;
                result
                    .map_err(|e| mysql::failed(table, &e))
                    .and_then(|r| r.downcast::<u64>().map_err(|_| unexpected()))
                    .map(|rows| {
                        progress.rows.fetch_add(*rows, Ordering::Relaxed);
                        progress.current_rows.store(0, Ordering::Relaxed);
                        progress.tables_done.fetch_add(1, Ordering::Relaxed);
                        steps.next += 1;
                    })
            }
        };
        let next = done.and_then(|()| self.mysql_table());
        match next {
            Ok(Some(effects)) => effects,
            Ok(None) => self.mysql_finish(None),
            Err(e) => self.mysql_finish(Some(e)),
        }
    }

    /// Starts writing the next table; `None` when all are written.
    fn mysql_table(&mut self) -> Result<Option<Effects>, DbError> {
        let time_zone = self.state.time_zone.clone();
        let Some(run) = self.state.run.as_mut() else {
            return Ok(None);
        };
        let Some(steps) = run.mysql.as_ref() else {
            return Ok(None);
        };
        let Some(prepared) = &steps.prepared else {
            return Ok(None);
        };
        let (Some(table), Some(job)) =
            (prepared.tables.get(steps.next), steps.jobs.get(steps.next))
        else {
            return Ok(None);
        };
        if run.progress.stop.load(Ordering::Relaxed) {
            return Err(DbError::new("stopped"));
        }
        let settings = &steps.settings;
        *run.progress.current.lock().expect("current") = table.name.clone();
        let path = mysql::data_path(&settings.folder, &table.name, settings.format.extension());
        let options = Options {
            table: Dialect::MYSQL.quote_ident(&table.name),
            dialect: Dialect::MYSQL,
            time_zone,
            generated: table.generated.clone(),
            ..settings.options.clone()
        };
        let sink = crate::to_file::Sink::new(
            &path,
            settings.format,
            options,
            run.progress.current_rows.clone(),
        )?;
        let filter = dbcraft_plsql::tokenize_in(&job.filter, Dialect::MYSQL.syntax())
            .iter()
            .any(|t| !t.kind.is_trivia())
            .then_some(job.filter.as_str());
        let sql = mysql::select(&prepared.schema, table, filter);
        let id = request_id();
        run.id = id;
        let mut effects = Effects::default();
        effects.request(
            Target::Own,
            DbRequest::ExecuteInto {
                id,
                sql,
                max_rows: crate::to_file::BATCH,
                sink: Box::new(sink),
            },
        );
        Ok(Some(effects))
    }

    /// Ends a MySQL export, the transaction of a consistent one too.
    fn mysql_finish(&mut self, error: Option<DbError>) -> Effects {
        let mut effects = Effects::default();
        let Some(run) = self.state.run.take() else {
            return effects;
        };
        let Some(steps) = run.mysql else {
            return effects;
        };
        if steps.settings.read == Read::Consistent && steps.prepared.is_some() {
            let task = mysql::end_transaction();
            effects.request(
                Target::Own,
                DbRequest::Run {
                    id: request_id(),
                    task,
                },
            );
        }
        let p = &run.progress;
        let tables = p.tables_done.load(Ordering::Relaxed);
        self.state.message = Some(match error {
            None => (
                false,
                format!(
                    "Exported {} rows from {tables} table(s) to {}",
                    p.rows.load(Ordering::Relaxed),
                    steps.settings.folder.display()
                ),
            ),
            Some(_) if p.stop.load(Ordering::Relaxed) => {
                (true, format!("Stopped after {tables} table(s)"))
            }
            Some(e) => (true, e.text()),
        });
        effects
    }

    pub fn ui(&mut self, ui: &mut Ui, cx: &DocContext) -> Effects {
        let mut effects = Effects::default();
        if !cx.connected {
            ui.centered_and_justified(|ui| ui.weak("Connect to export tables"));
            return effects;
        }
        self.state.dialect = Some(cx.dialect);
        if self.state.tables.is_none() && self.state.tables_request.is_none() {
            effects.extend(self.load_tables());
        }
        if let Some(rx) = &self.state.picking
            && let Ok(picked) = rx.try_recv()
        {
            self.state.picking = None;
            if picked.is_some() {
                self.folder = picked;
            }
        }

        let mut reload = false;
        ui.horizontal(|ui| {
            ui.label(if self.mysql() { "Database" } else { "Schema" });
            let r = ui.add(
                egui::TextEdit::singleline(&mut self.owner)
                    .hint_text("current")
                    .desired_width(140.0),
            );
            reload |= r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            reload |= ui.button("Reload").clicked();
            ui.separator();
            ui.add(
                egui::TextEdit::singleline(&mut self.state.filter)
                    .hint_text("Filter tables…")
                    .desired_width(180.0),
            );
            if let Some(Ok(tables)) = &mut self.state.tables {
                let needle = self.state.filter.trim().to_uppercase();
                if ui.small_button("Select all").clicked() {
                    for t in tables
                        .iter_mut()
                        .filter(|t| crate::browser::name_matches(&t.name, &needle))
                    {
                        t.selected = true;
                    }
                }
                if ui.small_button("None").clicked() {
                    for t in tables.iter_mut() {
                        t.selected = false;
                    }
                }
            }
        });
        if reload {
            self.state.tables = None;
            effects.extend(self.load_tables());
        }

        egui::Panel::bottom(egui::Id::new(("export-options", cx.id)))
            .resizable(false)
            .show(ui, |ui| effects.extend(self.options_ui(ui)));
        egui::CentralPanel::default().show(ui, |ui| self.tables_ui(ui));
        effects
    }

    fn tables_ui(&mut self, ui: &mut Ui) {
        let needle = self.state.filter.trim().to_uppercase();
        let dialect = self.dialect();
        let hint = if dialect == Dialect::MYSQL {
            "all rows, or e.g. created > now() - interval 30 day"
        } else {
            "all rows, or e.g. created > sysdate - 30"
        };
        match &mut self.state.tables {
            None => {
                ui.spinner();
            }
            Some(Err(e)) => {
                ui.colored_label(ui.visuals().error_fg_color, e.as_str());
            }
            Some(Ok(tables)) if tables.is_empty() => {
                ui.weak("No tables in this schema");
            }
            Some(Ok(tables)) => {
                egui::ScrollArea::vertical()
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        egui::Grid::new("export-tables")
                            .num_columns(3)
                            .striped(true)
                            .spacing([16.0, 4.0])
                            .show(ui, |ui| {
                                ui.strong("Table");
                                ui.strong("Rows (statistics)");
                                ui.strong("WHERE");
                                ui.end_row();
                                for t in tables
                                    .iter_mut()
                                    .filter(|t| crate::browser::name_matches(&t.name, &needle))
                                {
                                    ui.checkbox(
                                        &mut t.selected,
                                        RichText::new(crate::browser::shown_name(dialect, &t.name))
                                            .monospace(),
                                    );
                                    ui.weak(t.rows.map_or_else(|| "?".into(), |r| r.to_string()));
                                    ui.add_enabled(
                                        t.selected,
                                        egui::TextEdit::singleline(&mut t.filter)
                                            .hint_text(hint)
                                            .font(egui::TextStyle::Monospace)
                                            .desired_width(360.0),
                                    );
                                    ui.end_row();
                                }
                            });
                    });
            }
        }
    }

    fn options_ui(&mut self, ui: &mut Ui) -> Effects {
        let mut effects = Effects::default();
        ui.add_space(4.0);
        egui::Grid::new("export-settings")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label("Format");
                ui.horizontal(|ui| {
                    for f in Format::STREAMING {
                        ui.selectable_value(&mut self.format, *f, f.label());
                    }
                });
                ui.end_row();
                if matches!(self.format, Format::Csv | Format::Tsv) {
                    ui.label("Options");
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut self.header, "Header row");
                        if self.format == Format::Csv {
                            ui.label("Separator");
                            for (d, label) in
                                [(b',', ","), (b';', ";"), (b'|', "|"), (b'\t', "Tab")]
                            {
                                ui.selectable_value(&mut self.delimiter, d, label);
                            }
                        }
                        ui.label("NULL as");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.null_text)
                                .hint_text("empty")
                                .desired_width(70.0),
                        );
                    });
                    ui.end_row();
                }
                ui.label("Folder");
                ui.horizontal(|ui| {
                    match &self.folder {
                        Some(f) => {
                            ui.label(RichText::new(f.display().to_string()).monospace());
                        }
                        None => {
                            ui.weak("choose where the files go");
                        }
                    }
                    if ui.button("Choose…").clicked() && self.state.picking.is_none() {
                        let (tx, rx) = std::sync::mpsc::channel();
                        std::thread::spawn(move || {
                            let _ = tx.send(rfd::FileDialog::new().pick_folder());
                        });
                        self.state.picking = Some(rx);
                    }
                    ui.checkbox(&mut self.include_ddl, "Include DDL")
                        .on_hover_text("Writes <table>.ddl.sql next to each data file");
                });
                ui.end_row();
                ui.label("Read");
                let mysql = self.mysql();
                ui.horizontal(|ui| {
                    if mysql {
                        ui.selectable_value(&mut self.read, Read::Chunks, "Table by table")
                            .on_hover_text(
                                "Each table is one query, as the table was when it began: \
                                 MySQL keeps a query's snapshot as long as it runs. Tables are \
                                 read at different moments.",
                            );
                        ui.selectable_value(&mut self.read, Read::Consistent, "Consistent")
                            .on_hover_text(
                                "All tables as they were when the export began, in one \
                                 transaction with a consistent snapshot (InnoDB tables: \
                                 MyISAM keeps no versions). The server keeps the old versions \
                                 of rows changed meanwhile until the last table is read.",
                            );
                        return;
                    }
                    ui.selectable_value(&mut self.read, Read::Chunks, "In chunks")
                        .on_hover_text(
                            "Large tables are read in ranges of rows, each a short query: \
                             a range that fails with ORA-01555 (snapshot too old) is read \
                             again. Tables, and ranges, are read at different moments.",
                        );
                    ui.selectable_value(&mut self.read, Read::Consistent, "Consistent")
                        .on_hover_text(
                            "All tables as they were when the export began, in a read-only \
                             transaction. Oracle has to keep the undo until the last table is \
                             read: a long export may fail with ORA-01555 unless UNDO_RETENTION \
                             covers it.",
                        );
                });
                ui.end_row();
            });
        ui.add_space(4.0);
        let selected = match &self.state.tables {
            Some(Ok(t)) => t.iter().filter(|t| t.selected).count(),
            _ => 0,
        };
        ui.horizontal(|ui| {
            if let Some(run) = &self.state.run {
                let p = &run.progress;
                let (done, total) = (
                    p.tables_done.load(Ordering::Relaxed),
                    p.tables.load(Ordering::Relaxed),
                );
                let current = p.current.lock().expect("current").clone();
                ui.spinner();
                ui.add(
                    egui::ProgressBar::new(done as f32 / total.max(1) as f32)
                        .desired_width(220.0)
                        .text(format!("{done} / {total} tables")),
                );
                ui.weak(format!(
                    "{} · {} rows",
                    crate::browser::shown_name(self.dialect(), &current),
                    p.rows.load(Ordering::Relaxed) + p.current_rows.load(Ordering::Relaxed)
                ));
                if ui.button("Stop").clicked() {
                    p.stop.store(true, Ordering::Relaxed);
                    effects.cancel = true;
                }
                ui.ctx()
                    .request_repaint_after(std::time::Duration::from_millis(150));
            } else {
                if let Some((error, text)) = &self.state.message {
                    let color = if *error {
                        ui.visuals().error_fg_color
                    } else {
                        ui.visuals().text_color()
                    };
                    ui.colored_label(color, text);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let label = match selected {
                        1 => "Export 1 table".to_owned(),
                        n => format!("Export {n} tables"),
                    };
                    if ui
                        .add_enabled(
                            selected > 0 && self.folder.is_some(),
                            egui::Button::image_and_text(
                                dbcraft_ui::icons::Icon::Export.image(ui),
                                label,
                            ),
                        )
                        .clicked()
                    {
                        effects.extend(self.start());
                    }
                });
            }
        });
        ui.add_space(4.0);
        effects
    }
}

/// How a table's rows are written: INSERTs go into `table`, quoted unless
/// it is a plain name (#242).
fn insert_options(settings: &Settings, table: &str) -> Options {
    Options {
        table: dbcraft_data::identifier(table),
        ..settings.options.clone()
    }
}

/// Exports the tables; returns the total number of rows written.
pub fn export(
    conn: &Connection,
    settings: &Settings,
    jobs: &[Job],
    progress: &Progress,
) -> Result<u64, DbError> {
    let owner = if settings.owner.is_empty() {
        conn.query_row_as::<String>(
            "select sys_context('USERENV', 'CURRENT_SCHEMA') from dual",
            &[],
        )?
    } else {
        settings.owner.clone()
    };
    progress.tables.store(jobs.len(), Ordering::Relaxed);
    std::fs::create_dir_all(&settings.folder)
        .map_err(|e| DbError::new(format!("{}: {e}", settings.folder.display())))?;
    // The DDL first: DBMS_METADATA doesn't run in a read-only transaction.
    if settings.include_ddl {
        for job in jobs {
            if progress.stop.load(Ordering::Relaxed) {
                return Err(DbError::new("stopped"));
            }
            *progress.current.lock().expect("current") = job.table.clone();
            // A file of its own for each table, as Export schema writes (#280).
            let base = crate::object_files::file_stem(&job.table);
            let ddl =
                crate::object_files::object_text(conn, &owner, &job.table, ObjectType::Table)?;
            let path = settings.folder.join(format!("{base}.ddl.sql"));
            std::fs::write(&path, ddl)
                .map_err(|e| DbError::new(format!("{}: {e}", path.display())))?;
        }
    }
    if settings.read == Read::Consistent {
        // Every query of the transaction reads the database as it was when
        // it began, as one query would. It can't begin with changes not
        // committed, which stay as they are.
        conn.execute("set transaction read only", &[])
            .map_err(DbError::from)
            .map_err(|e| match e.code {
                Some(1453) => DbError::new(
                    "Commit or roll back first: a consistent export reads in a transaction \
                     of its own",
                ),
                _ => e,
            })?;
        let exported = export_tables(conn, &owner, settings, jobs, progress);
        // Ends the read-only transaction; it changed nothing.
        let _ = conn.rollback();
        return exported.map_err(|e| match e.code {
            Some(SNAPSHOT_TOO_OLD) => DbError::new(format!(
                "{}: the undo doesn't reach back to the start of the export any more. Export \
                 in chunks, or ask for a longer UNDO_RETENTION",
                e.message
            )),
            Some(DEFINITION_CHANGED) => DbError::new(format!(
                "{}: the table was changed (DDL) after the export began, or a few seconds \
                 before it: export again",
                e.message
            )),
            _ => e,
        });
    }
    export_tables(conn, &owner, settings, jobs, progress)
}

/// ORA-01555 "snapshot too old": the undo a query needs to read the rows
/// as they were when it started was overwritten.
const SNAPSHOT_TOO_OLD: i32 = 1555;

/// ORA-01466 "table definition has changed": a read-only transaction can't
/// read a table whose definition is newer than the transaction.
const DEFINITION_CHANGED: i32 = 1466;

/// How often a range of rows is read again after ORA-01555.
const RETRIES: usize = 3;

/// The tables' rows, each table into a file of its own.
fn export_tables(
    conn: &Connection,
    owner: &str,
    settings: &Settings,
    jobs: &[Job],
    progress: &Progress,
) -> Result<u64, DbError> {
    let mut total = 0;
    for job in jobs {
        if progress.stop.load(Ordering::Relaxed) {
            return Err(DbError::new("stopped"));
        }
        *progress.current.lock().expect("current") = job.table.clone();
        let rows = export_table(conn, owner, settings, job, progress).map_err(|e| {
            // Its code, for what the export says of ORA-01555.
            let mut error = DbError::new(format!("{}: {}", job.table, e.message));
            error.code = e.code;
            error
        })?;
        total += rows;
        progress.tables_done.fetch_add(1, Ordering::Relaxed);
    }
    Ok(total)
}

/// One table's rows into its file, under its name once they are all in it.
fn export_table(
    conn: &Connection,
    owner: &str,
    settings: &Settings,
    job: &Job,
    progress: &Progress,
) -> Result<u64, DbError> {
    let base = crate::object_files::file_stem(&job.table);
    // Invisible columns too (#444); INSERTs without the virtual ones,
    // which Oracle refuses to write (#443).
    let with_virtual = settings.format != Format::Insert;
    let columns = dbcraft_db::compat::table_columns(conn, owner, &job.table, with_virtual)?;
    let list = if columns.is_empty() {
        "*".to_owned()
    } else {
        columns
            .iter()
            .map(|c| quote_ident(c))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let select = format!(
        "select {list} from {}.{}",
        quote_ident(owner),
        quote_ident(&job.table)
    );
    // A filter that is all comment is none (#427): `where -- x` failed.
    let filter = dbcraft_plsql::tokenize(&job.filter)
        .iter()
        .any(|t| !t.kind.is_trivia())
        .then_some(job.filter.as_str());
    let ranges = match settings.read {
        Read::Chunks => rowid_ranges(conn, owner, &job.table, settings.chunk_bytes),
        Read::Consistent => vec![(None, None)],
    };
    let path = settings
        .folder
        .join(format!("{base}.{}", settings.format.extension()));
    let io = |e: &dyn std::fmt::Display| DbError::new(format!("{}: {e}", path.display()));
    // Under its name once it is whole: a DbCraft that was killed leaves no
    // file that looks complete.
    let part = crate::to_file::part_path(&path);
    let create = || {
        std::fs::File::create(&part)
            .map(|file| std::io::BufWriter::with_capacity(1 << 20, file))
            .map_err(|e| io(&e))
    };
    let mut out = Some(create()?);
    let mut writer: Option<StreamWriter<std::io::BufWriter<std::fs::File>>> = None;
    let options = insert_options(settings, &job.table);
    let mut written = || -> Result<u64, DbError> {
        let mut total = 0;
        for (lo, hi) in &ranges {
            let sql = range_query(&select, lo.as_deref(), hi.as_deref(), filter);
            let mut retries = 0;
            loop {
                let mark = match writer.as_mut() {
                    Some(w) => Some(w.mark().map_err(|e| io(&e))?),
                    None => None,
                };
                let mut fetched = 0;
                let result = dbcraft_db::stream_query(conn, &sql, 1000, |columns, rows| {
                    if progress.stop.load(Ordering::Relaxed) {
                        return Err(DbError::new("stopped"));
                    }
                    if let Some(out) = out.take() {
                        writer = Some(
                            StreamWriter::new(
                                settings.format,
                                columns.to_vec(),
                                options.clone(),
                                out,
                            )
                            .map_err(|e| io(&e))?,
                        );
                    }
                    if let Some(w) = writer.as_mut() {
                        w.write(rows).map_err(|e| io(&e))?;
                    }
                    fetched += rows.len() as u64;
                    progress
                        .rows
                        .fetch_add(rows.len() as u64, Ordering::Relaxed);
                    Ok(())
                });
                match result {
                    Ok(rows) => {
                        total += rows;
                        break;
                    }
                    // Read again, the rows of this range cut off the file:
                    // each range is a query of its own, short enough that
                    // the undo it needs is still there, most of the time.
                    Err(e)
                        if e.code == Some(SNAPSHOT_TOO_OLD)
                            && settings.read == Read::Chunks
                            && retries < RETRIES =>
                    {
                        retries += 1;
                        tracing::warn!(table = job.table, retries, "{}: read again", e.text());
                        progress.rows.fetch_sub(fetched, Ordering::Relaxed);
                        match (&mark, writer.as_mut()) {
                            (Some(mark), Some(w)) => w.rewind(mark).map_err(|e| io(&e))?,
                            // Not even the header was written before.
                            _ => {
                                writer = None;
                                out = Some(create()?);
                            }
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(total)
    };
    let result = written().and_then(|rows| {
        if let Some(w) = writer.take() {
            w.finish().map_err(|e| io(&e))?;
        }
        std::fs::rename(&part, &path).map_err(|e| io(&e))?;
        Ok(rows)
    });
    if result.is_err() {
        drop(writer);
        drop(out);
        let _ = std::fs::remove_file(&part);
    }
    result
}

/// `select`, the rows of the ROWID range from `lo` (inclusive) to `hi`
/// (exclusive), either end open when `None`, and of `filter`.
fn range_query(select: &str, lo: Option<&str>, hi: Option<&str>, filter: Option<&str>) -> String {
    let mut conditions = Vec::new();
    if let Some(lo) = lo {
        conditions.push(format!("rowid >= chartorowid('{lo}')"));
    }
    if let Some(hi) = hi {
        conditions.push(format!("rowid < chartorowid('{hi}')"));
    }
    // On a line of its own: a filter that ends in a `--` comment.
    if let Some(filter) = filter {
        conditions.push(format!("(\n{filter}\n)"));
    }
    if conditions.is_empty() {
        select.to_owned()
    } else {
        format!("{select} where {}", conditions.join(" and "))
    }
}

/// How much of a table a range of rows is read in.
pub const CHUNK_BYTES: u64 = 256 << 20;

/// ROWID ranges that a table's rows are read in, about `chunk` bytes of its
/// extents each: from one range's start to the next one's, the first and
/// the last open, so that together they hold every ROWID there is, whatever
/// the extents are. Without access to DBA_EXTENTS, from a sample of the
/// table's blocks instead. One range, open at both ends, when the table is
/// small, isn't a heap (an index-organized table has no such ROWIDs) or its
/// size isn't known (another user's table without statistics).
fn rowid_ranges(
    conn: &Connection,
    owner: &str,
    table: &str,
    chunk: u64,
) -> Vec<(Option<String>, Option<String>)> {
    let starts = range_starts(conn, owner, table, chunk).unwrap_or_else(|e| {
        tracing::debug!(table, "no ROWID ranges: {}", e.text());
        Vec::new()
    });
    let mut ranges = Vec::with_capacity(starts.len() + 1);
    let mut lo = None;
    for start in starts {
        ranges.push((lo, Some(start.clone())));
        lo = Some(start);
    }
    ranges.push((lo, None));
    ranges
}

/// The first ROWID of each range but the first: of the extent where the
/// bytes of the extents before it pass another `chunk`. Needs DBA_EXTENTS:
/// USER_EXTENTS has no blocks.
fn range_starts(
    conn: &Connection,
    owner: &str,
    table: &str,
    chunk: u64,
) -> Result<Vec<String>, DbError> {
    // Binds go by position, in the order they appear.
    let all = "select rowidtochar(dbms_rowid.rowid_create(1, obj, fno, block, 0))
                 from (select obj, fno, block, g, lag(g) over (order by obj, fno, block) prev
                         from (select o.data_object_id obj, e.relative_fno fno, e.block_id block,
                                      trunc((sum(e.bytes) over (order by o.data_object_id,
                                               e.relative_fno, e.block_id) - e.bytes) / :1) g
                                 from dba_extents e
                                 join all_objects o
                                   on o.object_name = e.segment_name
                                  and o.object_type = e.segment_type
                                  and nvl(o.subobject_name, ' ') = nvl(e.partition_name, ' ')
                                  and o.owner = e.owner and e.owner = :2
                                where e.segment_name = :3
                                  and e.segment_type in
                                      ('TABLE', 'TABLE PARTITION', 'TABLE SUBPARTITION')))
                where prev is not null and g <> prev
                order by obj, fno, block";
    let chunk = chunk as i64;
    let read = conn
        .query_as::<String>(all, &[&chunk, &owner, &table])
        .and_then(|rows| rows.collect::<Result<Vec<_>, _>>());
    match read {
        Ok(starts) => Ok(starts),
        Err(e) => {
            tracing::debug!(table, "no extents: {e}");
            sampled_starts(conn, owner, table, chunk)
        }
    }
}

/// Range starts from the ROWIDs of a sample of a table's blocks, a few
/// blocks a range: the table's size from USER_SEGMENTS for the user's own
/// tables, else from its statistics. Ranges of uneven size where the
/// sample is, but together still every row. Oracle samples blocks a
/// multiblock read at a time, so that a table of few extents may give no
/// rows or all of them: then from a sample of its rows, which reads it all,
/// but a table that small is quick to read.
fn sampled_starts(
    conn: &Connection,
    owner: &str,
    table: &str,
    chunk: i64,
) -> Result<Vec<String>, DbError> {
    let bytes: Option<i64> = conn.query_row_as(
        "select case when t.iot_type is null then
                  nvl((select sum(bytes) from user_segments
                        where segment_name = :1 and segment_type like 'TABLE%'
                          and user = :2),
                      t.num_rows * t.avg_row_len)
                end
           from all_tables t
          where t.owner = :3 and t.table_name = :4",
        &[&table, &owner, &owner, &table],
    )?;
    let ranges = bytes.unwrap_or(0) / chunk.max(1);
    if ranges < 2 {
        return Ok(Vec::new());
    }
    let blocks = (bytes.unwrap_or(0) / 8192).max(1);
    let percent = (100.0 * (ranges * 8) as f64 / blocks as f64).clamp(0.000001, 99.999999);
    let sample = |of: &str| {
        let sql = format!(
            "select rowidtochar(min(rid))
               from (select rowid rid, ntile(:1) over (order by rowid) g
                       from {}.{} sample {of}({percent:.6}))
              group by g
             having g > 1
              order by g",
            quote_ident(owner),
            quote_ident(table)
        );
        conn.query_as::<String>(&sql, &[&ranges])?
            .collect::<Result<Vec<_>, _>>()
            .map_err(DbError::from)
    };
    let starts = sample("block ")?;
    if (starts.len() as i64) + 1 < ranges {
        return sample("");
    }
    Ok(starts)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// INSERTs name the table as Oracle reads it: a name stored other than
    /// in plain uppercase in quotes (#242).
    #[test]
    fn inserts_name_the_table() {
        let settings = Settings {
            owner: String::new(),
            folder: PathBuf::new(),
            format: Format::Insert,
            options: Options::default(),
            include_ddl: false,
            read: Read::Chunks,
            chunk_bytes: CHUNK_BYTES,
        };
        let target = |table: &str| insert_options(&settings, table).table;
        assert_eq!(target("DEMO_EMPLOYEES"), "demo_employees");
        assert_eq!(target("guidelines-division"), "\"guidelines-division\"");
        assert_eq!(target("Foo"), "\"Foo\"");
        assert_eq!(target("MY TABLE"), "\"MY TABLE\"");
        assert_eq!(target("LEVEL"), "\"LEVEL\"");
        assert_eq!(target("RESOURCE"), "\"RESOURCE\"");
        assert_eq!(target("size"), "\"size\"");
    }

    /// The INSERTs of a table name its columns called like reserved words
    /// in quotes, and those stored in lowercase or mixed case: they run
    /// back into it.
    #[test]
    fn inserts_quote_reserved_words() {
        let Some(conn) = crate::test_db::connect("DBCRAFT_TEST_DB") else {
            return;
        };
        let _ = conn.execute("drop table r54_exp_words purge", &[]);
        conn.execute(
            "create table r54_exp_words (id number, \"LEVEL\" number, \"SIZE\" varchar2(10), \
             \"RESOURCE\" number, \"level\" number, \"Size\" number)",
            &[],
        )
        .unwrap();
        conn.execute("insert into r54_exp_words values (1, 2, 'x', 3, 4, 5)", &[])
            .unwrap();
        let folder = std::env::temp_dir().join(format!("dbcraft-r54-words-{}", std::process::id()));
        let settings = Settings {
            owner: String::new(),
            folder: folder.clone(),
            format: Format::Insert,
            options: Options::default(),
            include_ddl: false,
            read: Read::Chunks,
            chunk_bytes: CHUNK_BYTES,
        };
        let jobs = [Job {
            table: "R54_EXP_WORDS".into(),
            filter: String::new(),
        }];
        export(&conn, &settings, &jobs, &Progress::default()).unwrap();
        let text = std::fs::read_to_string(folder.join("r54_exp_words.sql")).unwrap();
        let insert = text.trim_end().trim_end_matches(';');
        conn.execute(insert, &[])
            .unwrap_or_else(|e| panic!("{e}\n{insert}"));
        let copies: i64 = conn
            .query_row_as(
                "select count(*) from r54_exp_words where id = 1 and \"LEVEL\" = 2 \
                 and \"SIZE\" = 'x' and \"RESOURCE\" = 3 and \"level\" = 4 and \"Size\" = 5",
                &[],
            )
            .unwrap();
        assert_eq!(copies, 2);
        conn.execute("drop table r54_exp_words purge", &[]).unwrap();
        std::fs::remove_dir_all(folder).unwrap();
    }

    /// A table's invisible columns are exported, which `select *` left
    /// out (#444); its INSERTs leave out its virtual columns, which Oracle
    /// refuses to write (#443), and run back into it. A CSV has them both.
    #[test]
    fn invisible_and_virtual_columns() {
        let Some(conn) = crate::test_db::connect("DBCRAFT_TEST_DB") else {
            return;
        };
        let _ = conn.execute("drop table fd_exp_cols purge", &[]);
        conn.execute(
            "create table fd_exp_cols (id number, n number, hidden_n number invisible, \
             twice as (n * 2) virtual)",
            &[],
        )
        .unwrap();
        conn.execute(
            "insert into fd_exp_cols (id, n, hidden_n) values (1, 2, 3)",
            &[],
        )
        .unwrap();
        let folder = std::env::temp_dir().join(format!("dbcraft-fd-cols-{}", std::process::id()));
        let export_as = |format: Format| {
            let settings = Settings {
                owner: String::new(),
                folder: folder.clone(),
                format,
                options: Options::default(),
                include_ddl: false,
                read: Read::Chunks,
                chunk_bytes: CHUNK_BYTES,
            };
            let jobs = [Job {
                table: "FD_EXP_COLS".into(),
                filter: String::new(),
            }];
            export(&conn, &settings, &jobs, &Progress::default()).unwrap();
            let path = folder.join(format!("fd_exp_cols.{}", format.extension()));
            std::fs::read_to_string(path).unwrap()
        };
        let csv = export_as(Format::Csv);
        assert!(csv.starts_with("ID,N,TWICE,HIDDEN_N"), "{csv}");
        let text = export_as(Format::Insert);
        let insert = text.trim_end().trim_end_matches(';');
        assert!(!insert.contains("twice"), "{insert}");
        conn.execute(insert, &[])
            .unwrap_or_else(|e| panic!("{e}\n{insert}"));
        let copies: i64 = conn
            .query_row_as(
                "select count(*) from fd_exp_cols where id = 1 and n = 2 and hidden_n = 3 \
                 and twice = 4",
                &[],
            )
            .unwrap();
        assert_eq!(copies, 2);
        conn.execute("drop table fd_exp_cols purge", &[]).unwrap();
        std::fs::remove_dir_all(folder).unwrap();
    }

    /// Tables whose names differ only in case get files of their own, also
    /// where the file system takes `Foo` and `foo` for one file, and so do
    /// names with a `/` or a `:`: no sub-folder, nothing Windows refuses.
    #[test]
    fn every_table_has_files_of_its_own() {
        let Some(conn) = crate::test_db::connect("DBCRAFT_TEST_DB") else {
            return;
        };
        let names = [
            "R54_EXP_FOO",
            "R54_EXP_Foo",
            "r54_exp_foo",
            "R54_EXP_A/B",
            "R54_EXP_A:B",
        ];
        let quoted = |name: &str| format!("\"{name}\"");
        for name in names {
            let _ = conn.execute(&format!("drop table {} purge", quoted(name)), &[]);
            conn.execute(
                &format!(
                    "create table {} as select '{name}' as name from dual",
                    quoted(name)
                ),
                &[],
            )
            .unwrap();
        }
        let folder = std::env::temp_dir().join(format!("dbcraft-r54-names-{}", std::process::id()));
        let settings = Settings {
            owner: String::new(),
            folder: folder.clone(),
            format: Format::Csv,
            options: Options::default(),
            include_ddl: true,
            read: Read::Chunks,
            chunk_bytes: CHUNK_BYTES,
        };
        let jobs: Vec<Job> = names
            .iter()
            .map(|name| Job {
                table: (*name).into(),
                filter: String::new(),
            })
            .collect();
        let exported = export(&conn, &settings, &jobs, &Progress::default());
        let mut files: Vec<(String, String)> = std::fs::read_dir(&folder)
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                (
                    path.file_name().unwrap().to_string_lossy().into_owned(),
                    text,
                )
            })
            .collect();
        files.sort();
        for name in names {
            let _ = conn.execute(&format!("drop table {} purge", quoted(name)), &[]);
        }
        std::fs::remove_dir_all(&folder).unwrap();
        assert_eq!(exported.map_err(|e| e.message), Ok(5), "{files:?}");
        assert_eq!(files.len(), 10, "{files:?}");
        let lowercase: std::collections::HashSet<String> =
            files.iter().map(|(f, _)| f.to_lowercase()).collect();
        assert_eq!(lowercase.len(), 10, "{files:?}");
        for name in names {
            let csv = format!("NAME\n{name}\n");
            let data = files.iter().filter(|(_, text)| *text == csv).count();
            let ddl = format!("CREATE TABLE {}", quoted(name));
            let ddls = files.iter().filter(|(_, t)| t.contains(&ddl)).count();
            assert_eq!((data, ddls), (1, 1), "{name}: {files:?}");
        }
        for (file, _) in &files {
            assert!(
                !file.contains(['<', '>', ':', '"', '/', '\\', '|', '?', '*']),
                "{file}"
            );
        }
    }

    #[test]
    fn exports_tables_with_filters() {
        let Ok(spec) = std::env::var("DBCRAFT_TEST_DB") else {
            return;
        };
        let (cred, db) = spec.rsplit_once('@').unwrap();
        let (user, pw) = cred.split_once('/').unwrap();
        let conn = Connection::connect(user, pw, db).unwrap();
        let _ = conn.execute("drop table dbcraft_exp_a purge", &[]);
        conn.execute(
            "create table dbcraft_exp_a as select level as id, case when mod(level, 2) = 0 then 'x' end as tag
               from dual connect by level <= 10",
            &[],
        )
        .unwrap();
        let folder = std::env::temp_dir().join(format!("dbcraft-exp-{}", std::process::id()));
        let settings = Settings {
            owner: String::new(),
            folder: folder.clone(),
            format: Format::Csv,
            options: Options {
                delimiter: Some(b';'),
                null_text: "NULL".into(),
                ..Options::default()
            },
            include_ddl: true,
            read: Read::Chunks,
            chunk_bytes: CHUNK_BYTES,
        };
        let jobs = [Job {
            table: "DBCRAFT_EXP_A".into(),
            filter: "id <= 3".into(),
        }];
        let progress = Progress::default();
        let rows = export(&conn, &settings, &jobs, &progress).unwrap();
        assert_eq!(rows, 3);
        let csv = std::fs::read_to_string(folder.join("dbcraft_exp_a.csv")).unwrap();
        assert_eq!(csv, "ID;TAG\n1;NULL\n2;x\n3;NULL\n");
        let ddl = std::fs::read_to_string(folder.join("dbcraft_exp_a.ddl.sql")).unwrap();
        assert!(ddl.contains("CREATE TABLE \"DBCRAFT_EXP_A\""), "{ddl}");

        // A filter that is all comment exports every row.
        let commented = [Job {
            table: "DBCRAFT_EXP_A".into(),
            filter: "-- id <= 1".into(),
        }];
        let all = export(&conn, &settings, &commented, &Progress::default()).unwrap();
        assert!(all > 3, "{all}");

        // A bad filter fails that table and leaves no partial file.
        let bad = [Job {
            table: "DBCRAFT_EXP_A".into(),
            filter: "no_such_column = 1".into(),
        }];
        std::fs::remove_file(folder.join("dbcraft_exp_a.csv")).unwrap();
        let err = export(&conn, &settings, &bad, &Progress::default()).unwrap_err();
        assert!(err.message.contains("ORA-00904"), "{err}");
        assert!(!folder.join("dbcraft_exp_a.csv").exists());

        conn.execute("drop table dbcraft_exp_a purge", &[]).unwrap();
        std::fs::remove_dir_all(folder).unwrap();
    }

    /// A table larger than a chunk is read in ROWID ranges, which hold
    /// every row once, also with a filter; read consistently, it is one
    /// query, and not with changes not committed (they stay).
    #[test]
    fn exports_in_chunks_and_consistently() {
        let Some(conn) = crate::test_db::connect("DBCRAFT_TEST_DB") else {
            return;
        };
        let _ = conn.execute("drop table dbcraft_exp_c purge", &[]);
        conn.execute(
            "create table dbcraft_exp_c (id number primary key, pad varchar2(400))
               storage (initial 64k next 64k)",
            &[],
        )
        .unwrap();
        conn.execute(
            "insert into dbcraft_exp_c
             select level, rpad('x', 400, 'x') from dual connect by level <= 20000",
            &[],
        )
        .unwrap();
        conn.commit().unwrap();
        let owner: String = conn.query_row_as("select user from dual", &[]).unwrap();
        // 8 MB of rows, about 64 extents of 64 KB to 1 MB: from a sample of
        // its blocks as the user, from DBA_EXTENTS as the DBA.
        let ranges = rowid_ranges(&conn, &owner, "DBCRAFT_EXP_C", 256 << 10);
        assert!(ranges.len() > 4, "{ranges:?}");
        assert!(ranges[0].0.is_none() && ranges.last().unwrap().1.is_none());
        if let Some(dba) = crate::test_db::connect("DBCRAFT_TEST_DB_DBA") {
            let extents = range_starts(&dba, &owner, "DBCRAFT_EXP_C", 256 << 10).unwrap();
            assert!(extents.len() > 4, "{extents:?}");
        }
        assert_eq!(
            rowid_ranges(&conn, &owner, "DBCRAFT_EXP_C", CHUNK_BYTES),
            [(None, None)],
            "smaller than a chunk"
        );

        let folder = std::env::temp_dir().join(format!("dbcraft-exp-c-{}", std::process::id()));
        let mut settings = Settings {
            owner: String::new(),
            folder: folder.clone(),
            format: Format::Csv,
            options: Options {
                header: false,
                ..Options::default()
            },
            include_ddl: false,
            read: Read::Chunks,
            chunk_bytes: 256 << 10,
        };
        let job = |filter: &str| Job {
            table: "DBCRAFT_EXP_C".into(),
            filter: filter.into(),
        };
        let ids = || {
            let csv = std::fs::read_to_string(folder.join("dbcraft_exp_c.csv")).unwrap();
            let mut ids: Vec<u32> = csv
                .lines()
                .map(|l| l.split(',').next().unwrap().parse().unwrap())
                .collect();
            ids.sort_unstable();
            ids
        };
        let progress = Progress::default();
        assert_eq!(
            export(&conn, &settings, &[job("")], &progress).unwrap(),
            20000
        );
        assert_eq!(progress.rows.load(Ordering::Relaxed), 20000);
        assert_eq!(ids(), (1..=20000).collect::<Vec<_>>());
        let filtered = export(
            &conn,
            &settings,
            &[job("mod(id, 7) = 0 -- sevens")],
            &Progress::default(),
        );
        assert_eq!(filtered.unwrap(), 20000 / 7);
        assert_eq!(ids(), (1..=20000 / 7).map(|i| i * 7).collect::<Vec<_>>());

        settings.read = Read::Consistent;
        // Oracle maps SCNs to times by the few seconds: once in a while the
        // table just created is too new for the transaction (ORA-01466).
        let consistent = || export(&conn, &settings, &[job("")], &Progress::default());
        let exported = consistent().or_else(|e| {
            assert!(e.message.contains("export again"), "{e}");
            std::thread::sleep(std::time::Duration::from_secs(5));
            consistent()
        });
        assert_eq!(exported.unwrap(), 20000);
        assert_eq!(ids().len(), 20000);
        conn.execute("delete from dbcraft_exp_c where id = 1", &[])
            .unwrap();
        let err = export(&conn, &settings, &[job("")], &Progress::default()).unwrap_err();
        assert!(
            err.message.starts_with("Commit or roll back first"),
            "{err}"
        );
        let left: i64 = conn
            .query_row_as("select count(*) from dbcraft_exp_c", &[])
            .unwrap();
        assert_eq!(left, 19999, "the delete still pending");
        conn.rollback().unwrap();

        conn.execute("drop table dbcraft_exp_c purge", &[]).unwrap();
        std::fs::remove_dir_all(folder).unwrap();
    }

    /// The ranges' conditions, and a filter after them on a line of its
    /// own, so that a `--` comment ends with it.
    #[test]
    fn range_queries() {
        let select = "select a from s.t";
        assert_eq!(range_query(select, None, None, None), select);
        assert_eq!(
            range_query(select, Some("AAA"), Some("BBB"), Some("a > 1 -- big")),
            "select a from s.t where rowid >= chartorowid('AAA') and rowid < \
             chartorowid('BBB') and (\na > 1 -- big\n)"
        );
        assert_eq!(
            range_query(select, None, Some("BBB"), None),
            "select a from s.t where rowid < chartorowid('BBB')"
        );
    }
}
