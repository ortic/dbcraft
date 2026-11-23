//! Export tables: several tables at once, each with an optional WHERE
//! clause, one file per table (optionally with its DDL) or INSERTs as one
//! SQL dump to import elsewhere ([`dump`]), streamed so table size doesn't
//! matter. Oracle's tables are read by a task on the session; the other
//! databases' stream from the session itself ([`others`]).

mod dump;
mod others;

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
    /// INSERTs as one file, a dump to import with the database's client,
    /// instead of a file per table.
    #[serde(default)]
    pub single_file: bool,
    /// The dump's file.
    #[serde(default, with = "crate::serde_path::option")]
    pub file: Option<PathBuf>,
    /// The dump drops the tables before it creates them (with their DDL).
    #[serde(default)]
    pub drop_tables: bool,
    /// How the tables are listed.
    #[serde(default)]
    pub sort: SortBy,
    #[serde(default)]
    pub descending: bool,
    #[serde(skip)]
    state: State,
}

/// The column the tables are sorted by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SortBy {
    #[default]
    Name,
    Rows,
    Size,
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
            single_file: false,
            file: None,
            drop_tables: false,
            sort: SortBy::default(),
            descending: false,
            state: State::default(),
        }
    }
}

#[derive(Default)]
struct State {
    /// The connection's database, as the window last drew (Oracle until it
    /// did).
    dialect: Option<Dialect>,
    /// The MySQL session's time zone, which its INSERT scripts set (#213).
    time_zone: Option<String>,
    tables: Option<Result<Vec<Choice>, String>>,
    tables_request: Option<u64>,
    filter: String,
    picking: Option<Receiver<Option<PathBuf>>>,
    /// The dump's file being chosen.
    picking_file: Option<Receiver<Option<PathBuf>>>,
    run: Option<Run>,
    message: Option<(bool, String)>,
}

#[derive(Debug, Clone, Default)]
pub struct Choice {
    pub name: String,
    pub rows: Option<i64>,
    /// The bytes it takes with its indexes, as the catalog says.
    pub bytes: Option<i64>,
    pub selected: bool,
    pub filter: String,
}

struct Run {
    /// The request running: the task, or on the other databases the table
    /// being read.
    id: u64,
    progress: Arc<Progress>,
    streamed: Option<Streamed>,
}

/// An export on a database other than Oracle: the tables' columns first,
/// then one table after the other.
struct Streamed {
    dialect: Dialect,
    settings: Settings,
    jobs: Vec<Job>,
    prepared: Option<others::Prepared>,
    /// The table being read.
    next: usize,
    /// One file for all tables, once the tables are prepared.
    dump: Option<dump::Dump>,
}

#[derive(Default)]
pub struct Progress {
    pub tables_done: AtomicUsize,
    pub tables: AtomicUsize,
    pub rows: AtomicU64,
    pub current: Mutex<String>,
    pub stop: AtomicBool,
    /// The rows of the table being written, on the databases other than
    /// Oracle; `rows` has the tables' before it.
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
    /// INSERTs into this one file instead of a file per table in `folder`.
    pub dump: Option<PathBuf>,
    /// The dump drops the tables first.
    pub drop_tables: bool,
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
                bytes: None,
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

    fn oracle(&self) -> bool {
        self.dialect() == Dialect::ORACLE
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
        if !self.oracle() {
            let task = others::load_tables(owner);
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
            let tables = oracle_tables(conn, &owner)?;
            Ok(Box::new(tables) as Box<dyn std::any::Any + Send>)
        });
        effects.request(Target::Own, DbRequest::Task { id, task });
        effects
    }

    /// Whether the rows go into one dump file.
    fn dumping(&self) -> bool {
        self.format == Format::Insert && self.single_file
    }

    /// Where the export writes: the dump's file, or the folder.
    fn destination(&self) -> Option<&Path> {
        if self.dumping() {
            self.file.as_deref()
        } else {
            self.folder.as_deref()
        }
    }

    fn start(&mut self) -> Effects {
        let mut effects = Effects::default();
        let dump = self.dumping().then(|| self.file.clone());
        let (folder, dump) = match dump {
            Some(Some(file)) => (
                file.parent().unwrap_or(Path::new("")).to_owned(),
                Some(file),
            ),
            Some(None) => return effects,
            None => match &self.folder {
                Some(folder) => (folder.clone(), None),
                None => return effects,
            },
        };
        let Some(Ok(tables)) = &self.state.tables else {
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
            folder,
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
            drop_tables: dump.is_some() && self.include_ddl && self.drop_tables,
            dump,
        };
        let progress = Arc::new(Progress::default());
        let id = request_id();
        self.state.message = None;
        if !self.oracle() {
            let task = others::prepare(
                settings.owner.clone(),
                jobs.clone(),
                settings.folder.clone(),
                settings.include_ddl,
                settings.read == Read::Consistent,
                settings.dump.is_some(),
            );
            self.state.run = Some(Run {
                id,
                progress,
                streamed: Some(Streamed {
                    dialect: self.dialect(),
                    settings,
                    jobs,
                    prepared: None,
                    next: 0,
                    dump: None,
                }),
            });
            effects.request(Target::Own, DbRequest::Run { id, task });
            return effects;
        }
        self.state.run = Some(Run {
            id,
            progress: progress.clone(),
            streamed: None,
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
            .is_some_and(|r| r.id == id && r.streamed.is_some())
        {
            return self.streamed_step(result);
        }
        let to = self
            .destination()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let s = &mut self.state;
        if s.tables_request == Some(id) {
            s.tables_request = None;
            s.tables = Some(match result.map(|a| a.downcast::<Vec<Choice>>()) {
                Ok(Ok(mut t)) => {
                    sort_tables(&mut t, self.sort, self.descending);
                    Ok(*t)
                }
                Ok(Err(_)) => Err("unexpected result".into()),
                Err(e) => Err(e.to_string()),
            });
        } else if let Some(run) = s.run.take_if(|r| r.id == id) {
            let tables = run.progress.tables_done.load(Ordering::Relaxed);
            let stopped = run.progress.stop.load(Ordering::Relaxed);
            s.message = Some(match result.map(|a| a.downcast::<u64>()) {
                Ok(Ok(rows)) => (
                    false,
                    format!("Exported {rows} rows from {tables} table(s) to {to}"),
                ),
                Ok(Err(_)) => (true, "unexpected result".into()),
                Err(_) if stopped => (true, format!("Stopped after {tables} table(s)")),
                Err(e) => (true, e.to_string()),
            });
        }
        Effects::default()
    }

    /// A streamed export's next step, once the one before is done: the
    /// first table once the columns were read, the next once a table is
    /// written.
    fn streamed_step(&mut self, result: dbcraft_db::TaskResult) -> Effects {
        let unexpected = || DbError::new("unexpected result");
        let Some(run) = self.state.run.as_mut() else {
            return Effects::default();
        };
        let progress = run.progress.clone();
        let Some(steps) = run.streamed.as_mut() else {
            return Effects::default();
        };
        let done = match &steps.prepared {
            None => result
                .and_then(|r| r.downcast::<others::Prepared>().map_err(|_| unexpected()))
                .and_then(|prepared| {
                    progress
                        .tables
                        .store(prepared.tables.len(), Ordering::Relaxed);
                    // The jobs in the tables' order, a dump's by its
                    // foreign keys.
                    let mut jobs = std::mem::take(&mut steps.jobs);
                    steps.jobs = prepared
                        .tables
                        .iter()
                        .filter_map(|t| {
                            let i = jobs.iter().position(|j| j.table == t.name)?;
                            Some(jobs.swap_remove(i))
                        })
                        .collect();
                    if let Some(path) = &steps.settings.dump {
                        let parts: Vec<dump::Part> = prepared
                            .tables
                            .iter()
                            .map(|t| dump::Part {
                                name: &t.name,
                                ddl: t.ddl.as_deref(),
                            })
                            .collect();
                        let header = dump::header(
                            steps.dialect,
                            &prepared.schema,
                            &parts,
                            steps.settings.drop_tables,
                            &prepared.cycle,
                        );
                        steps.dump = Some(dump::Dump::create(path, &header)?);
                    }
                    steps.prepared = Some(*prepared);
                    Ok(())
                }),
            Some(prepared) => {
                let table = &prepared.tables[steps.next].name;
                result
                    .map_err(|e| others::failed(steps.dialect, table, &e))
                    .and_then(|r| r.downcast::<u64>().map_err(|_| unexpected()))
                    .map(|rows| {
                        progress.rows.fetch_add(*rows, Ordering::Relaxed);
                        progress.current_rows.store(0, Ordering::Relaxed);
                        progress.tables_done.fetch_add(1, Ordering::Relaxed);
                        steps.next += 1;
                    })
            }
        };
        let next = done.and_then(|()| self.streamed_table());
        match next {
            Ok(Some(effects)) => effects,
            Ok(None) => self.streamed_finish(None),
            Err(e) => self.streamed_finish(Some(e)),
        }
    }

    /// Starts writing the next table; `None` when all are written.
    fn streamed_table(&mut self) -> Result<Option<Effects>, DbError> {
        let time_zone = self.state.time_zone.clone();
        let Some(run) = self.state.run.as_mut() else {
            return Ok(None);
        };
        let Some(steps) = run.streamed.as_ref() else {
            return Ok(None);
        };
        let dialect = steps.dialect;
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
        let options = Options {
            table: dialect.quote_ident(&table.name),
            dialect,
            time_zone: time_zone.filter(|_| dialect == Dialect::MYSQL),
            generated: table.generated.clone(),
            identity: table.identity.clone(),
            ..settings.options.clone()
        };
        let sink = match &steps.dump {
            Some(file) => {
                let part = dump::Part {
                    name: &table.name,
                    ddl: table.ddl.as_deref(),
                };
                crate::to_file::Sink::shared(
                    &file.file,
                    &file.path,
                    settings.format,
                    Options {
                        rows_per_insert: dump::ROWS_PER_INSERT,
                        ..options
                    },
                    dump::around(dialect, &prepared.schema, &part, &table.sequenced),
                    run.progress.current_rows.clone(),
                )?
            }
            None => {
                let path =
                    others::data_path(&settings.folder, &table.name, settings.format.extension());
                crate::to_file::Sink::new(
                    &path,
                    settings.format,
                    options,
                    run.progress.current_rows.clone(),
                )?
            }
        };
        let filter = dbcraft_plsql::tokenize_in(&job.filter, dialect.syntax())
            .iter()
            .any(|t| !t.kind.is_trivia())
            .then_some(job.filter.as_str());
        let sql = others::select(dialect, &prepared.schema, table, filter);
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

    /// Ends a streamed export, the transaction of a consistent one too.
    fn streamed_finish(&mut self, error: Option<DbError>) -> Effects {
        let mut effects = Effects::default();
        let Some(run) = self.state.run.take() else {
            return effects;
        };
        let Some(mut steps) = run.streamed else {
            return effects;
        };
        let p = &run.progress;
        let rows = p.rows.load(Ordering::Relaxed);
        // The dump is complete, or its part goes.
        let error = match (steps.dump.take(), error) {
            (Some(file), None) => file.finish(&dump::footer(steps.dialect, rows)).err(),
            (_, error) => error,
        };
        if steps.settings.read == Read::Consistent && steps.prepared.is_some() {
            let task = others::end_transaction();
            effects.request(
                Target::Own,
                DbRequest::Run {
                    id: request_id(),
                    task,
                },
            );
        }
        let tables = p.tables_done.load(Ordering::Relaxed);
        let to = steps
            .settings
            .dump
            .as_ref()
            .unwrap_or(&steps.settings.folder);
        self.state.message = Some(match error {
            None => (
                false,
                format!(
                    "Exported {rows} rows from {tables} table(s) to {}",
                    to.display()
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
        if let Some(rx) = &self.state.picking_file
            && let Ok(picked) = rx.try_recv()
        {
            self.state.picking_file = None;
            if picked.is_some() {
                self.file = picked;
            }
        }

        let mut reload = false;
        ui.horizontal(|ui| {
            ui.label(if self.dialect() == Dialect::MYSQL {
                "Database"
            } else {
                "Schema"
            });
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
                ui.separator();
                ui.weak(selection_summary(tables));
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
        let hint = match dialect {
            Dialect::ORACLE => "all rows, or e.g. created > sysdate - 30",
            Dialect::MYSQL => "all rows, or e.g. created > now() - interval 30 day",
            Dialect::POSTGRES => "all rows, or e.g. created > now() - interval '30 days'",
            Dialect::SQLSERVER => "all rows, or e.g. created > dateadd(day, -30, getdate())",
            _ => "all rows, or e.g. created > date('now', '-30 days')",
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
                            .num_columns(4)
                            .striped(true)
                            .spacing([16.0, 4.0])
                            .show(ui, |ui| {
                                let mut header =
                                    |ui: &mut Ui, label: &str, by: SortBy, hover: &str| {
                                        let arrow = match (self.sort == by, self.descending) {
                                            (false, _) => "",
                                            (true, false) => " ⏶",
                                            (true, true) => " ⏷",
                                        };
                                        let clicked = ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new(format!("{label}{arrow}"))
                                                        .strong(),
                                                )
                                                .frame(false),
                                            )
                                            .on_hover_text(hover)
                                            .clicked();
                                        if clicked {
                                            // Large first, names A to Z.
                                            self.descending = if self.sort == by {
                                                !self.descending
                                            } else {
                                                by != SortBy::Name
                                            };
                                            self.sort = by;
                                            sort_tables(tables, self.sort, self.descending);
                                        }
                                    };
                                header(ui, "Table", SortBy::Name, "Sort by name");
                                header(
                                    ui,
                                    "Rows",
                                    SortBy::Rows,
                                    "The rows the database's statistics count; sort by them",
                                );
                                header(
                                    ui,
                                    "Size (MB)",
                                    SortBy::Size,
                                    "What the table takes with its indexes, as the database's \
                                     catalog says; sort by it",
                                );
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
                                    ui.weak(t.bytes.map_or_else(|| "?".into(), megabytes));
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
                if self.format == Format::Insert {
                    ui.label("Files");
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.single_file, false, "One per table")
                            .on_hover_text("<table>.sql in a folder, a file for each table");
                        ui.selectable_value(&mut self.single_file, true, "One file")
                            .on_hover_text(
                                "All tables in one script, to import elsewhere with the \
                                 database's own client (mysql, psql, sqlcmd, sqlite3, SQL*Plus): \
                                 the tables after the ones their foreign keys reference, the \
                                 rows a hundred an INSERT and committed every 10,000",
                            );
                    });
                    ui.end_row();
                }
                if self.dumping() {
                    ui.label("File");
                    ui.horizontal(|ui| {
                        match &self.file {
                            Some(f) => {
                                ui.label(RichText::new(f.display().to_string()).monospace());
                            }
                            None => {
                                ui.weak("choose the file to write");
                            }
                        }
                        if ui.button("Choose…").clicked() && self.state.picking_file.is_none() {
                            let name = match self.owner.trim() {
                                "" => "dump.sql".to_owned(),
                                owner => format!("{owner}.sql"),
                            };
                            let (tx, rx) = std::sync::mpsc::channel();
                            std::thread::spawn(move || {
                                let picked = rfd::FileDialog::new()
                                    .add_filter("SQL", &["sql"])
                                    .set_file_name(name)
                                    .save_file();
                                let _ = tx.send(picked);
                            });
                            self.state.picking_file = Some(rx);
                        }
                        ui.checkbox(&mut self.include_ddl, "Include DDL")
                            .on_hover_text("Each table's CREATE TABLE before its rows");
                        ui.add_enabled(
                            self.include_ddl,
                            egui::Checkbox::new(&mut self.drop_tables, "Drop tables first"),
                        )
                        .on_hover_text(
                            "The dump starts with a DROP TABLE of each table, so that it imports \
                             again into a database that has them",
                        );
                    });
                } else {
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
                }
                ui.end_row();
                ui.label("Read");
                let dialect = self.dialect();
                ui.horizontal(|ui| {
                    if dialect != Dialect::ORACLE {
                        ui.selectable_value(&mut self.read, Read::Chunks, "Table by table")
                            .on_hover_text(
                                "Each table is one query, as the table was when it began: \
                                 the database keeps a query's snapshot as long as it runs. \
                                 Tables are read at different moments.",
                            );
                        let consistent = match dialect {
                            Dialect::MYSQL => {
                                "All tables as they were when the export began, in one \
                                 transaction with a consistent snapshot (InnoDB tables: \
                                 MyISAM keeps no versions). The server keeps the old versions \
                                 of rows changed meanwhile until the last table is read."
                            }
                            Dialect::POSTGRES => {
                                "All tables as they were when the export began, in one \
                                 read-only REPEATABLE READ transaction. VACUUM can't remove \
                                 rows changed meanwhile until the last table is read."
                            }
                            Dialect::SQLSERVER => {
                                "All tables as they were when the export began, in one \
                                 SNAPSHOT transaction: the database needs \
                                 ALLOW_SNAPSHOT_ISOLATION ON. tempdb keeps the old versions \
                                 of rows changed meanwhile until the last table is read."
                            }
                            _ => {
                                "All tables as they were when the export began, in one \
                                 transaction. Other connections' writes wait for it unless \
                                 the database is in WAL mode."
                            }
                        };
                        ui.selectable_value(&mut self.read, Read::Consistent, "Consistent")
                            .on_hover_text(consistent);
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
                            selected > 0 && self.destination().is_some(),
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

/// Sorts the tables by `by`: those of unknown rows or size last either
/// way, ties by name.
fn sort_tables(tables: &mut [Choice], by: SortBy, descending: bool) {
    let name = |t: &Choice| t.name.to_lowercase();
    tables.sort_by(|a, b| {
        let key = |t: &Choice| match by {
            SortBy::Name => None,
            SortBy::Rows => Some(t.rows),
            SortBy::Size => Some(t.bytes),
        };
        let order = match (key(a), key(b)) {
            (Some(Some(x)), Some(Some(y))) if descending => y.cmp(&x),
            (Some(Some(x)), Some(Some(y))) => x.cmp(&y),
            (Some(Some(_)), Some(None)) => std::cmp::Ordering::Less,
            (Some(None), Some(Some(_))) => std::cmp::Ordering::Greater,
            _ => std::cmp::Ordering::Equal,
        };
        let names = || match (by, descending) {
            (SortBy::Name, true) => name(b).cmp(&name(a)),
            _ => name(a).cmp(&name(b)),
        };
        order.then_with(names)
    });
}

/// Bytes in megabytes, as the list shows them.
fn megabytes(bytes: i64) -> String {
    let mb = bytes as f64 / (1024.0 * 1024.0);
    if bytes > 0 && mb < 0.1 {
        "< 0.1".into()
    } else {
        format!("{mb:.1}")
    }
}

/// What the selected tables hold, as the statistics say.
fn selection_summary(tables: &[Choice]) -> String {
    let selected: Vec<&Choice> = tables.iter().filter(|t| t.selected).collect();
    let mut text = format!("{} of {} selected", selected.len(), tables.len());
    if selected.is_empty() {
        return text;
    }
    let rows: i64 = selected.iter().filter_map(|t| t.rows).sum();
    let bytes: i64 = selected.iter().filter_map(|t| t.bytes).sum();
    let some = |f: fn(&Choice) -> Option<i64>| selected.iter().any(|t| f(t).is_some());
    if some(|t| t.rows) {
        text.push_str(&format!(" · about {rows} rows"));
    }
    if some(|t| t.bytes) {
        text.push_str(&format!(" · {} MB", megabytes(bytes)));
    }
    text
}

/// The tables of `owner` with the rows their statistics count and the
/// bytes of their segments, indexes and LOBs too: from DBA_SEGMENTS, or
/// USER_SEGMENTS for the user's own tables; without either, no sizes.
fn oracle_tables(conn: &Connection, owner: &str) -> Result<Vec<Choice>, DbError> {
    let tables = "select table_name, num_rows from all_tables
                   where owner = :1 and nested = 'NO' and secondary = 'N'
                     and table_name not like 'BIN$%'";
    let sized = |segments: &str| {
        format!(
            "with seg as (select segment_name, segment_type, bytes from {segments}),
                  sizes as (select segment_name table_name, bytes from seg
                             where segment_type like 'TABLE%'
                            union all
                            select i.table_name, s.bytes from seg s
                              join all_indexes i
                                on i.owner = :2 and i.index_name = s.segment_name
                             where s.segment_type like 'INDEX%'
                            union all
                            select l.table_name, s.bytes from seg s
                              join all_lobs l
                                on l.owner = :3 and l.segment_name = s.segment_name
                             where s.segment_type like 'LOB%')
             select t.table_name, t.num_rows, z.bytes
               from ({tables}) t
               left join (select table_name, sum(bytes) bytes from sizes group by table_name) z
                 on z.table_name = t.table_name
              order by t.table_name"
        )
    };
    let read = |sql: &str,
                binds: &[&dyn dbcraft_db::oracle::sql_type::ToSql]|
     -> Result<Vec<Choice>, DbError> {
        let mut found = Vec::new();
        for row in conn.query_as::<(String, Option<i64>, Option<i64>)>(sql, binds)? {
            let (name, rows, bytes) = row?;
            found.push(Choice {
                name,
                rows,
                bytes,
                selected: false,
                filter: String::new(),
            });
        }
        Ok(found)
    };
    let all = sized(&format!(
        "dba_segments where owner = '{}'",
        owner.replace('\'', "''")
    ));
    match read(&all, &[&owner, &owner, &owner]) {
        Ok(tables) => return Ok(tables),
        Err(e) => tracing::debug!("table sizes from DBA_SEGMENTS: {}", e.text()),
    }
    let user: String = conn.query_row_as("select user from dual", &[])?;
    if user == owner {
        match read(&sized("user_segments"), &[&owner, &owner, &owner]) {
            Ok(tables) => return Ok(tables),
            Err(e) => tracing::debug!("table sizes from USER_SEGMENTS: {}", e.text()),
        }
    }
    let plain = format!("select table_name, num_rows, null from ({tables}) order by table_name");
    read(&plain, &[&owner])
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
    if settings.dump.is_none() {
        std::fs::create_dir_all(&settings.folder)
            .map_err(|e| DbError::new(format!("{}: {e}", settings.folder.display())))?;
    }
    // A dump's tables after the ones they reference.
    let mut cycle = Vec::new();
    let jobs: Vec<Job> = match &settings.dump {
        Some(_) => {
            let sql = dump::foreign_keys_sql(Dialect::ORACLE).expect("Oracle's");
            let edges = conn
                .query_as::<(String, String)>(sql, &[&owner])?
                .collect::<Result<Vec<_>, _>>()?;
            let names: Vec<String> = jobs.iter().map(|j| j.table.clone()).collect();
            let (order, tangled) = dump::dependency_order(&names, &edges);
            cycle = tangled;
            order.iter().map(|&i| jobs[i].clone()).collect()
        }
        None => jobs.to_vec(),
    };
    let jobs = &jobs[..];
    // The DDL first: DBMS_METADATA doesn't run in a read-only transaction.
    let mut ddls: Vec<Option<String>> = vec![None; jobs.len()];
    if settings.include_ddl {
        for (job, kept) in jobs.iter().zip(&mut ddls) {
            if progress.stop.load(Ordering::Relaxed) {
                return Err(DbError::new("stopped"));
            }
            *progress.current.lock().expect("current") = job.table.clone();
            let ddl =
                crate::object_files::object_text(conn, &owner, &job.table, ObjectType::Table)?;
            if settings.dump.is_some() {
                *kept = Some(ddl);
                continue;
            }
            // A file of its own for each table, as Export schema writes (#280).
            let base = crate::object_files::file_stem(&job.table);
            let path = settings.folder.join(format!("{base}.ddl.sql"));
            std::fs::write(&path, ddl)
                .map_err(|e| DbError::new(format!("{}: {e}", path.display())))?;
        }
    }
    let file = match &settings.dump {
        Some(path) => {
            let parts: Vec<dump::Part> = jobs
                .iter()
                .zip(&ddls)
                .map(|(job, ddl)| dump::Part {
                    name: &job.table,
                    ddl: ddl.as_deref(),
                })
                .collect();
            let header = dump::header(
                Dialect::ORACLE,
                &owner,
                &parts,
                settings.drop_tables,
                &cycle,
            );
            Some(dump::Dump::create(path, &header)?)
        }
        None => None,
    };
    let rows = if settings.read == Read::Consistent {
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
        let exported = export_tables(conn, &owner, settings, jobs, &ddls, file.as_ref(), progress);
        // Ends the read-only transaction; it changed nothing.
        let _ = conn.rollback();
        exported.map_err(|e| match e.code {
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
        })?
    } else {
        export_tables(conn, &owner, settings, jobs, &ddls, file.as_ref(), progress)?
    };
    // Dropped on an error, the dump removes its part.
    if let Some(file) = file {
        file.finish(&dump::footer(Dialect::ORACLE, rows))?;
    }
    Ok(rows)
}

/// ORA-01555 "snapshot too old": the undo a query needs to read the rows
/// as they were when it started was overwritten.
const SNAPSHOT_TOO_OLD: i32 = 1555;

/// ORA-01466 "table definition has changed": a read-only transaction can't
/// read a table whose definition is newer than the transaction.
const DEFINITION_CHANGED: i32 = 1466;

/// How often a range of rows is read again after ORA-01555.
const RETRIES: usize = 3;

/// The tables' rows, each table into a file of its own or all into the
/// dump `file`, each with its DDL (`ddls`) there.
fn export_tables(
    conn: &Connection,
    owner: &str,
    settings: &Settings,
    jobs: &[Job],
    ddls: &[Option<String>],
    file: Option<&dump::Dump>,
    progress: &Progress,
) -> Result<u64, DbError> {
    let mut total = 0;
    for (job, ddl) in jobs.iter().zip(ddls) {
        if progress.stop.load(Ordering::Relaxed) {
            return Err(DbError::new("stopped"));
        }
        *progress.current.lock().expect("current") = job.table.clone();
        let into = file.map(|file| {
            let part = dump::Part {
                name: &job.table,
                ddl: ddl.as_deref(),
            };
            (file, dump::around(Dialect::ORACLE, owner, &part, &[]))
        });
        let rows = export_table(conn, owner, settings, job, into, progress).map_err(|e| {
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

type Out = std::io::BufWriter<std::fs::File>;

/// One table's rows into its file, under its name once they are all in it;
/// or into a dump, with what goes around them there.
fn export_table(
    conn: &Connection,
    owner: &str,
    settings: &Settings,
    job: &Job,
    into: Option<(&dump::Dump, crate::to_file::Around)>,
    progress: &Progress,
) -> Result<u64, DbError> {
    use std::io::{Seek, SeekFrom, Write};

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
    let path = match into {
        Some((file, _)) => file.path.clone(),
        None => settings
            .folder
            .join(format!("{base}.{}", settings.format.extension())),
    };
    let io = |e: &dyn std::fmt::Display| DbError::new(format!("{}: {e}", path.display()));
    // Under its name once it is whole: a DbCraft that was killed leaves no
    // file that looks complete.
    let part = crate::to_file::part_path(&path);
    let create = || {
        std::fs::File::create(&part)
            .map(|file| std::io::BufWriter::with_capacity(1 << 20, file))
            .map_err(|e| io(&e))
    };
    // A dump's file, after the tables before; where this table starts in it.
    let (mut out, start, around) = match into {
        Some((file, around)) => {
            let mut out = file
                .file
                .lock()
                .expect("dump file")
                .take()
                .ok_or_else(|| io(&"a table before wasn't written"))?;
            out.write_all(around.before.as_bytes())
                .map_err(|e| io(&e))?;
            out.flush().map_err(|e| io(&e))?;
            let start = out.get_mut().stream_position().map_err(|e| io(&e))?;
            (Some(out), start, Some((file, around)))
        }
        None => (Some(create()?), 0, None),
    };
    let mut writer: Option<StreamWriter<Out>> = None;
    let options = insert_options(settings, &job.table);
    let every = around.as_ref().and_then(|(_, a)| a.every.clone());
    let mut since = 0;
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
                        // A dump commits every so many rows.
                        if let Some((n, text)) = &every {
                            since += rows.len() as u64;
                            if since >= *n {
                                since = 0;
                                w.get_mut().write_all(text.as_bytes()).map_err(|e| io(&e))?;
                            }
                        }
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
                            // Not even the header was written before: the
                            // file as it was before the table.
                            _ if around.is_some() => {
                                let mut back = match (writer.take(), out.take()) {
                                    (Some(w), _) => w.into_inner(),
                                    (None, Some(out)) => out,
                                    (None, None) => return Err(io(&"no file")),
                                };
                                back.flush().map_err(|e| io(&e))?;
                                let file = back.get_mut();
                                file.set_len(start).map_err(|e| io(&e))?;
                                file.seek(SeekFrom::Start(start)).map_err(|e| io(&e))?;
                                out = Some(back);
                            }
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
        let done = match writer.take() {
            Some(w) => Some(w.finish().map_err(|e| io(&e))?),
            None => out.take(),
        };
        match (&around, done) {
            (Some((file, around)), Some(mut done)) => {
                done.write_all(around.after.as_bytes())
                    .map_err(|e| io(&e))?;
                *file.file.lock().expect("dump file") = Some(done);
            }
            (Some(_), None) => return Err(io(&"no file")),
            (None, done) => {
                drop(done);
                std::fs::rename(&part, &path).map_err(|e| io(&e))?;
            }
        }
        Ok(rows)
    });
    if result.is_err() && around.is_none() {
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
            dump: None,
            drop_tables: false,
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
            dump: None,
            drop_tables: false,
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
                dump: None,
                drop_tables: false,
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
            dump: None,
            drop_tables: false,
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

    /// One file on Oracle: the parent before its child, everything dropped
    /// first (the child first), a commit every 10,000 rows, the tables'
    /// indexes but not their keys' (which CREATE TABLE makes); and the dump
    /// imports where it came from, as SQL*Plus runs it.
    #[test]
    fn dumps_into_one_file() {
        let Some(conn) = crate::test_db::connect("DBCRAFT_TEST_DB") else {
            return;
        };
        let drop = |conn: &Connection| {
            for table in ["R55_CHILD", "R55_PARENT", "R55_BIG"] {
                let _ = conn.execute(&format!("drop table {table} purge"), &[]);
            }
        };
        drop(&conn);
        for sql in [
            "create table r55_parent (id number primary key, name varchar2(20))",
            "insert into r55_parent values (1, 'R&D')",
            "insert into r55_parent values (2, 'it''s')",
            "create table r55_child (id number primary key, \
               parent_id number references r55_parent (id))",
            "insert into r55_child values (10, 1)",
            "insert into r55_child values (11, 2)",
            "create table r55_big (n number)",
            "insert into r55_big select level from dual connect by level <= 25000",
            "create index r55_big_n on r55_big (n)",
            "commit",
        ] {
            conn.execute(sql, &[])
                .unwrap_or_else(|e| panic!("{sql}: {e}"));
        }
        let folder = std::env::temp_dir().join(format!("dbcraft-r55-dump-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&folder);
        let path = folder.join("dump.sql");
        let settings = Settings {
            owner: String::new(),
            folder: folder.clone(),
            format: Format::Insert,
            options: Options::default(),
            include_ddl: true,
            read: Read::Chunks,
            // Several ranges of rows, where DBA_EXTENTS or a sample says.
            chunk_bytes: 64 << 10,
            dump: Some(path.clone()),
            drop_tables: true,
        };
        let jobs: Vec<Job> = ["R55_BIG", "R55_CHILD", "R55_PARENT"]
            .iter()
            .map(|name| Job {
                table: (*name).into(),
                filter: String::new(),
            })
            .collect();
        let exported = export(&conn, &settings, &jobs, &Progress::default());
        assert_eq!(exported.map_err(|e| e.message), Ok(25004));
        let dump = std::fs::read_to_string(&path).unwrap();
        assert!(
            !std::fs::read_dir(&folder).unwrap().any(|f| f
                .unwrap()
                .path()
                .extension()
                .is_some_and(|e| e == "part")),
            "no .part file left"
        );
        let at = |needle: &str| {
            dump.find(needle)
                .unwrap_or_else(|| panic!("{needle} not in\n{dump}"))
        };
        assert!(at("set define off") < at("-- Table"));
        assert!(
            at("-- Table r55_parent") < at("-- Table r55_child"),
            "{dump}"
        );
        assert!(
            at("drop table r55_child") < at("drop table r55_parent"),
            "{dump}"
        );
        // Oracle's literals have `&` as chr(38) anyway.
        assert!(dump.contains("'R' || chr(38) || 'D'"), "{dump}");
        // Its own indexes, not the ones of its keys, which CREATE TABLE makes.
        assert!(dump.contains("CREATE INDEX \"R55_BIG_N\""), "{dump}");
        assert!(!dump.contains("SYS_C"), "{dump}");
        assert_eq!(dump.matches("commit;").count(), 2 + 3, "two within R55_BIG");

        // As SQL*Plus runs it: the client's commands aside.
        let statements = dbcraft_plsql::split_statements_in(&dump, dbcraft_plsql::Syntax::Oracle);
        for statement in &statements {
            if statement.kind == dbcraft_plsql::StatementKind::SqlPlus {
                continue;
            }
            let sql = statement.text(&dump);
            conn.execute(sql, &[])
                .unwrap_or_else(|e| panic!("{sql}: {e}"));
        }
        let count = |table: &str| -> i64 {
            conn.query_row_as(&format!("select count(*) from {table}"), &[])
                .unwrap()
        };
        let counts = [count("r55_big"), count("r55_child"), count("r55_parent")];
        let name: String = conn
            .query_row_as("select name from r55_parent where id = 1", &[])
            .unwrap();
        drop(&conn);
        std::fs::remove_dir_all(&folder).unwrap();
        assert_eq!(counts, [25000, 2, 2]);
        assert_eq!(name, "R&D");
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
            dump: None,
            drop_tables: false,
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
            dump: None,
            drop_tables: false,
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
