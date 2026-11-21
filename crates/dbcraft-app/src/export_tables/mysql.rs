//! Export tables on MySQL and MariaDB. The window lists the tables with a
//! task on the session; the rows of each table stream into its file from
//! the session itself ([`DbRequest::ExecuteInto`]), one table after the
//! other. A query keeps its snapshot as long as it runs, so a table needs
//! no chunks; *Consistent* reads all of them in one transaction with a
//! consistent snapshot.

use std::path::{Path, PathBuf};

use dbcraft_db::{Client, DbError, Dialect, RunFn};

use super::{Choice, Job};

/// A table's columns as the export reads them.
#[derive(Debug, Clone)]
pub struct Table {
    pub name: String,
    /// All columns, invisible ones too (`select *` leaves them out).
    pub columns: Vec<String>,
    /// The generated columns, which INSERTs leave out.
    pub generated: Vec<String>,
}

/// What the export reads before the rows: the tables' columns, their DDL
/// written next to the data files.
#[derive(Debug)]
pub struct Prepared {
    pub schema: String,
    pub tables: Vec<Table>,
}

/// ER_TABLE_DEF_CHANGED: a consistent snapshot can't read a table changed
/// (DDL) after the snapshot began.
const DEFINITION_CHANGED: i32 = 1412;

/// The database typed, or the session's current one.
fn schema(client: &mut dyn Client, typed: &str) -> Result<String, DbError> {
    if !typed.is_empty() {
        return Ok(typed.to_owned());
    }
    let rows = client.query("select database()", &[])?;
    rows.into_iter()
        .next()
        .and_then(|row| row.into_iter().next().flatten())
        .ok_or_else(|| DbError::new("No database selected: type the one to export from"))
}

/// The tables of database `owner` (empty: the current one), with the row
/// counts the server estimates.
pub fn load_tables(owner: String) -> RunFn {
    Box::new(move |client| {
        let schema = schema(client, &owner)?;
        let rows = client.query(
            "select table_name, table_rows from information_schema.tables
              where table_schema = ? and table_type = 'BASE TABLE'
              order by table_name",
            &[&schema],
        )?;
        let tables: Vec<Choice> = rows
            .into_iter()
            .filter_map(|row| {
                let mut row = row.into_iter();
                let name = row.next().flatten()?;
                let rows = row.next().flatten().and_then(|r| r.parse().ok());
                Some(Choice {
                    name,
                    rows,
                    selected: false,
                    filter: String::new(),
                })
            })
            .collect();
        Ok(Box::new(tables) as Box<dyn std::any::Any + Send>)
    })
}

/// Reads the tables' columns and writes their DDL (`SHOW CREATE TABLE`)
/// when asked to; with `consistent`, begins the transaction the rows are
/// read in, last, so that its snapshot is the moment the rows start.
pub fn prepare(
    owner: String,
    jobs: Vec<Job>,
    folder: PathBuf,
    include_ddl: bool,
    consistent: bool,
) -> RunFn {
    Box::new(move |client| {
        let schema = schema(client, &owner)?;
        let mut tables = Vec::with_capacity(jobs.len());
        for job in &jobs {
            let named = |e: DbError| DbError::new(format!("{}: {}", job.table, e.text()));
            let rows = client
                .query(
                    "select column_name,
                            case when coalesce(generation_expression, '') <> ''
                                 then 1 else 0 end
                       from information_schema.columns
                      where table_schema = ? and table_name = ?
                      order by ordinal_position",
                    &[&schema, &job.table],
                )
                .map_err(named)?;
            let mut table = Table {
                name: job.table.clone(),
                columns: Vec::new(),
                generated: Vec::new(),
            };
            for row in rows {
                let mut row = row.into_iter();
                let Some(column) = row.next().flatten() else {
                    continue;
                };
                if row.next().flatten().as_deref() == Some("1") {
                    table.generated.push(column.clone());
                }
                table.columns.push(column);
            }
            if table.columns.is_empty() {
                return Err(DbError::new(format!("{}: no such table", job.table)));
            }
            if include_ddl {
                let ddl = client
                    .query(
                        &format!("show create table {}", qualified(&schema, &job.table)),
                        &[],
                    )
                    .map_err(named)?
                    .into_iter()
                    .next()
                    .and_then(|row| row.into_iter().nth(1).flatten())
                    .unwrap_or_default();
                let path = folder.join(format!("{}.ddl.sql", file_stem(&job.table)));
                std::fs::write(&path, format!("{ddl};\n"))
                    .map_err(|e| DbError::new(format!("{}: {e}", path.display())))?;
            }
            tables.push(table);
        }
        if consistent {
            client.execute("start transaction with consistent snapshot, read only")?;
        }
        Ok(Box::new(Prepared { schema, tables }) as Box<dyn std::any::Any + Send>)
    })
}

/// Ends the transaction of a consistent export; it changed nothing.
pub fn end_transaction() -> RunFn {
    Box::new(|client| {
        client.execute("rollback")?;
        Ok(Box::new(()) as Box<dyn std::any::Any + Send>)
    })
}

/// What a failed table says: what to do when the snapshot can't read it.
pub fn failed(table: &str, error: &DbError) -> DbError {
    match error.code {
        Some(DEFINITION_CHANGED) => DbError::new(format!(
            "{table}: {}: the table was changed (DDL) after the export began: export again",
            error.text()
        )),
        _ => DbError::new(format!("{table}: {}", error.text())),
    }
}

fn qualified(schema: &str, table: &str) -> String {
    format!(
        "{}.{}",
        Dialect::MYSQL.quote_ident(schema),
        Dialect::MYSQL.quote_ident(table)
    )
}

/// The query of a table's rows: its columns by name, the WHERE clause on
/// lines of its own, so that a comment at its end ends there.
pub fn select(schema: &str, table: &Table, filter: Option<&str>) -> String {
    let columns = table
        .columns
        .iter()
        .map(|c| Dialect::MYSQL.quote_ident(c))
        .collect::<Vec<_>>()
        .join(", ");
    let from = qualified(schema, &table.name);
    match filter {
        Some(filter) => format!("select {columns} from {from} where (\n{filter}\n)"),
        None => format!("select {columns} from {from}"),
    }
}

/// The file name of table `name`, without extension. MySQL's names are
/// mostly lowercase: their files are named as they are (`orders` →
/// `orders`), where [`crate::object_files::file_stem`] would mark them as
/// Oracle's quoted names; a letter in uppercase is marked instead
/// (`Orders` → `^o^rders`), one file per table also where `Foo` and `foo`
/// are one file.
pub fn file_stem(name: &str) -> String {
    let swapped: String = name
        .chars()
        .map(|c| {
            let other: Vec<char> = if c.is_lowercase() {
                c.to_uppercase().collect()
            } else {
                c.to_lowercase().collect()
            };
            match other.as_slice() {
                [one] => *one,
                _ => c,
            }
        })
        .collect();
    crate::object_files::file_stem(&swapped)
}

/// Where table `name`'s rows go.
pub fn data_path(folder: &Path, name: &str, extension: &str) -> PathBuf {
    folder.join(format!("{}.{extension}", file_stem(name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names() {
        assert_eq!(file_stem("orders"), "orders");
        assert_eq!(file_stem("order_items2"), "order_items2");
        assert_ne!(file_stem("Orders"), file_stem("orders"));
        assert_ne!(file_stem("ORDERS"), file_stem("orders"));
        assert_eq!(file_stem("a.b"), "a%2Eb");
    }

    #[test]
    fn selects() {
        let table = Table {
            name: "order".into(),
            columns: vec!["id".into(), "total sum".into()],
            generated: vec![],
        };
        assert_eq!(
            select("shop", &table, None),
            "select id, `total sum` from shop.`order`"
        );
        assert_eq!(
            select("shop", &table, Some("id > 3 -- big")),
            "select id, `total sum` from shop.`order` where (\nid > 3 -- big\n)"
        );
    }
}
