//! Export tables on the databases other than Oracle: MySQL and MariaDB,
//! PostgreSQL, SQL Server and SQLite. The window lists the tables with a
//! task on the session; the rows of each table stream into its file from
//! the session itself ([`dbcraft_db::DbRequest::ExecuteInto`]), one table
//! after the other. Each table is one query, which keeps its snapshot as
//! long as it runs (none of these has Oracle's ORA-01555), so a table needs
//! no chunks; *Consistent* reads all of them in one transaction.

use std::path::{Path, PathBuf};

use dbcraft_db::{Client, DbError, Dialect, MetaQuery, MetaResult, ObjectType, RunFn};

use super::{Choice, Job};

/// A table's columns as the export reads them.
#[derive(Debug, Clone)]
pub struct Table {
    pub name: String,
    /// All columns, invisible ones too (MySQL's `select *` leaves them out).
    pub columns: Vec<String>,
    /// The columns the database computes, which INSERTs leave out.
    pub generated: Vec<String>,
    /// Identity columns that take a value only when told to.
    pub identity: Vec<String>,
}

/// What the export reads before the rows: the tables' columns, their DDL
/// written next to the data files.
#[derive(Debug)]
pub struct Prepared {
    pub schema: String,
    pub tables: Vec<Table>,
}

/// The database typed, or the session's current one.
fn schema(client: &mut dyn Client, typed: &str) -> Result<String, DbError> {
    if !typed.is_empty() {
        return Ok(typed.to_owned());
    }
    let dialect = client.dialect();
    let sql = match dialect {
        Dialect::MYSQL => "select database()",
        Dialect::POSTGRES => "select current_schema()",
        Dialect::SQLSERVER => "select schema_name()",
        _ => return Ok("main".to_owned()),
    };
    let rows = client.query(sql, &[])?;
    rows.into_iter()
        .next()
        .and_then(|row| row.into_iter().next().flatten())
        .ok_or_else(|| {
            DbError::new(if dialect == Dialect::MYSQL {
                "No database selected: type the one to export from"
            } else {
                "No current schema: type the one to export from"
            })
        })
}

/// The tables of `schema` and the rows the database estimates they have
/// (SQLite keeps no count); the schema is the query's only parameter.
fn tables_sql(dialect: Dialect, schema: &str) -> String {
    match dialect {
        Dialect::MYSQL => "select table_name, table_rows from information_schema.tables
                            where table_schema = ? and table_type = 'BASE TABLE'
                            order by table_name"
            .into(),
        // Partitioned tables, not their partitions; -1 is never analyzed.
        Dialect::POSTGRES => "select c.relname,
                                     case when c.reltuples >= 0 then c.reltuples::bigint end
                                from pg_class c
                                join pg_namespace n on n.oid = c.relnamespace
                               where n.nspname = $1 and c.relkind in ('r', 'p')
                                 and not c.relispartition
                               order by c.relname"
            .into(),
        Dialect::SQLSERVER => "select t.name,
                                      (select sum(p.rows) from sys.partitions p
                                        where p.object_id = t.object_id
                                          and p.index_id in (0, 1))
                                 from sys.tables t
                                 join sys.schemas s on s.schema_id = t.schema_id
                                where s.name = @P1
                                order by t.name"
            .into(),
        _ => format!(
            "select name, null from {}.sqlite_master
              where type = 'table' and name not like 'sqlite\\_%' escape '\\'
              order by name",
            dialect.quote_ident(schema)
        ),
    }
}

/// The tables of database `owner` (empty: the current one), with the row
/// counts the server estimates.
pub fn load_tables(owner: String) -> RunFn {
    Box::new(move |client| {
        let schema = schema(client, &owner)?;
        let dialect = client.dialect();
        let sql = tables_sql(dialect, &schema);
        let params: &[&str] = if dialect == Dialect::SQLITE {
            &[]
        } else {
            &[&schema]
        };
        let tables: Vec<Choice> = client
            .query(&sql, params)?
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

/// A table's columns in order: each its name, whether the database
/// computes it (1) and whether it is an identity that takes a value only
/// when told to (1).
fn columns(client: &mut dyn Client, schema: &str, table: &str) -> Result<Table, DbError> {
    let dialect = client.dialect();
    let rows = match dialect {
        Dialect::MYSQL => client.query(
            "select column_name,
                    case when coalesce(generation_expression, '') <> '' then 1 else 0 end, 0
               from information_schema.columns
              where table_schema = ? and table_name = ?
              order by ordinal_position",
            &[schema, table],
        )?,
        Dialect::POSTGRES => client.query(
            "select a.attname,
                    case when a.attgenerated <> '' then 1 else 0 end,
                    case when a.attidentity = 'a' then 1 else 0 end
               from pg_attribute a
               join pg_class c on c.oid = a.attrelid
               join pg_namespace n on n.oid = c.relnamespace
              where n.nspname = $1 and c.relname = $2
                and a.attnum > 0 and not a.attisdropped
              order by a.attnum",
            &[schema, table],
        )?,
        // A rowversion takes no value either.
        Dialect::SQLSERVER => client.query(
            "select c.name,
                    case when c.is_computed = 1 or ty.name = 'timestamp' then 1 else 0 end,
                    cast(c.is_identity as int)
               from sys.columns c
               join sys.types ty on ty.user_type_id = c.user_type_id
              where c.object_id = object_id(@P1)
              order by c.column_id",
            &[&qualified(dialect, schema, table)],
        )?,
        // Hidden 1 is a virtual table's hidden column, 2 and 3 generated.
        _ => client.query(
            "select name, case when hidden in (2, 3) then 1 else 0 end, 0
               from pragma_table_xinfo(?, ?)
              where hidden <> 1
              order by cid",
            &[table, schema],
        )?,
    };
    let mut found = Table {
        name: table.to_owned(),
        columns: Vec::new(),
        generated: Vec::new(),
        identity: Vec::new(),
    };
    for row in rows {
        let mut row = row.into_iter();
        let Some(column) = row.next().flatten() else {
            continue;
        };
        if row.next().flatten().as_deref() == Some("1") {
            found.generated.push(column.clone());
        }
        if row.next().flatten().as_deref() == Some("1") {
            found.identity.push(column.clone());
        }
        found.columns.push(column);
    }
    if found.columns.is_empty() {
        return Err(DbError::new("no such table"));
    }
    Ok(found)
}

/// Begins the transaction a consistent export reads all tables in: as the
/// database was when it began (SQLite: when it first reads).
fn begin(client: &mut dyn Client) -> Result<(), DbError> {
    match client.dialect() {
        Dialect::MYSQL => client.execute("start transaction with consistent snapshot, read only"),
        Dialect::POSTGRES => {
            client.execute("start transaction isolation level repeatable read, read only")
        }
        Dialect::SQLSERVER => {
            client.execute("set transaction isolation level snapshot; begin transaction")
        }
        _ => client.execute("begin"),
    }
}

/// Reads the tables' columns and writes their DDL when asked to; with
/// `consistent`, begins the transaction the rows are read in, last, so
/// that its snapshot is the moment the rows start.
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
            let table = columns(client, &schema, &job.table).map_err(named)?;
            if include_ddl {
                let ddl = match client
                    .meta(&MetaQuery::Ddl {
                        owner: schema.clone(),
                        name: job.table.clone(),
                        object_type: ObjectType::Table,
                    })
                    .map_err(named)?
                {
                    MetaResult::Text(ddl) => ddl,
                    _ => String::new(),
                };
                let path = folder.join(format!("{}.ddl.sql", file_stem(&job.table)));
                let ddl = ddl.trim_end();
                let end = if ddl.ends_with(';') { "\n" } else { ";\n" };
                std::fs::write(&path, format!("{ddl}{end}"))
                    .map_err(|e| DbError::new(format!("{}: {e}", path.display())))?;
            }
            tables.push(table);
        }
        if consistent {
            begin(client).map_err(|e| began(client.dialect(), e))?;
        }
        Ok(Box::new(Prepared { schema, tables }) as Box<dyn std::any::Any + Send>)
    })
}

/// Ends the transaction of a consistent export; it changed nothing.
pub fn end_transaction() -> RunFn {
    Box::new(|client| {
        let sql = match client.dialect() {
            // Back to the isolation sessions have, also when a failed read
            // ended the transaction already.
            Dialect::SQLSERVER => {
                "set transaction isolation level read committed; \
                 if @@trancount > 0 rollback"
            }
            _ => "rollback",
        };
        client.execute(sql)?;
        Ok(Box::new(()) as Box<dyn std::any::Any + Send>)
    })
}

/// SQL Server's snapshot isolation is off for the database (3952 when the
/// transaction first reads).
const SNAPSHOT_OFF: i32 = 3952;

fn began(dialect: Dialect, error: DbError) -> DbError {
    match (dialect, error.code) {
        (Dialect::SQLSERVER, Some(SNAPSHOT_OFF)) => snapshot_off(&error),
        _ => error,
    }
}

fn snapshot_off(error: &DbError) -> DbError {
    DbError::new(format!(
        "{}: a consistent export needs snapshot isolation (ALTER DATABASE … SET \
         ALLOW_SNAPSHOT_ISOLATION ON); or export table by table",
        error.text()
    ))
}

/// What a failed table says: what to do when the snapshot can't read it.
pub fn failed(dialect: Dialect, table: &str, error: &DbError) -> DbError {
    // MySQL's ER_TABLE_DEF_CHANGED, SQL Server's 3961: the table was changed
    // (DDL) after the consistent snapshot began.
    let changed = matches!(
        (dialect, error.code),
        (Dialect::MYSQL, Some(1412)) | (Dialect::SQLSERVER, Some(3961))
    );
    if changed {
        return DbError::new(format!(
            "{table}: {}: the table was changed (DDL) after the export began: export again",
            error.text()
        ));
    }
    if dialect == Dialect::SQLSERVER && error.code == Some(SNAPSHOT_OFF) {
        return DbError::new(format!("{table}: {}", snapshot_off(error).message));
    }
    DbError::new(format!("{table}: {}", error.text()))
}

fn qualified(dialect: Dialect, schema: &str, table: &str) -> String {
    format!(
        "{}.{}",
        dialect.quote_ident(schema),
        dialect.quote_ident(table)
    )
}

/// The query of a table's rows: its columns by name, the WHERE clause on
/// lines of its own, so that a comment at its end ends there.
pub fn select(dialect: Dialect, schema: &str, table: &Table, filter: Option<&str>) -> String {
    let columns = table
        .columns
        .iter()
        .map(|c| dialect.quote_ident(c))
        .collect::<Vec<_>>()
        .join(", ");
    let from = qualified(dialect, schema, &table.name);
    match filter {
        Some(filter) => format!("select {columns} from {from} where (\n{filter}\n)"),
        None => format!("select {columns} from {from}"),
    }
}

/// The file name of table `name`, without extension. These databases'
/// names are mostly lowercase: their files are named as they are (`orders`
/// → `orders`), where [`crate::object_files::file_stem`] would mark them
/// as Oracle's quoted names; a letter in uppercase is marked instead
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
            identity: vec![],
        };
        assert_eq!(
            select(Dialect::MYSQL, "shop", &table, None),
            "select id, `total sum` from shop.`order`"
        );
        assert_eq!(
            select(Dialect::MYSQL, "shop", &table, Some("id > 3 -- big")),
            "select id, `total sum` from shop.`order` where (\nid > 3 -- big\n)"
        );
        assert_eq!(
            select(Dialect::POSTGRES, "public", &table, None),
            "select id, \"total sum\" from public.\"order\""
        );
        assert_eq!(
            select(Dialect::SQLSERVER, "dbo", &table, None),
            "select id, [total sum] from dbo.[order]"
        );
    }
}
