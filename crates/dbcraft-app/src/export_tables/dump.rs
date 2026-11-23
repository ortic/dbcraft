//! *One file*: the tables as one SQL script that the database's own client
//! imports elsewhere (`mysql db < dump.sql`, `psql`, `sqlcmd`, `sqlite3`,
//! SQL*Plus): a header that sets the session up for the import, per table
//! its DDL (after the DROPs of all of them, when asked for) and its rows in
//! transactions of a few thousand, a footer that sets the session back.
//! The tables come in the order their foreign keys need, the ones they
//! reference first.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use dbcraft_db::{DbError, Dialect};

use crate::to_file::{Around, SharedFile};

/// Rows a transaction of the import takes: `commit` after so many.
pub const COMMIT_EVERY: u64 = 10_000;

/// Rows one INSERT takes (`insert … values (…), (…)`).
pub const ROWS_PER_INSERT: usize = 100;

/// The dump being written: into `<name>.part`, which becomes the file once
/// it is complete. Dropped before, it removes the part.
pub struct Dump {
    pub path: PathBuf,
    part: PathBuf,
    pub file: SharedFile,
    done: bool,
}

impl Dump {
    /// Creates the file and writes `header`.
    pub fn create(path: &Path, header: &str) -> Result<Self, DbError> {
        let part = crate::to_file::part_path(path);
        let io = |e: std::io::Error| DbError::new(format!("{}: {e}", path.display()));
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let mut out = BufWriter::with_capacity(1 << 20, File::create(&part).map_err(io)?);
        out.write_all(header.as_bytes()).map_err(io)?;
        Ok(Self {
            path: path.to_owned(),
            part,
            file: Arc::new(Mutex::new(Some(out))),
            done: false,
        })
    }

    /// Writes `footer` and gives the file its name.
    pub fn finish(mut self, footer: &str) -> Result<(), DbError> {
        let io = |e: std::io::Error| DbError::new(format!("{}: {e}", self.path.display()));
        let mut out = self.file.lock().expect("dump file").take().ok_or_else(|| {
            DbError::new(format!("{}: a table wasn't written", self.path.display()))
        })?;
        out.write_all(footer.as_bytes()).map_err(io)?;
        out.flush().map_err(io)?;
        drop(out);
        std::fs::rename(&self.part, &self.path).map_err(io)?;
        self.done = true;
        Ok(())
    }
}

impl Drop for Dump {
    fn drop(&mut self) {
        if !self.done {
            self.file.lock().expect("dump file").take();
            let _ = std::fs::remove_file(&self.part);
        }
    }
}

/// A table of the dump: its name and, when asked for, its DDL.
pub struct Part<'a> {
    pub name: &'a str,
    pub ddl: Option<&'a str>,
}

/// The name a DROP and a comment give the table: with its schema where
/// the DDL names it so (PostgreSQL, SQL Server), as it is elsewhere.
fn table_name(dialect: Dialect, schema: &str, table: &str) -> String {
    match dialect {
        Dialect::POSTGRES | Dialect::SQLSERVER => format!(
            "{}.{}",
            dialect.quote_ident(schema),
            dialect.quote_ident(table)
        ),
        // As its INSERTs name it: lowercase, unless it needs quotes.
        Dialect::ORACLE => dbcraft_data::identifier(table),
        _ => dialect.quote_ident(table),
    }
}

fn begin(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::MYSQL => "start transaction;\n",
        Dialect::SQLSERVER => "begin transaction;\n",
        // A transaction begins with the first INSERT.
        Dialect::ORACLE => "",
        _ => "begin;\n",
    }
}

fn commit(dialect: Dialect) -> &'static str {
    match dialect {
        // A batch of its own: sqlcmd doesn't read the whole dump at once.
        Dialect::SQLSERVER => "commit;\nGO\n",
        _ => "commit;\n",
    }
}

/// The dump's start: what it is, how to import it, the session set up for
/// the import, then with `drop` the DROPs of every table, the ones that
/// reference others first.
pub fn header(
    dialect: Dialect,
    schema: &str,
    tables: &[Part],
    drop: bool,
    cycle: &[String],
) -> String {
    let what = match dialect {
        Dialect::MYSQL => "database",
        _ => "schema",
    };
    let mut out = format!(
        "-- DbCraft {} dump of {what} {schema}: {} table(s), {}\n",
        env!("CARGO_PKG_VERSION"),
        tables.len(),
        chrono::Local::now().format("%Y-%m-%d %H:%M"),
    );
    let import = match dialect {
        Dialect::MYSQL => "mysql -u <user> -p <database> < <this file>",
        Dialect::POSTGRES => "psql -U <user> -d <database> -f <this file>",
        Dialect::SQLSERVER => "sqlcmd -S <server> -d <database> -i <this file>",
        Dialect::ORACLE => "sqlplus <user>@<database> @<this file>",
        _ => "sqlite3 <database file> < <this file>",
    };
    out.push_str(&format!("-- Import: {import}\n"));
    if !cycle.is_empty() {
        out.push_str(&format!(
            "-- These tables reference each other: {}. Their foreign keys may have to wait \
             until all rows are in.\n",
            cycle.join(", ")
        ));
    }
    out.push('\n');
    out.push_str(match dialect {
        // As mysqldump: the rows' bytes are UTF-8, foreign and unique keys
        // aren't checked while the rows come, an id 0 stays 0.
        Dialect::MYSQL => {
            "set names utf8mb4;\n\
             set @old_foreign_key_checks = @@foreign_key_checks, foreign_key_checks = 0;\n\
             set @old_unique_checks = @@unique_checks, unique_checks = 0;\n\
             set @old_sql_mode = @@sql_mode, sql_mode = 'NO_AUTO_VALUE_ON_ZERO';\n"
        }
        // The DDL names the schema; the rows go there too.
        Dialect::POSTGRES => {
            "set client_encoding = 'UTF8';\nset standard_conforming_strings = on;\n"
        }
        Dialect::SQLSERVER => "set nocount on;\nGO\n",
        // `&` in a value is no substitution variable.
        Dialect::ORACLE => "set define off\n",
        _ => "pragma foreign_keys = off;\n",
    });
    // The schema the DDL names, where it isn't the one every database has.
    let ddl = tables.iter().any(|t| t.ddl.is_some());
    match dialect {
        Dialect::POSTGRES => {
            let quoted = dialect.quote_ident(schema);
            if ddl && schema != "public" {
                out.push_str(&format!("create schema if not exists {quoted};\n"));
            }
            out.push_str(&format!("set search_path = {quoted};\n"));
        }
        Dialect::SQLSERVER if ddl && !schema.eq_ignore_ascii_case("dbo") => {
            out.push_str(&format!(
                "if schema_id(N'{}') is null exec(N'create schema {}');\nGO\n",
                schema.replace('\'', "''"),
                dialect.quote_ident(schema).replace('\'', "''")
            ));
        }
        _ => {}
    }
    if drop {
        out.push('\n');
        for table in tables.iter().rev() {
            let name = table_name(dialect, schema, table.name);
            out.push_str(&match dialect {
                Dialect::ORACLE => format!(
                    "begin\n  execute immediate 'drop table {} cascade constraints purge';\n\
                     exception\n  when others then\n    if sqlcode <> -942 then raise; end if;\n\
                     end;\n/\n",
                    name.replace('\'', "''")
                ),
                _ => format!("drop table if exists {name};\n"),
            });
        }
        if dialect == Dialect::SQLSERVER {
            out.push_str("GO\n");
        }
    }
    out
}

/// What goes around a table's rows: a comment, its DDL, its rows in
/// transactions of [`COMMIT_EVERY`]; on PostgreSQL its sequences set past
/// the ids it holds (`sequenced`: the columns that take theirs from one).
pub fn around(dialect: Dialect, schema: &str, table: &Part, sequenced: &[String]) -> Around {
    let name = table_name(dialect, schema, table.name);
    let mut before = format!("\n-- Table {name}\n");
    if let Some(ddl) = table.ddl {
        let ddl = ddl.trim_end();
        before.push_str(ddl);
        // Oracle's DDL has its terminator, or none (a `/` alone ends a
        // block); SQL Server's ends its batch with `GO`.
        let ended = super::others::ends_statement(ddl) || ddl.ends_with("\n/");
        before.push_str(if ended { "\n" } else { ";\n" });
        let go = ddl
            .rsplit('\n')
            .next()
            .is_some_and(|last| last.trim().eq_ignore_ascii_case("go"));
        if dialect == Dialect::SQLSERVER && !go {
            before.push_str("GO\n");
        }
    }
    before.push_str(begin(dialect));
    let mut after = commit(dialect).to_owned();
    if dialect == Dialect::POSTGRES {
        for column in sequenced {
            let column = dialect.quote_ident(column);
            let target = name.replace('\'', "''");
            after.push_str(&format!(
                "select setval(pg_get_serial_sequence('{target}', '{}'), coalesce(max({column}), 1), \
                 max({column}) is not null) from {name};\n",
                column.replace('\'', "''")
            ));
        }
    }
    Around {
        before,
        after,
        every: Some((
            COMMIT_EVERY,
            format!("{}{}", commit(dialect), begin(dialect)),
        )),
    }
}

/// The dump's end: the session as it was.
pub fn footer(dialect: Dialect, rows: u64) -> String {
    let reset = match dialect {
        Dialect::MYSQL => {
            "set sql_mode = @old_sql_mode;\n\
             set unique_checks = @old_unique_checks;\n\
             set foreign_key_checks = @old_foreign_key_checks;\n"
        }
        Dialect::ORACLE => "set define on\n",
        Dialect::SQLITE => "pragma foreign_keys = on;\n",
        _ => "",
    };
    format!("\n{reset}-- {rows} row(s)\n")
}

/// The tables in an order their foreign keys can be created and filled
/// in: a table after the ones it references (`edges`: referencing,
/// referenced), else in the order they come. Tables that reference each
/// other come in their order, named in the second list.
pub fn dependency_order(
    tables: &[String],
    edges: &[(String, String)],
) -> (Vec<usize>, Vec<String>) {
    let index = |name: &str| tables.iter().position(|t| t == name);
    // The tables each references, of these and other than itself.
    let mut parents: Vec<Vec<usize>> = vec![Vec::new(); tables.len()];
    for (child, parent) in edges {
        if let (Some(c), Some(p)) = (index(child), index(parent))
            && c != p
            && !parents[c].contains(&p)
        {
            parents[c].push(p);
        }
    }
    let mut placed = vec![false; tables.len()];
    let mut order = Vec::with_capacity(tables.len());
    let mut cycle = Vec::new();
    while order.len() < tables.len() {
        let ready =
            (0..tables.len()).find(|&t| !placed[t] && parents[t].iter().all(|&p| placed[p]));
        let next = match ready {
            Some(t) => t,
            // Only tables in a cycle (or after one) are left: the first.
            None => {
                let t = (0..tables.len()).find(|&t| !placed[t]).expect("one left");
                for &p in &parents[t] {
                    if !placed[p] && !cycle.contains(&tables[p]) {
                        cycle.push(tables[p].clone());
                    }
                }
                if !cycle.contains(&tables[t]) {
                    cycle.push(tables[t].clone());
                }
                t
            }
        };
        placed[next] = true;
        order.push(next);
    }
    (order, cycle)
}

/// The foreign keys among the tables of `schema` (MySQL's database), as
/// (referencing, referenced) pairs; the query's parameter is the schema.
pub fn foreign_keys_sql(dialect: Dialect) -> Option<&'static str> {
    Some(match dialect {
        Dialect::MYSQL => {
            "select table_name, referenced_table_name
               from information_schema.referential_constraints
              where constraint_schema = ? and unique_constraint_schema = constraint_schema"
        }
        Dialect::POSTGRES => {
            "select c.relname, p.relname
               from pg_constraint k
               join pg_class c on c.oid = k.conrelid
               join pg_namespace n on n.oid = c.relnamespace
               join pg_class p on p.oid = k.confrelid
              where k.contype = 'f' and n.nspname = $1 and p.relnamespace = c.relnamespace"
        }
        Dialect::SQLSERVER => {
            "select object_name(f.parent_object_id), object_name(f.referenced_object_id)
               from sys.foreign_keys f
              where f.schema_id = schema_id(@P1)
                and object_schema_name(f.referenced_object_id) = @P1"
        }
        Dialect::ORACLE => {
            "select c.table_name, p.table_name
               from all_constraints c
               join all_constraints p
                 on p.owner = c.r_owner and p.constraint_name = c.r_constraint_name
              where c.owner = :1 and c.constraint_type = 'R' and c.r_owner = c.owner"
        }
        // SQLite: per table, pragma_foreign_key_list.
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn edges(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    }

    #[test]
    fn referenced_tables_first() {
        let tables = names(&["items", "orders", "products", "customers"]);
        let fks = edges(&[
            ("items", "orders"),
            ("items", "products"),
            ("orders", "customers"),
            ("orders", "orders"),
            ("orders", "elsewhere"),
        ]);
        let (order, cycle) = dependency_order(&tables, &fks);
        let order: Vec<&str> = order.iter().map(|&i| tables[i].as_str()).collect();
        assert_eq!(order, ["products", "customers", "orders", "items"]);
        assert!(cycle.is_empty());

        let tables = names(&["a", "b", "c", "d"]);
        let (order, cycle) =
            dependency_order(&tables, &edges(&[("a", "b"), ("b", "a"), ("c", "a")]));
        // d needs none; then the cycle as it comes, and c after its a.
        assert_eq!(order, [3, 0, 1, 2]);
        assert_eq!(cycle, ["b", "a"]);
    }

    #[test]
    fn mysql_dump_text() {
        let tables = [
            Part {
                name: "customers",
                ddl: Some("CREATE TABLE `customers` (id int);"),
            },
            Part {
                name: "order",
                ddl: Some("CREATE TABLE `order` (id int)"),
            },
        ];
        let header = header(Dialect::MYSQL, "shop", &tables, true, &[]);
        assert!(header.contains("database shop: 2 table(s)"), "{header}");
        assert!(header.contains("foreign_key_checks = 0"), "{header}");
        let drops = header.find("drop table if exists `order`;").unwrap();
        assert!(drops < header.find("drop table if exists customers;").unwrap());
        let around = around(Dialect::MYSQL, "shop", &tables[1], &[]);
        assert_eq!(
            around.before,
            "\n-- Table `order`\nCREATE TABLE `order` (id int);\nstart transaction;\n"
        );
        assert_eq!(around.after, "commit;\n");
        assert_eq!(
            around.every,
            Some((COMMIT_EVERY, "commit;\nstart transaction;\n".into()))
        );
        assert!(footer(Dialect::MYSQL, 3).contains("foreign_key_checks = @old"));
    }

    #[test]
    fn postgres_sequences_follow_the_rows() {
        let table = Part {
            name: "Orders",
            ddl: None,
        };
        let around = around(Dialect::POSTGRES, "shop", &table, &["id".into()]);
        assert_eq!(
            around.after,
            "commit;\nselect setval(pg_get_serial_sequence('shop.\"Orders\"', 'id'), \
             coalesce(max(id), 1), max(id) is not null) from shop.\"Orders\";\n"
        );
    }
}
