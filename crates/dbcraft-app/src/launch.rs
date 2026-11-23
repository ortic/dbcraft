//! A connection given on the command line, as `ddev dbcraft` (or another
//! tool's launcher) starts DbCraft:
//!
//! ```text
//! dbcraft mysql://root:root@127.0.0.1:32768/db?name=ddev-shop
//! dbcraft postgres://db:db@127.0.0.1:32769/db
//! ```
//!
//! `mysql://` and `mariadb://` are MySQL's, `postgres://` and
//! `postgresql://` PostgreSQL's. The user and password are percent-encoded,
//! as in any URL; `name` names the connection (by default `user@host…`), the
//! other query parameters are the connect string's. The connection isn't
//! saved: a launcher's port changes from one start to the next.

use dbcraft_config::{ConnectionProfile, DbKind};

use crate::connections::Passwords;
use crate::dialogs::ConnectRequest;

/// The connection the command line asks for: `None` without a connection
/// URL among the arguments (the program's own name left out), an error when
/// the URL can't be used.
pub fn from_args(args: impl IntoIterator<Item = String>) -> Option<Result<ConnectRequest, String>> {
    args.into_iter()
        .find(|a| scheme_kind(a).is_some())
        .map(|a| parse(&a))
}

fn scheme_kind(text: &str) -> Option<DbKind> {
    let (scheme, _) = text.split_once("://")?;
    match scheme.to_ascii_lowercase().as_str() {
        "mysql" | "mariadb" => Some(DbKind::MySql),
        "postgres" | "postgresql" => Some(DbKind::Postgres),
        _ => None,
    }
}

/// The connection of a `mysql://` or `postgres://` URL.
pub fn parse(text: &str) -> Result<ConnectRequest, String> {
    let kind = scheme_kind(text).ok_or_else(|| {
        "A connection on the command line is a mysql://, mariadb://, postgres:// or postgresql:// URL"
            .to_owned()
    })?;
    // Not shown back in errors: it has the password.
    let url =
        url::Url::parse(text).map_err(|e| format!("The connection URL can't be read: {e}"))?;
    let host = match url.host_str() {
        Some(host) if !host.is_empty() => host,
        _ => return Err("The connection URL has no host".to_owned()),
    };
    let decode = |s: &str| {
        percent_encoding::percent_decode_str(s)
            .decode_utf8()
            .map(|s| s.into_owned())
            .map_err(|_| "The connection URL's user or password isn't UTF-8".to_owned())
    };
    let username = decode(url.username())?;
    let password = url.password().map(decode).transpose()?.unwrap_or_default();

    let mut name = String::new();
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    let mut options = false;
    for (key, value) in url.query_pairs() {
        if key == "name" {
            name = value.into_owned();
        } else {
            query.append_pair(&key, &value);
            options = true;
        }
    }

    let mut address = host.to_owned();
    if let Some(port) = url.port() {
        address = format!("{address}:{port}");
    }
    let database = url.path().trim_start_matches('/');
    if !database.is_empty() {
        address = format!("{address}/{}", decode(database)?);
    }
    if options {
        address = format!("{address}?{}", query.finish());
    }
    let connect_string = match kind {
        DbKind::Postgres => format!("postgresql://{address}"),
        _ => address,
    };

    Ok(ConnectRequest {
        profile: ConnectionProfile {
            name,
            kind,
            username,
            connect_string,
            ..Default::default()
        },
        passwords: Passwords {
            database: password,
            ssh: String::new(),
        },
        save_profile: false,
        previous: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn ddev_mysql() {
        let request = parse("mysql://root:root@127.0.0.1:32768/db?name=ddev-shop").unwrap();
        assert_eq!(request.profile.kind, DbKind::MySql);
        assert_eq!(request.profile.name, "ddev-shop");
        assert_eq!(request.profile.username, "root");
        assert_eq!(request.profile.connect_string, "127.0.0.1:32768/db");
        assert_eq!(request.passwords.database, "root");
        assert!(!request.save_profile);
        assert!(!request.profile.save_password);
    }

    #[test]
    fn mariadb_without_database_or_name() {
        let request = parse("mariadb://root@localhost:3307").unwrap();
        assert_eq!(request.profile.kind, DbKind::MySql);
        assert_eq!(request.profile.connect_string, "localhost:3307");
        assert_eq!(request.profile.display_name(), "root@localhost:3307");
        assert_eq!(request.passwords.database, "");
    }

    #[test]
    fn postgres_keeps_its_options() {
        let request =
            parse("postgresql://db:db@127.0.0.1:32769/db?sslmode=disable&name=ddev-shop").unwrap();
        assert_eq!(request.profile.kind, DbKind::Postgres);
        assert_eq!(request.profile.name, "ddev-shop");
        assert_eq!(
            request.profile.connect_string,
            "postgresql://127.0.0.1:32769/db?sslmode=disable"
        );
    }

    #[test]
    fn percent_encoded_credentials() {
        let request = parse("mysql://us%40er:p%40ss%3Aw%2Frd@db.example/app").unwrap();
        assert_eq!(request.profile.username, "us@er");
        assert_eq!(request.passwords.database, "p@ss:w/rd");
        assert_eq!(request.profile.connect_string, "db.example/app");
    }

    #[test]
    fn errors_leave_out_the_password() {
        let e = parse("mysql://root:secret@:99999/db").err().unwrap();
        assert!(!e.contains("secret"), "{e}");
        assert!(parse("oracle://scott:tiger@db/x").is_err());
    }

    #[test]
    fn only_connection_urls_are_taken() {
        assert!(from_args(args(&[])).is_none());
        assert!(from_args(args(&["C:\\scripts\\report.sql"])).is_none());
        let found = from_args(args(&["report.sql", "MySQL://root:root@127.0.0.1/db"]));
        assert_eq!(
            found.unwrap().unwrap().profile.connect_string,
            "127.0.0.1/db"
        );
        assert!(
            from_args(args(&["mysql://root:root@/db"]))
                .unwrap()
                .is_err()
        );
    }
}
