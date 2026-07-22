use rusqlite::{Connection, OptionalExtension, Result};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use tracing::info;

pub struct Database {
    conn: Arc<Mutex<Connection>>,
}

impl Database {
    pub fn new() -> Result<Self> {
        let path = Self::db_path();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(&path)?;
        let db = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        db.init_tables()?;
        info!("database opened: {:?}", path);
        Ok(db)
    }

    fn db_path() -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join("phantom-p2p.db")))
            .unwrap_or_else(|| PathBuf::from("phantom-p2p.db"))
    }

    fn init_tables(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY, username TEXT NOT NULL, public_key TEXT,
                created_at TEXT NOT NULL, last_seen TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS rooms (
                room_code TEXT PRIMARY KEY, host_user_id TEXT NOT NULL,
                created_at TEXT NOT NULL, closed_at TEXT, guest_count INTEGER DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS connection_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL,
                room_code TEXT, event_type TEXT NOT NULL, timestamp TEXT NOT NULL, details TEXT
             );
             CREATE TABLE IF NOT EXISTS room_networks (
                room_code TEXT PRIMARY KEY, subnet TEXT NOT NULL,
                created_at TEXT NOT NULL, released_at TEXT
             );
             CREATE TABLE IF NOT EXISTS room_peers (
                room_code TEXT NOT NULL, session_id TEXT NOT NULL, virtual_ip TEXT NOT NULL,
                role TEXT NOT NULL, allocated_at TEXT NOT NULL, released_at TEXT,
                PRIMARY KEY (room_code, session_id)
             );
             CREATE TABLE IF NOT EXISTS fixed_host_addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL,
                virtual_ip TEXT NOT NULL, allocated_at TEXT NOT NULL, released_at TEXT
             );
             CREATE UNIQUE INDEX IF NOT EXISTS active_room_subnet
                ON room_networks(subnet) WHERE released_at IS NULL;
             CREATE UNIQUE INDEX IF NOT EXISTS active_room_peer_ip
                ON room_peers(room_code, virtual_ip) WHERE released_at IS NULL;
             CREATE UNIQUE INDEX IF NOT EXISTS active_fixed_host_user
                ON fixed_host_addresses(user_id) WHERE released_at IS NULL;
             CREATE UNIQUE INDEX IF NOT EXISTS active_fixed_host_ip
                ON fixed_host_addresses(virtual_ip) WHERE released_at IS NULL;",
        )?;
        // A process restart invalidates all live WebSocket sessions. Release
        // their durable network leases so a crashed server cannot exhaust the
        // address pool forever.
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE room_peers SET released_at = ?1 WHERE released_at IS NULL",
            [&now],
        )?;
        conn.execute(
            "UPDATE room_networks SET released_at = ?1 WHERE released_at IS NULL",
            [&now],
        )?;
        Ok(())
    }

    pub fn upsert_user(&self, user_id: &str, username: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO users (user_id, username, created_at, last_seen) VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(user_id) DO UPDATE SET username = ?2, last_seen = ?3",
            rusqlite::params![user_id, username, now],
        )?;
        Ok(())
    }

    pub fn create_room(&self, room_code: &str, host_user_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO rooms (room_code, host_user_id, created_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(room_code) DO UPDATE SET host_user_id = ?2, created_at = ?3, closed_at = NULL, guest_count = 0",
            rusqlite::params![room_code, host_user_id, now])?;
        Ok(())
    }

    pub fn close_room(&self, room_code: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE rooms SET closed_at = ?1 WHERE room_code = ?2",
            rusqlite::params![chrono::Utc::now().to_rfc3339(), room_code],
        )?;
        Ok(())
    }

    pub fn update_guest_count(&self, room_code: &str, count: i32) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE rooms SET guest_count = ?1 WHERE room_code = ?2",
            rusqlite::params![count, room_code],
        )?;
        Ok(())
    }

    pub fn log_event(
        &self,
        user_id: &str,
        room_code: Option<&str>,
        event_type: &str,
        details: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO connection_logs (user_id, room_code, event_type, timestamp, details) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![user_id, room_code.unwrap_or(""), event_type, chrono::Utc::now().to_rfc3339(), details.unwrap_or("")])?;
        Ok(())
    }

    pub fn get_user_count(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
    }

    pub fn get_room_count(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM rooms", [], |row| row.get(0))
    }

    pub fn allocate_subnet(&self, room_code: &str) -> Result<String> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        if let Ok(existing) = conn.query_row(
            "SELECT subnet FROM room_networks WHERE room_code = ?1 AND released_at IS NULL",
            [room_code],
            |row| row.get::<_, String>(0),
        ) {
            return Ok(existing);
        }
        conn.execute(
            "DELETE FROM room_networks WHERE room_code = ?1 AND released_at IS NOT NULL",
            [room_code],
        )?;
        // Dynamic room networks occupy 172.16.0.0/13. The 172.24.0.0/13
        // half is reserved exclusively for persistent Host /32 addresses.
        for n in 0..2048u32 {
            let subnet = format!("172.{}.{}", 16 + n / 256, n % 256);
            if conn.execute(
                "INSERT OR IGNORE INTO room_networks (room_code, subnet, created_at, released_at) VALUES (?1, ?2, ?3, NULL)",
                rusqlite::params![room_code, subnet, now])? == 1 { return Ok(subnet); }
        }
        Err(rusqlite::Error::QueryReturnedNoRows)
    }

    pub fn get_fixed_host_ip(&self, user_id: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT virtual_ip FROM fixed_host_addresses
             WHERE user_id = ?1 AND released_at IS NULL",
            [user_id],
            |row| row.get(0),
        )
        .optional()
    }

    pub fn allocate_fixed_host_ip(&self, user_id: &str) -> Result<String> {
        let conn = self.conn.lock().unwrap();
        if let Some(existing) = conn
            .query_row(
                "SELECT virtual_ip FROM fixed_host_addresses
                 WHERE user_id = ?1 AND released_at IS NULL",
                [user_id],
                |row| row.get(0),
            )
            .optional()?
        {
            return Ok(existing);
        }

        let now = chrono::Utc::now().to_rfc3339();
        let mut statement =
            conn.prepare("SELECT virtual_ip FROM fixed_host_addresses WHERE released_at IS NULL")?;
        let occupied: HashSet<String> = statement
            .query_map([], |row| row.get(0))?
            .collect::<Result<_>>()?;
        drop(statement);
        for second in 24..=31u16 {
            for third in 0..=255u16 {
                for host in 1..=254u16 {
                    let ip = format!("172.{}.{}.{}", second, third, host);
                    if occupied.contains(&ip) {
                        continue;
                    }
                    conn.execute(
                        "INSERT INTO fixed_host_addresses
                         (user_id, virtual_ip, allocated_at, released_at)
                         VALUES (?1, ?2, ?3, NULL)",
                        rusqlite::params![user_id, ip, now],
                    )?;
                    return Ok(ip);
                }
            }
        }
        Err(rusqlite::Error::QueryReturnedNoRows)
    }

    pub fn release_fixed_host_ip(&self, user_id: &str) -> Result<Option<String>> {
        let existing = self.get_fixed_host_ip(user_id)?;
        if existing.is_none() {
            return Ok(None);
        }
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE fixed_host_addresses SET released_at = ?1
             WHERE user_id = ?2 AND released_at IS NULL",
            rusqlite::params![chrono::Utc::now().to_rfc3339(), user_id],
        )?;
        Ok(existing)
    }

    pub fn assign_peer_ip(
        &self,
        room_code: &str,
        session_id: &str,
        virtual_ip: &str,
        role: &str,
    ) -> Result<String> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO room_peers
             (room_code, session_id, virtual_ip, role, allocated_at, released_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL)
             ON CONFLICT(room_code, session_id) DO UPDATE SET
                virtual_ip = ?3, role = ?4, allocated_at = ?5, released_at = NULL",
            rusqlite::params![room_code, session_id, virtual_ip, role, now],
        )?;
        Ok(virtual_ip.to_string())
    }

    pub fn allocate_peer_ip(
        &self,
        room_code: &str,
        session_id: &str,
        role: &str,
    ) -> Result<String> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        if let Ok(existing) = conn.query_row(
            "SELECT virtual_ip FROM room_peers WHERE room_code = ?1 AND session_id = ?2 AND released_at IS NULL",
            rusqlite::params![room_code, session_id], |row| row.get::<_, String>(0)) { return Ok(existing); }
        conn.execute(
            "DELETE FROM room_peers WHERE room_code = ?1 AND session_id = ?2 AND released_at IS NOT NULL",
            rusqlite::params![room_code, session_id])?;
        let subnet: String = conn.query_row(
            "SELECT subnet FROM room_networks WHERE room_code = ?1 AND released_at IS NULL",
            [room_code],
            |row| row.get(0),
        )?;
        // For a dynamic Host, .1 is already occupied and the unique index
        // advances the first Guest to .2. A fixed /32 Host lives outside this
        // subnet, so its room may also use .1 for a Guest.
        let first = 1;
        for host in first..=254u16 {
            let ip = format!("{}.{}", subnet, host);
            if conn.execute(
                "INSERT OR IGNORE INTO room_peers (room_code, session_id, virtual_ip, role, allocated_at, released_at) VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                rusqlite::params![room_code, session_id, ip, role, now])? == 1 { return Ok(ip); }
        }
        Err(rusqlite::Error::QueryReturnedNoRows)
    }

    pub fn release_peer(&self, room_code: &str, session_id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("UPDATE room_peers SET released_at = ?1 WHERE room_code = ?2 AND session_id = ?3 AND released_at IS NULL", rusqlite::params![chrono::Utc::now().to_rfc3339(), room_code, session_id])?;
        Ok(())
    }

    pub fn release_room_network(&self, room_code: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE room_peers SET released_at = ?1 WHERE room_code = ?2 AND released_at IS NULL",
            rusqlite::params![now, room_code],
        )?;
        conn.execute("UPDATE room_networks SET released_at = ?1 WHERE room_code = ?2 AND released_at IS NULL", rusqlite::params![now, room_code])?;
        Ok(())
    }
}

static DB_INSTANCE: OnceLock<Arc<Database>> = OnceLock::new();

pub fn init_database() -> Result<Arc<Database>> {
    if let Some(db) = DB_INSTANCE.get() {
        return Ok(db.clone());
    }
    let db = Arc::new(Database::new()?);
    let _ = DB_INSTANCE.set(db.clone());
    Ok(DB_INSTANCE.get().cloned().unwrap_or(db))
}

pub fn get_database() -> Option<Arc<Database>> {
    DB_INSTANCE.get().cloned()
}

#[cfg(test)]
mod room_peer_tests {
    use super::*;

    fn memory_db() -> Database {
        let db = Database {
            conn: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
        };
        db.init_tables().unwrap();
        db
    }

    #[test]
    fn dynamic_and_fixed_pools_do_not_overlap() {
        let db = memory_db();
        assert_eq!(db.allocate_subnet("ROOM01").unwrap(), "172.16.0");
        assert_eq!(db.allocate_fixed_host_ip("user-a").unwrap(), "172.24.0.1");
    }

    #[test]
    fn fixed_pool_uses_all_host_octets_before_next_subnet() {
        let db = memory_db();
        for host in 1..=254 {
            assert_eq!(
                db.allocate_fixed_host_ip(&format!("user-{host}")).unwrap(),
                format!("172.24.0.{host}")
            );
        }
        assert_eq!(db.allocate_fixed_host_ip("user-255").unwrap(), "172.24.1.1");
    }

    #[test]
    fn fixed_address_is_stable_unique_and_survives_table_init() {
        let db = memory_db();
        let first = db.allocate_fixed_host_ip("user-a").unwrap();
        assert_eq!(db.allocate_fixed_host_ip("user-a").unwrap(), first);
        assert_ne!(db.allocate_fixed_host_ip("user-b").unwrap(), first);

        db.init_tables().unwrap();
        assert_eq!(db.get_fixed_host_ip("user-a").unwrap(), Some(first));
    }

    #[test]
    fn fixed_address_survives_database_reopen() {
        let path = std::env::temp_dir().join(format!(
            "phantom-fixed-ip-{}-{}.db",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        {
            let db = Database {
                conn: Arc::new(Mutex::new(Connection::open(&path).unwrap())),
            };
            db.init_tables().unwrap();
            assert_eq!(db.allocate_fixed_host_ip("user-a").unwrap(), "172.24.0.1");
        }
        {
            let db = Database {
                conn: Arc::new(Mutex::new(Connection::open(&path).unwrap())),
            };
            db.init_tables().unwrap();
            assert_eq!(
                db.get_fixed_host_ip("user-a").unwrap().as_deref(),
                Some("172.24.0.1")
            );
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn released_fixed_address_can_be_reused() {
        let db = memory_db();
        assert_eq!(db.allocate_fixed_host_ip("user-a").unwrap(), "172.24.0.1");
        assert_eq!(
            db.release_fixed_host_ip("user-a").unwrap().as_deref(),
            Some("172.24.0.1")
        );
        assert_eq!(db.get_fixed_host_ip("user-a").unwrap(), None);
        assert_eq!(db.allocate_fixed_host_ip("user-b").unwrap(), "172.24.0.1");
    }

    #[test]
    fn fixed_host_room_can_assign_dot_one_to_guest() {
        let db = memory_db();
        db.allocate_subnet("ROOM01").unwrap();
        db.assign_peer_ip("ROOM01", "host", "172.24.0.1", "host")
            .unwrap();
        assert_eq!(
            db.allocate_peer_ip("ROOM01", "guest", "guest").unwrap(),
            "172.16.0.1"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn memory_db() -> Database {
        let db = Database {
            conn: Arc::new(Mutex::new(Connection::open_in_memory().unwrap())),
        };
        db.init_tables().unwrap();
        db
    }

    #[test]
    fn allocates_unique_addresses_for_one_hundred_guests() {
        let db = memory_db();
        assert_eq!(db.allocate_subnet("ROOM01").unwrap(), "172.16.0");
        assert_eq!(
            db.allocate_peer_ip("ROOM01", "host", "host").unwrap(),
            "172.16.0.1"
        );
        let mut addresses = HashSet::new();
        for index in 0..100 {
            let ip = db
                .allocate_peer_ip("ROOM01", &format!("guest-{index}"), "guest")
                .unwrap();
            assert!(addresses.insert(ip));
        }
        assert_eq!(addresses.len(), 100);
    }

    #[test]
    fn released_guest_address_can_be_reused() {
        let db = memory_db();
        db.allocate_subnet("ROOM02").unwrap();
        let first = db.allocate_peer_ip("ROOM02", "guest-a", "guest").unwrap();
        db.release_peer("ROOM02", "guest-a").unwrap();
        let second = db.allocate_peer_ip("ROOM02", "guest-b", "guest").unwrap();
        assert_eq!(first, second);
    }
}
