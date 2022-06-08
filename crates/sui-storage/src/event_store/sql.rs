//! SQL and SQLite-based Event Store

use super::*;

use async_trait::async_trait;
use serde_json::{json, Value};

use sqlx::{sqlite::SqliteRow, Executor, Row, SqlitePool};
use sui_types::event::Event;
use tracing::{debug, info};

pub struct SqlEventStore {
    pool: SqlitePool,
}

const SQL_TABLE_CREATE: &str = "\
    CREATE TABLE IF NOT EXISTS events(
        timestamp INTEGER NOT NULL,
        checkpoint INTEGER,
        tx_digest BLOB,
        event_type TEXT,
        package_id BLOB,
        module_name TEXT,
        object_id BLOB,
        fields TEXT
    );
";

const INDEXED_COLUMNS: &[&str] = &[
    "timestamp",
    "tx_digest",
    "event_type",
    "package_id",
    "module_name",
];

impl SqlEventStore {
    /// Creates a new SQLite database for event storage
    /// db_path may be a regular path starting with "/" or ":memory:" for in-memory database.
    pub async fn new_sqlite(db_path: &str) -> Result<Self, EventStoreError> {
        let pool = SqlitePool::connect(format!("sqlite:{}", db_path).as_str()).await?;
        info!(db_path, "Created new SQLite EventStore");
        Ok(Self { pool })
    }

    /// Initializes the database, creating tables and indexes as needed
    /// It should be safe to call this every time after new_sqlite() as IF NOT EXISTS are used.
    pub async fn initialize(&self) -> Result<(), EventStoreError> {
        // First create the table if needed
        self.pool.execute(SQL_TABLE_CREATE).await?;
        info!("SQLite events table created");

        // Then, create indexes
        for column in INDEXED_COLUMNS {
            // NOTE: Cannot prepare CREATE INDEX statements
            self.pool
                .execute(
                    format!(
                        "CREATE INDEX IF NOT EXISTS {}_idx on events ({})",
                        column, column
                    )
                    .as_str(),
                )
                .await?;
        }
        info!("Indexes created");

        Ok(())
    }
}

fn try_extract_object_id(
    row: &SqliteRow,
    index: usize,
) -> Result<Option<ObjectID>, EventStoreError> {
    let raw_bytes: Option<Vec<u8>> = row.get(index);
    match raw_bytes {
        Some(bytes) => Ok(Some(
            ObjectID::try_from(bytes).map_err(|e| EventStoreError::GenericError(e.into()))?,
        )),
        None => Ok(None),
    }
}

// Translate a Row into StoredEvent
// TODO: convert to use FromRow trait so query_as() could be used?
fn sql_row_to_event(row: SqliteRow) -> StoredEvent {
    let timestamp: i64 = row.get(0);
    let checkpoint: i64 = row.get(1);
    let digest_raw: Option<Vec<u8>> = row.get(2);
    let tx_digest = digest_raw.map(|bytes| {
        TransactionDigest::new(
            bytes
                .try_into()
                .expect("Cannot convert digest bytes to TxDigest"),
        )
    });
    let event_type: String = row.get(3);
    let package_id = try_extract_object_id(&row, 4).expect("Error converting package ID bytes");
    let object_id = try_extract_object_id(&row, 6).expect("Error converting object ID bytes");
    let module_name: Option<String> = row.get(5);
    let fields_text: &str = row.get(7);
    let fields: Vec<_> = if fields_text.is_empty() {
        Vec::new()
    } else {
        let fields_json = serde_json::from_str(fields_text)
            .expect(format!("Could not parse [{}] as JSON", fields_text).as_str());
        if let Value::Object(map) = fields_json {
            map.into_iter()
                .map(|(k, v)| (flexstr::SharedStr::from(k), EventValue::Json(v)))
                .collect()
        } else {
            debug!(?fields_json, "Could not parse JSON as object");
            Vec::new()
        }
    };

    StoredEvent {
        timestamp: timestamp as u64,
        checkpoint_num: checkpoint as u64,
        tx_digest,
        event_type: event_type.into(),
        module_name: module_name.map(|s| s.into()),
        object_id: object_id.or(package_id),
        fields,
    }
}

// Adds JSON fields for items not in any of the standard columns in table definition, eg for MOVE events.
fn event_to_json(event: &EventEnvelope) -> String {
    if let Some(json_value) = &event.move_struct_json_value {
        json_value.to_string()
    } else {
        let maybe_json = match &event.event {
            Event::TransferObject {
                version,
                destination_addr,
                type_,
                ..
            } => Some(json!({"destination": destination_addr.to_string(),
                       "version": version.value(),
                       "type": type_.to_string() })),
            _ => None,
        };
        maybe_json.map(|j| j.to_string()).unwrap_or(String::new())
    }
}

const SQL_INSERT_TX: &str = "INSERT INTO events (timestamp, checkpoint, tx_digest, event_type, \
    package_id, module_name, object_id, fields) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

const TS_QUERY: &str = "SELECT * FROM events WHERE timestamp >= ? AND timestamp < ? LIMIT ?";

const TX_QUERY: &str = "SELECT * FROM events WHERE tx_digest = ?";

#[async_trait]
impl EventStore for SqlEventStore {
    type EventIt = std::vec::IntoIter<StoredEvent>;

    async fn add_events(
        &self,
        events: &[EventEnvelope],
        checkpoint_num: u64,
    ) -> Result<(), EventStoreError> {
        // TODO: benchmark
        // TODO: use techniques in https://docs.rs/sqlx-core/0.5.13/sqlx_core/query_builder/struct.QueryBuilder.html#method.push_values
        // to execute all inserts in a single statement?
        // TODO: See https://kerkour.com/high-performance-rust-with-sqlite
        for event in events {
            // If batching, turn off persistent to avoid caching as we may fill up the prepared statement cache
            let insert_tx_q = sqlx::query(SQL_INSERT_TX).persistent(true);
            let module_id = event.event.module_id();
            // TODO: use batched API?
            insert_tx_q
                .bind(event.timestamp as i64)
                .bind(checkpoint_num as i64)
                .bind(event.tx_digest.map(|txd| txd.to_bytes()))
                .bind(event.event_type())
                .bind(module_id.clone().map(|mid| mid.address().to_vec()))
                .bind(module_id.map(|mid| mid.name().to_string()))
                .bind(event.event.object_id().map(|id| id.to_vec()))
                .bind(event_to_json(event))
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    async fn events_for_transaction(
        &self,
        digest: TransactionDigest,
    ) -> Result<Self::EventIt, EventStoreError> {
        let rows = sqlx::query(TX_QUERY)
            .bind(digest.to_bytes())
            .map(sql_row_to_event)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter())
    }

    async fn events_by_type(
        &self,
        start_time: u64,
        end_time: u64,
        event_type: EventType,
        limit: usize,
    ) -> Result<Self::EventIt, EventStoreError> {
        unimplemented!()
    }

    async fn event_iterator(
        &self,
        start_time: u64,
        end_time: u64,
        limit: usize,
    ) -> Result<Self::EventIt, EventStoreError> {
        // TODO: check limit is not too high
        let rows = sqlx::query(TS_QUERY)
            .bind(start_time as i64)
            .bind(end_time as i64)
            .bind(limit as i64)
            .map(sql_row_to_event)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter())
    }

    async fn events_by_checkpoint(
        &self,
        start_checkpoint: u64,
        end_checkpoint: u64,
        limit: usize,
    ) -> Result<Self::EventIt, EventStoreError> {
        unimplemented!()
    }

    async fn events_by_module_id(
        &self,
        start_time: u64,
        end_time: u64,
        module: ModuleId,
        limit: usize,
    ) -> Result<Self::EventIt, EventStoreError> {
        unimplemented!()
    }

    async fn total_event_count(&self) -> Result<usize, EventStoreError> {
        let result = sqlx::query("SELECT COUNT(*) FROM events")
            .fetch_one(&self.pool)
            .await?;
        let num_rows: i64 = result.get(0);
        Ok(num_rows as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flexstr::shared_str;
    use serde_json::json;
    use std::collections::BTreeMap;

    use sui_types::{
        base_types::SuiAddress,
        event::{Event, EventEnvelope, TransferType},
    };

    fn new_test_publish_event() -> Event {
        Event::Publish {
            package_id: ObjectID::random(),
        }
    }

    fn new_test_newobj_event() -> Event {
        Event::NewObject(ObjectID::random())
    }

    fn new_test_deleteobj_event() -> Event {
        Event::DeleteObject(ObjectID::random())
    }

    fn new_test_transfer_event(typ: TransferType) -> Event {
        Event::TransferObject {
            object_id: ObjectID::random(),
            version: 1.into(),
            destination_addr: SuiAddress::random_for_testing_only(),
            type_: typ,
        }
    }

    fn test_events() -> Vec<EventEnvelope> {
        vec![
            EventEnvelope::new(
                1_000_000,
                Some(TransactionDigest::random()),
                new_test_newobj_event(),
                None,
            ),
            EventEnvelope::new(1_001_000, None, new_test_publish_event(), None),
            EventEnvelope::new(
                1_002_000,
                Some(TransactionDigest::random()),
                new_test_transfer_event(TransferType::Coin),
                None,
            ),
            EventEnvelope::new(
                1_003_000,
                Some(TransactionDigest::random()),
                new_test_deleteobj_event(),
                None,
            ),
        ]
    }

    fn test_queried_event_vs_test_envelope(queried: &StoredEvent, orig: &EventEnvelope) {
        assert_eq!(queried.timestamp, orig.timestamp);
        assert_eq!(queried.checkpoint_num, 1);
        assert_eq!(queried.tx_digest, orig.tx_digest);
        assert_eq!(queried.event_type, shared_str!(orig.event_type()));
        assert_eq!(queried.module_name, None);
        assert_eq!(queried.object_id, orig.event.object_id());
    }

    #[tokio::test]
    async fn test_eventstore_basic_insert_read() -> Result<(), EventStoreError> {
        telemetry_subscribers::init_for_testing();

        // Initialize store
        let db = SqlEventStore::new_sqlite(":memory:").await?;
        db.initialize().await?;

        // Insert some records
        info!("Inserting records!");
        let to_insert = test_events();
        db.add_events(&to_insert, 1).await?;
        info!("Done inserting");

        assert_eq!(db.total_event_count().await?, 4);

        // Query for records in time range, end should be exclusive - should get 2
        let event_it = db.event_iterator(1_000_000, 1_002_000, 10).await?;
        let queried_events: Vec<_> = event_it.collect();

        assert_eq!(queried_events.len(), 2);
        for i in 0..2 {
            test_queried_event_vs_test_envelope(&queried_events[i], &to_insert[i]);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_eventstore_transfers_tx_read() -> Result<(), EventStoreError> {
        telemetry_subscribers::init_for_testing();

        // Initialize store
        let db = SqlEventStore::new_sqlite(":memory:").await?;
        db.initialize().await?;

        // Insert some records
        info!("Inserting records!");
        let to_insert = test_events();
        db.add_events(&to_insert, 1).await?;
        info!("Done inserting");

        // Query for transfer event
        let mut event_it = db
            .events_for_transaction(to_insert[2].tx_digest.unwrap())
            .await?;
        let transfer_event = event_it.next().expect("No transfer events in result!!");
        assert_eq!(event_it.next(), None); // Should be no more events, just that one

        test_queried_event_vs_test_envelope(&transfer_event, &to_insert[2]);

        // Now test for fields
        assert_eq!(transfer_event.fields.len(), 3);
        let field_map: BTreeMap<_, _> = transfer_event.fields.into_iter().collect();
        let keys: Vec<_> = field_map.keys().collect();
        assert_eq!(
            keys,
            vec![
                shared_str!("destination"),
                shared_str!("type"),
                shared_str!("version")
            ]
        );

        let type_str = field_map.get(&shared_str!("type")).unwrap();
        assert_eq!(type_str, &EventValue::Json(json!("Coin")));

        Ok(())
    }

    // TODO: test MoveEvents

    // TODO: test limit
}
