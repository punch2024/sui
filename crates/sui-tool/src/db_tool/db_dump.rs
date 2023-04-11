// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use clap::{Parser, ValueEnum};
use comfy_table::{Cell, ContentArrangement, Row, Table};
use rocksdb::MultiThreaded;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::str;
use strum_macros::EnumString;
use sui_core::authority::authority_per_epoch_store::AuthorityEpochTables;
use sui_core::authority::authority_store_tables::AuthorityPerpetualTables;
// use sui_core::authority::authority_store_types::{StoreData, StoreObject};
use sui_core::epoch::committee_store::CommitteeStoreTables;
use sui_storage::IndexStoreTables;
use sui_types::base_types::EpochId;
use typed_store::rocks::{default_db_options, MetricConf};
use typed_store::traits::{Map, TableSummary};

#[derive(EnumString, Clone, Parser, Debug, ValueEnum)]
pub enum StoreName {
    Validator,
    Index,
    Epoch,
    // TODO: Add the new checkpoint v2 tables.
}
impl std::fmt::Display for StoreName {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn list_tables(path: PathBuf) -> anyhow::Result<Vec<String>> {
    rocksdb::DBWithThreadMode::<MultiThreaded>::list_cf(&default_db_options().options, path)
        .map_err(|e| e.into())
        .map(|q| {
            q.iter()
                .filter_map(|s| {
                    // The `default` table is not used
                    if s != "default" {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .collect()
        })
}

pub fn table_summary(
    store_name: StoreName,
    epoch: Option<EpochId>,
    db_path: PathBuf,
    table_name: &str,
) -> anyhow::Result<TableSummary> {
    match store_name {
        StoreName::Validator => {
            let epoch_tables = AuthorityEpochTables::describe_tables();
            if epoch_tables.contains_key(table_name) {
                let epoch = epoch.ok_or_else(|| anyhow!("--epoch is required"))?;
                AuthorityEpochTables::open_readonly(epoch, &db_path).table_summary(table_name)
            } else {
                AuthorityPerpetualTables::open_readonly(&db_path).table_summary(table_name)
            }
        }
        StoreName::Index => {
            IndexStoreTables::get_read_only_handle(db_path, None, None, MetricConf::default())
                .table_summary(table_name)
        }
        StoreName::Epoch => {
            CommitteeStoreTables::get_read_only_handle(db_path, None, None, MetricConf::default())
                .table_summary(table_name)
        }
    }
    .map_err(|err| anyhow!(err.to_string()))
}

pub fn print_table_metadata(
    store_name: StoreName,
    epoch: Option<EpochId>,
    db_path: PathBuf,
    table_name: &str,
) -> anyhow::Result<()> {
    let db = match store_name {
        StoreName::Validator => {
            let epoch_tables = AuthorityEpochTables::describe_tables();
            if epoch_tables.contains_key(table_name) {
                let epoch = epoch.ok_or_else(|| anyhow!("--epoch is required"))?;
                AuthorityEpochTables::open_readonly(epoch, &db_path)
                    .next_shared_object_versions
                    .rocksdb
            } else {
                AuthorityPerpetualTables::open_readonly(&db_path)
                    .objects
                    .rocksdb
            }
        }
        StoreName::Index => {
            IndexStoreTables::get_read_only_handle(db_path, None, None, MetricConf::default())
                .event_by_move_module
                .rocksdb
        }
        StoreName::Epoch => {
            CommitteeStoreTables::get_read_only_handle(db_path, None, None, MetricConf::default())
                .committee_map
                .rocksdb
        }
    };

    let mut table = Table::new();
    table
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_width(200)
        .set_header(vec![
            "name",
            "level",
            "num_entries",
            "start_key",
            "end_key",
            "num_deletions",
            "file_size",
        ]);

    for file in db.live_files()?.iter() {
        if file.column_family_name != table_name {
            continue;
        }
        let mut row = Row::new();
        row.add_cell(Cell::new(&file.name));
        row.add_cell(Cell::new(file.level));
        row.add_cell(Cell::new(file.num_entries));
        row.add_cell(Cell::new(hex::encode(
            file.start_key.as_ref().unwrap_or(&"".as_bytes().to_vec()),
        )));
        row.add_cell(Cell::new(hex::encode(
            file.end_key.as_ref().unwrap_or(&"".as_bytes().to_vec()),
        )));
        row.add_cell(Cell::new(file.num_deletions));
        row.add_cell(Cell::new(file.size));
        table.add_row(row);
    }

    eprintln!("{}", table);
    Ok(())
}

pub fn duplicate_objects_summary(db_path: PathBuf) -> (usize, usize, usize, usize) {
    let perpetual_tables = AuthorityPerpetualTables::open_readonly(&db_path);
    let mut iter = perpetual_tables.indirect_move_objects.iter();

    loop {
        let item = iter.raw_next();
        match item {
            None => break,
            Some((k, v)) => eprintln!("key is {:?} value {:?}", k, v),
        }
    }

    (0, 0, 0, 0)
}

// TODO: condense this using macro or trait dyn skills
pub fn dump_table(
    store_name: StoreName,
    epoch: Option<EpochId>,
    db_path: PathBuf,
    table_name: &str,
    page_size: u16,
    page_number: usize,
) -> anyhow::Result<BTreeMap<String, String>> {
    match store_name {
        StoreName::Validator => {
            let epoch_tables = AuthorityEpochTables::describe_tables();
            if epoch_tables.contains_key(table_name) {
                let epoch = epoch.ok_or_else(|| anyhow!("--epoch is required"))?;
                AuthorityEpochTables::open_readonly(epoch, &db_path).dump(
                    table_name,
                    page_size,
                    page_number,
                )
            } else {
                AuthorityPerpetualTables::open_readonly(&db_path).dump(
                    table_name,
                    page_size,
                    page_number,
                )
            }
        }
        StoreName::Index => {
            IndexStoreTables::get_read_only_handle(db_path, None, None, MetricConf::default()).dump(
                table_name,
                page_size,
                page_number,
            )
        }
        StoreName::Epoch => {
            CommitteeStoreTables::get_read_only_handle(db_path, None, None, MetricConf::default())
                .dump(table_name, page_size, page_number)
        }
    }
    .map_err(|err| anyhow!(err.to_string()))
}

#[cfg(test)]
mod test {
    use sui_core::authority::authority_per_epoch_store::AuthorityEpochTables;
    use sui_core::authority::authority_store_tables::AuthorityPerpetualTables;

    use crate::db_tool::db_dump::{dump_table, list_tables, StoreName};

    #[tokio::test]
    async fn db_dump_population() -> Result<(), anyhow::Error> {
        let primary_path = tempfile::tempdir()?.into_path();

        // Open the DB for writing
        let _: AuthorityEpochTables = AuthorityEpochTables::open(0, &primary_path, None);
        let _: AuthorityPerpetualTables = AuthorityPerpetualTables::open(&primary_path, None);

        // Get all the tables for AuthorityEpochTables
        let tables = {
            let mut epoch_tables =
                list_tables(AuthorityEpochTables::path(0, &primary_path)).unwrap();
            let mut perpetual_tables =
                list_tables(AuthorityPerpetualTables::path(&primary_path)).unwrap();
            epoch_tables.append(&mut perpetual_tables);
            epoch_tables
        };

        let mut missing_tables = vec![];
        for t in tables {
            println!("{}", t);
            if dump_table(
                StoreName::Validator,
                Some(0),
                primary_path.clone(),
                &t,
                0,
                0,
            )
            .is_err()
            {
                missing_tables.push(t);
            }
        }
        if missing_tables.is_empty() {
            return Ok(());
        }
        panic!(
            "{}",
            format!(
                "Missing {} table(s) from DB dump registration function: {:?} \n Update the dump function.",
                missing_tables.len(),
                missing_tables
            )
        );
    }
}
