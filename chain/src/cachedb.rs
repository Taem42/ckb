use db::batch::{Batch, Col, Operation};
use db::kvdb::{KeyValueDB, Result};
use fnv::FnvHashMap;
use lru_cache::LruCache;
use util::RwLock;

type CacheTable = FnvHashMap<Col, LruCache<Vec<u8>, Vec<u8>>>;
pub type CacheCols = (u32, usize);

pub struct CacheDB<T>
where
    T: KeyValueDB,
{
    db: T,
    cache: RwLock<CacheTable>,
}

impl<T> CacheDB<T>
where
    T: KeyValueDB,
{
    pub fn new(db: T, cols: &[CacheCols]) -> Self {
        let mut table = FnvHashMap::with_capacity_and_hasher(cols.len(), Default::default());
        for (idx, capacity) in cols {
            table.insert(Some(*idx), LruCache::new(*capacity, false));
        }
        CacheDB {
            db,
            cache: RwLock::new(table),
        }
    }
}

impl<T> KeyValueDB for CacheDB<T>
where
    T: KeyValueDB,
{
    fn cols(&self) -> u32 {
        self.db.cols()
    }

    fn write(&self, batch: Batch) -> Result<()> {
        let mut cache_guard = self.cache.write();
        batch.operations.iter().for_each(|op| match op {
            Operation::Insert { col, key, value } => {
                if let Some(lru) = cache_guard.get_mut(&col) {
                    lru.insert(key.clone(), value.clone());
                }
            }
            Operation::Delete { col, key } => {
                if let Some(lru) = cache_guard.get_mut(&col) {
                    lru.remove(key);
                }
            }
        });
        self.db.write(batch)
    }

    fn read(&self, col: Col, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cache_guard = self.cache.read();
        if let Some(value) = cache_guard
            .get(&col)
            .and_then(|cache| cache.get(key))
            .cloned()
        {
            return Ok(Some(value));
        }
        self.db.read(col, key)
    }
}
