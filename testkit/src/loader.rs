use ckb_script::DataLoader;
use ckb_types::{
    bytes::Bytes,
    core::{cell::CellMeta, BlockExt, EpochExt, HeaderView},
    packed::{Byte32, OutPoint},
};
use std::collections::HashMap;

#[derive(Default)]
pub struct DummyDataLoader {
    headers: HashMap<Byte32, HeaderView>,
    epoches: HashMap<Byte32, EpochExt>,
    cells: HashMap<OutPoint, CellMeta>,
}

impl DataLoader for DummyDataLoader {
    // Return the corresponding cell_data and data_hash
    fn load_cell_data(&self, cell: &CellMeta) -> Option<(Bytes, Byte32)> {
        cell.mem_cell_data.clone().or_else(|| {
            self.cells
                .get(&cell.out_point)
                .and_then(|cell_meta| cell_meta.mem_cell_data.clone())
        })
    }

    fn get_header(&self, block_hash: &Byte32) -> Option<HeaderView> {
        self.headers.get(block_hash).cloned()
    }

    fn get_block_ext(&self, _hash: &Byte32) -> Option<BlockExt> {
        unreachable!()
    }

    fn get_block_epoch(&self, block_hash: &Byte32) -> Option<EpochExt> {
        self.epoches.get(block_hash).cloned()
    }
}

impl DummyDataLoader {
    pub fn add_header(&mut self, block_hash: Byte32, header: HeaderView) {
        self.headers.insert(block_hash, header);
    }

    pub fn add_epoch(&mut self, block_hash: Byte32, epoch: EpochExt) {
        self.epoches.insert(block_hash, epoch);
    }

    pub fn add_cell(&mut self, cell_meta: CellMeta) {
        self.cells.insert(cell_meta.out_point.clone(), cell_meta);
    }

    pub fn get_cell(&mut self, out_point: &OutPoint) -> Option<&CellMeta> {
        self.cells.get(out_point)
    }
}
