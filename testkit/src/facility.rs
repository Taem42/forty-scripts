use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellMetaBuilder},
        Capacity, DepType, ScriptHashType,
    },
    packed::{CellDep, CellOutput, OutPoint, Script},
    prelude::*,
};

pub trait Facility {
    fn cell_meta(&self) -> CellMeta {
        let data = self.data().clone();
        let data_capacity = Capacity::bytes(data.len()).unwrap();
        let output = CellOutput::new_builder()
            .lock(Script::default())
            .build_exact_capacity(data_capacity)
            .unwrap();
        let out_point = self.out_point();
        CellMetaBuilder::from_cell_output(output, data)
            .out_point(out_point)
            // leave transaction_info to None
            .build()
    }

    fn cell_dep(&self) -> CellDep {
        CellDep::new_builder()
            .out_point(self.out_point())
            .dep_type(DepType::Code.into())
            .build()
    }

    fn out_point(&self) -> OutPoint {
        let fake_tx_hash = CellOutput::calc_data_hash(self.data().as_ref());
        let fake_index = 0;
        OutPoint::new(fake_tx_hash, fake_index)
    }

    fn script(&self) -> Script {
        let code_hash = CellOutput::calc_data_hash(self.data().as_ref());
        Script::new_builder()
            .code_hash(code_hash)
            .hash_type(ScriptHashType::Data.into())
            .build()
    }

    fn data(&self) -> &Bytes;
}
