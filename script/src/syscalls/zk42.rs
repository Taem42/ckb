use crate::{
    cost_model::transferred_byte_cycles,
    syscalls::{
        utils::store_data, LOAD_TRANSACTION_SYSCALL_NUMBER, LOAD_TX_HASH_SYSCALL_NUMBER, SUCCESS,
    },
};
use ckb_types::{core::TransactionView, prelude::*};
use ckb_vm::memory::Memory;
use ckb_vm::{
    registers::{A0, A7},
    Error as VMError, Register, SupportMachine, Syscalls,
};
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs::File;
use std::io::Write;
use std::process::Command;

const zk42code: u64 = 42;
static verifying_key_path: &str = "/src/42zk/data/verifying-key.txt";
static public_data_path: &str = "/src/42zk/data/public-data.json";
static proof_path: &str = "/src/42zk/data/proof";
static zargo_path: &str = "/root/app/zinc/zargo";

pub fn get_arr<Mac: ckb_vm::SupportMachine>(
    machine: &mut Mac,
    addr: u64,
    size: u64,
) -> Result<Vec<u8>, ckb_vm::Error> {
    let mut addr = addr;
    let mut buffer = Vec::new();
    for _ in 0..size {
        let byte = machine
            .memory_mut()
            .load8(&Mac::REG::from_u64(addr))?
            .to_u8();
        buffer.push(byte);
        addr += 1;
    }
    machine.add_cycles(buffer.len() as u64 * 10)?;
    Ok(buffer)
}

fn hash_to_bits(h: Vec<u8>) -> Vec<bool> {
    let mut r: Vec<bool> = Vec::new();
    for i in 0..32 {
        let e = h[31 - i];
        r.push(e & 0b00000001 != 0x00);
        r.push(e & 0b00000010 != 0x00);
        r.push(e & 0b00000100 != 0x00);
        r.push(e & 0b00001000 != 0x00);
        r.push(e & 0b00010000 != 0x00);
        r.push(e & 0b00100000 != 0x00);
        r.push(e & 0b01000000 != 0x00);
        r.push(e & 0b10000000 != 0x00);
    }
    r
}

#[derive(Serialize, Deserialize)]
struct PublicData {
    input_amount_hash: Vec<bool>,
    output_amount_hash: Vec<bool>,
}

#[derive(Debug)]
pub struct Zk42 {
    // tx: &'a TransactionView,
}

impl Zk42 {
    pub fn new() -> Zk42 {
        Zk42 {}
    }
}

impl<Mac: SupportMachine> Syscalls<Mac> for Zk42 {
    fn initialize(&mut self, _machine: &mut Mac) -> Result<(), VMError> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut Mac) -> Result<bool, VMError> {
        let code = machine.registers()[A7].to_u64();
        if code == zk42code {
            return Ok(true);
        }

        // input_hash_addr output_hash_addr proof proof_size
        let input_hash_addr = machine.registers()[ckb_vm::registers::A0].to_u64();
        let output_hash_addr = machine.registers()[ckb_vm::registers::A1].to_u64();
        let proof_addr = machine.registers()[ckb_vm::registers::A2].to_u64();
        let proof_size = machine.registers()[ckb_vm::registers::A3].to_u64();

        let input_hash = get_arr(machine, input_hash_addr, 256)?;
        let output_hash = get_arr(machine, output_hash_addr, 256)?;
        let proof = get_arr(machine, proof_addr, proof_size)?;

        let a = hash_to_bits(input_hash);
        let b = hash_to_bits(output_hash);

        let public_data = PublicData {
            input_amount_hash: a,
            output_amount_hash: b,
        };
        let j = serde_json::to_string(&public_data).unwrap();

        let mut f0 = File::create(public_data_path)?;
        f0.write_all(j.as_bytes());
        let mut f1 = File::create(proof_path)?;
        f1.write_all(hex::encode(proof).as_bytes());

        let output = Command::new(zargo_path)
            .arg("verify")
            .output()
            .expect("zargo command failed to start");

        Ok(output.status.success())
    }
}
