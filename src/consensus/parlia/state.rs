use std::collections::HashMap;
use super::*;
use types::*;

#[derive(Debug)]
pub struct ParliaNewBlockState {
    next_validators: Option<(Vec<Address>, HashMap<Address, BLSPublicKey>)>
}

impl ParliaNewBlockState {

    /// instance parlia state with validators, guarantee address list is sorted by Ascending
    pub fn new(next_validators: Option<(Vec<Address>, HashMap<Address, BLSPublicKey>)>) -> ParliaNewBlockState {
        ParliaNewBlockState {
            next_validators
        }
    }

    pub fn get_validators(&self) -> Option<&(Vec<Address>, HashMap<Address, BLSPublicKey>)> {
        self.next_validators.as_ref()
    }

    pub fn parsed_validators(&self) -> bool {
        self.next_validators.is_some()
    }
}
