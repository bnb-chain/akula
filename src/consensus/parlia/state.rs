use super::*;

#[derive(Debug)]
pub struct ParliaNewHeaderState {
    snap: Snapshot
}

impl ParliaNewHeaderState {

    pub fn new(snap: Snapshot) -> ParliaNewHeaderState {
        ParliaNewHeaderState {
            snap
        }
    }

    pub fn get_snap(&self) -> &Snapshot {
        &self.snap
    }
}

#[derive(Debug)]
pub struct ParliaNewBlockState {
    next_validators: Option<BTreeSet<Address>>
}

impl ParliaNewBlockState {

    pub fn new(next_validators: Option<BTreeSet<Address>>) -> ParliaNewBlockState {
        ParliaNewBlockState {
            next_validators
        }
    }

    pub fn get_validators(&self) -> Option<&BTreeSet<Address>> {
        self.next_validators.as_ref()
    }

    pub fn parsed_validators(&self) -> bool {
        self.next_validators.is_some()
    }
}