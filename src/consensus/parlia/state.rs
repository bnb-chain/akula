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

#[derive(Debug)]
pub struct ParliaFinalizeState {
    system_account_balance: U256,
    system_reward_contract_balance: U256,
}

impl ParliaFinalizeState {

    pub fn new(
        system_account_balance: U256,
        system_reward_contract_balance: U256,
    ) -> ParliaFinalizeState {
        ParliaFinalizeState {
            system_account_balance,
            system_reward_contract_balance
        }
    }

    pub fn get_system_account_balance(&self) -> U256 {
        self.system_account_balance
    }

    pub fn get_system_reward_contract_balance(&self) -> U256 {
        self.system_reward_contract_balance
    }
}