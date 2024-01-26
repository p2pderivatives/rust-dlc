use std::sync::OnceLock;

use dlc_manager::contract::{
    contract_info::ContractInfo,
    contract_input::{ContractInput, ContractInputInfo},
};
use dlc_messages::oracle_msgs::OracleAnnouncement;
use regex::Regex;
use secp256k1_zkp::{Secp256k1, Verification};

use crate::{error::*, ContractParams};

static TIMESTAMP_FROM_EVENTID: OnceLock<Regex> = OnceLock::new();

pub fn verify_and_get_contract_params<C: Verification, O: AsRef<[OracleAnnouncement]>>(
    secp: &Secp256k1<C>,
    contract_input: ContractInput,
    fund_serial_id: u64,
    refund_locktime: u32,
    cet_locktime: u32,
    oracle_announcements: &mut [O],
) -> Result<ContractParams> {
    let _ = &contract_input.validate().map_err(FromDlcError::Manager)?;

    (contract_input.contract_infos.len() == oracle_announcements.len())
        .then_some(())
        .ok_or(FromDlcError::InvalidState(
            "Number of contracts and Oracle Announcement set must match".to_owned(),
        ))?;

    oracle_announcements.sort_unstable_by_key(|c| {
        c.as_ref()
            .get(0)
            .expect("At least one announcement per contract")
            .oracle_event
            .event_maturity_epoch
    });

    let contract_infos = contract_input.contract_infos;

    let regex: &Regex =
        TIMESTAMP_FROM_EVENTID.get_or_init(|| Regex::new(r"/([a-z_]+)(\d+)/i").unwrap());

    let contract_timestamps = contract_infos
        .iter()
        .map(|c| {
            Ok(regex
                .captures(&c.oracles.event_id)
                .ok_or(FromDlcError::InvalidEventId)?
                .get(2)
                .ok_or(FromDlcError::InvalidEventId)?
                .as_str()
                .parse::<u32>()
                .map_err(|_| FromDlcError::InvalidEventId)?)
        })
        .collect::<Result<Vec<u32>>>()?;

    let mut contracts_ts = contract_infos
        .into_iter()
        .zip(contract_timestamps)
        .collect::<Vec<(ContractInputInfo, u32)>>();

    contracts_ts.sort_unstable_by_key(|(_, ts)| *ts);

    let sorted_contract_infos = contracts_ts
        .into_iter()
        .map(|(info, _)| info)
        .collect::<Vec<ContractInputInfo>>();

    let mut contract_info = Vec::new();
    for (x, y) in sorted_contract_infos
        .iter()
        .zip(oracle_announcements.iter())
    {
        if x.oracles.event_id != y.as_ref().get(0).unwrap().oracle_event.event_id {
            return Err(FromDlcError::InvalidState(
                "Oracle Announcement and contract info cannot be matched".to_owned(),
            ));
        }
        contract_info.push(ContractInfo {
            contract_descriptor: x.contract_descriptor.clone(),
            oracle_announcements: y.as_ref().to_vec(),
            threshold: x.oracles.threshold as usize,
        });
    }

    // Missing check on locktime for refund and contract maturity compared to oracle maturity, cf OfferMsg validate method

    // Maybe some check in validate method of offeredContract too

    for c in contract_info.iter() {
        for o in &c.oracle_announcements {
            o.validate(secp).map_err(FromDlcError::Dlc)?
        }
    }

    Ok(ContractParams {
        contract_info: contract_info.into_boxed_slice(),
        offer_collateral: contract_input.offer_collateral,
        accept_collateral: contract_input.accept_collateral,
        fund_serial_id,
        refund_locktime,
        cet_locktime,
        fee_rate_per_vb: contract_input.fee_rate,
    })
}
