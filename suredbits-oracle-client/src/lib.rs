use std::collections::HashMap;

use dlc_manager::error::Error;
use dlc_manager::Oracle;
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use dlc_messages::ser_impls::read_as_tlv;
use lightning::util::ser::Readable;
use secp256k1_zkp::XOnlyPublicKey;

pub struct SureditsOracleClient {
    name: String,
    public_key: XOnlyPublicKey,
}

fn to_oracle_error(e: reqwest::Error) -> Error {
    Error::OracleError(e.to_string())
}

impl SureditsOracleClient {
    pub fn try_new(name: &str) -> Result<Self, Error> {
        let announcements = get_announcement_map(name)?;
        let public_key = if let Some(content) = announcements.values().next() {
            println!("{:?}", content);
            let announcement = content.get_announcement();
            announcement.oracle_public_key
        } else {
            return Err(Error::InvalidParameters(
                "Oracle doesn't have any event".to_string(),
            ));
        };

        Ok(Self {
            name: name.to_string(),
            public_key,
        })
    }
}

impl Oracle for SureditsOracleClient {
    fn get_public_key(&self) -> XOnlyPublicKey {
        self.public_key.clone()
    }

    fn get_announcement(
        &self,
        event_id: &str,
    ) -> Result<OracleAnnouncement, dlc_manager::error::Error> {
        let announcements = get_announcement_map(&self.name)?;
        if let Some(content) = announcements.get(event_id) {
            return Ok(content.get_announcement());
        }

        Err(Error::OracleError("Event not found".to_string()))
    }

    fn get_attestation(
        &self,
        event_id: &str,
    ) -> Result<OracleAttestation, dlc_manager::error::Error> {
        let announcements = get_announcement_map(&self.name)?;
        if let Some(content) = announcements.get(event_id) {
            if let Some(attestation) = &content.attestations {
                let buf = bitcoin_test_utils::str_to_hex(attestation);
                Readable::read(&mut std::io::Cursor::new(buf))
                    .expect("to be able to read the announcement")
            }
        }

        Err(Error::OracleError("Event not found".to_string()))
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
struct AnnouncementContent {
    id: String,
    oracle_name: String,
    uri: Option<String>,
    announcement: String,
    attestations: Option<String>,
    outcome: String,
}

impl AnnouncementContent {
    fn get_announcement(&self) -> OracleAnnouncement {
        let buf = bitcoin_test_utils::str_to_hex(&self.announcement);
        read_as_tlv(&mut std::io::Cursor::new(buf)).expect("to be able to read the announcement")
    }
}

fn get_announcement_map(name: &str) -> Result<HashMap<String, AnnouncementContent>, Error> {
    let res: AnnouncementResp = reqwest::blocking::get(&format!(
        "https://oracle.suredbits.com/v2/announcements?oracleName={}",
        name
    ))
    .map_err(to_oracle_error)?
    .json()
    .map_err(to_oracle_error)?;

    let mut announcements = HashMap::new();

    for content in res.result {
        announcements.insert(content.id.clone(), content);
    }

    Ok(announcements)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct AnnouncementResp {
    result: Vec<AnnouncementContent>,
    error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use dlc_messages::oracle_msgs::OracleAnnouncement;
    use lightning::util::ser::Readable;

    use crate::SureditsOracleClient;

    #[test]
    fn basic_test() {
        let oracle = SureditsOracleClient::try_new("suredbits-oracle-bot").unwrap();
    }

    #[test]
    fn deser_test() {
        let input = "fdd824fd02d4c5f249d809788f01266ff14dd496cae9c7eb9e163a9a17dfbd1834b830f7c198b2387e79ee3bb0b046871af8db1e4b42325b918decbb13f4d1ff48d8e304aa4804ba9838623f02c940d20d7b185d410178cff7990c7fcf19186c7f58c7c4b8defdd822fd026e001261bdd9d8fa16f78cfa4de9d48f79120f9735ce2cb30fb07213b73ece4687bbcdcb4aec272e8022a2dad6145d83f61f0c1b180017d72f9edcffe8098ffd7f291017847cc75eab2fd7f7ad2db824dcdf5c3c900c36fcf3a3bebda13edae26e2f51800d7c9ae7c6d1bf722548254c824d193b4ff483bc735bd1c73adc419e508580be30e604388ca43db344adf84aa183b74c422aebab7ef644ccbdec2c3de60599a1d5209745761baa57d8bb29ac5466f9cd0e2102429a1d64d065dacd5b1688d5fe155ef23b844e856006a0676a295f207fd317fabfa67aa40d2d76f6e0bf01c569ce7c2c35b7c17975eccf7681b1415462ce8194808db37a6910b3864515051897cec99bb3ecd1cb1c1f075812844bee27a92b301f9eef021fe744d98606afe354c2d05c3d7ba31d047bd5d98233b0a30ebc659987eaedf4a6b0068de378e09757f7ca53bd28c2e09b1bdff1587660c00a553cfd1c8cefeec99956734064066e9370e2be2bd12e8537bfe40de79b506fe681f69692ab600e088e2b75f69db7d709984556d25ab4cb0ed90da88cf89cffa96f3874fee020144cc11c8077ca2e416f758c13e31499524751e994e91b58a3d11d89907b9e74aabd2b4f97369826fc169516fe9d3008f7a58b275ae8c2c48d369cf19cb5cb45ca0d27354fb474e44248ecedf944bd7ee0fbc6f5ea357ff3e9e64fb0e05ea7cf58843808e2e6ea862dec962bb101cad544a763a386f9738d69883da6b77e92fab7f5af15ceb1655bbfdd1b243a1e5cdc98e070910a6f0f39a885ea3a226eb884f221280d4ea102d23a613b1080fdd80a100002000642544355534400000000001213446572696269742d4254432d31305345503231";
        let hex = bitcoin_test_utils::str_to_hex(input);
        let announcement: OracleAnnouncement = read_as_tlv(&mut Cursor::new(&hex)).unwrap();
    }
}
