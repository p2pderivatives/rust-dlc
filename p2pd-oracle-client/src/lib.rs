//! # cg-oracle-client
//! Http client wrapper for the Crypto Garage DLC oracle

#![crate_name = "p2pd_oracle_client"]
#![crate_type = "dylib"]
#![crate_type = "rlib"]
// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(dead_code)]
#![deny(unused_imports)]
#![deny(missing_docs)]

extern crate chrono;
extern crate dlc_manager;
extern crate dlc_messages;
extern crate reqwest;
extern crate secp256k1_zkp;
extern crate serde;

use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};
use dlc_manager::error::Error as DlcManagerError;
use dlc_manager::Oracle;
use dlc_messages::oracle_msgs::{
    DigitDecompositionEventDescriptor, EventDescriptor as OracleEventDescriptor,
    OracleAnnouncement, OracleAttestation, OracleEvent,
};
use secp256k1_zkp::schnorrsig::{PublicKey, Signature};

/// Enables interacting with a DLC oracle.
pub struct P2PDOracleClient {
    host: String,
    public_key: PublicKey,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyResponse {
    public_key: PublicKey,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct EventDescriptor {
    base: u64,
    is_signed: bool,
    unit: String,
    precision: i32,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Event {
    nonces: Vec<PublicKey>,
    event_maturity: DateTime<Utc>,
    event_id: String,
    event_descriptor: EventDescriptor,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AnnoucementResponse {
    oracle_public_key: PublicKey,
    oracle_event: Event,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AttestationResponse {
    event_id: String,
    signatures: Vec<Signature>,
    values: Vec<String>,
}

fn get<T>(path: &str) -> Result<T, DlcManagerError>
where
    T: serde::de::DeserializeOwned,
{
    Ok(reqwest::blocking::get(path)
        .map_err(|x| {
            dlc_manager::error::Error::IOError(std::io::Error::new(std::io::ErrorKind::Other, x))
        })?
        .json::<T>()
        .map_err(|e| dlc_manager::error::Error::OracleError(e.to_string()))?)
}

fn pubkey_path(host: &str) -> String {
    format!("{}{}", host, "oracle/publickey")
}

fn announcement_path(host: &str, asset_id: &str, date_time: &DateTime<Utc>) -> String {
    format!(
        "{}asset/{}/announcement/{}",
        host,
        asset_id,
        date_time.to_rfc3339_opts(SecondsFormat::Secs, true)
    )
}

fn attestation_path(host: &str, asset_id: &str, date_time: &DateTime<Utc>) -> String {
    format!(
        "{}asset/{}/attestation/{}",
        host,
        asset_id,
        date_time.to_rfc3339_opts(SecondsFormat::Secs, true)
    )
}

impl P2PDOracleClient {
    /// Try to create an instance of an oracle client connecting to the provided
    /// host. Returns an error if the host could not be reached. Panics if the
    /// oracle uses an incompatible format.
    pub fn new(host: &str) -> Result<P2PDOracleClient, DlcManagerError> {
        if host.len() < 1 {
            return Err(DlcManagerError::InvalidParameters(
                "Invalid host".to_string(),
            ));
        }
        let host = if host.chars().last().unwrap() != '/' {
            format!("{}{}", host, "/")
        } else {
            host.to_string()
        };
        let path = pubkey_path(&host);
        let public_key = get::<PublicKeyResponse>(&path)?.public_key;
        Ok(P2PDOracleClient { host, public_key })
    }
}

fn parse_event_id(event_id: &str) -> Result<(String, DateTime<Utc>), DlcManagerError> {
    let asset_id = &event_id[..6];
    let timestamp_str = &event_id[6..];
    let timestamp: i64 = timestamp_str
        .parse()
        .map_err(|_| DlcManagerError::OracleError("Invalid timestamp format".to_string()))?;
    let naive_date_time = NaiveDateTime::from_timestamp(timestamp, 0);
    let date_time = DateTime::from_utc(naive_date_time, Utc);
    Ok((asset_id.to_string(), date_time))
}

impl Oracle for P2PDOracleClient {
    fn get_public_key(&self) -> PublicKey {
        self.public_key
    }

    fn get_announcement(&self, event_id: &str) -> Result<OracleAnnouncement, DlcManagerError> {
        let (asset_id, date_time) = parse_event_id(event_id)?;
        let path = announcement_path(&self.host, &asset_id, &date_time);
        let AnnoucementResponse {
            oracle_public_key,
            oracle_event,
        } = get(&path)?;
        let Event {
            nonces,
            event_maturity,
            event_id,
            event_descriptor,
        } = oracle_event;
        let EventDescriptor {
            base,
            is_signed,
            unit,
            precision,
        } = event_descriptor;
        Ok(OracleAnnouncement {
            // TODO(tibo): fix once oracle provides signatures.
            announcement_signature: "67159dad98bdc1ee51169bece3b1da1ab7f918697a084afce3db639388757d1bfacf0a4d725fc8e09ed97dac559a0e89648e04cb64405ae5a3ba3280c3eef1ff".parse().unwrap(),
            oracle_public_key,
            oracle_event: OracleEvent {
                event_descriptor: OracleEventDescriptor::DigitDecompositionEvent(DigitDecompositionEventDescriptor {
                    base,
                    is_signed,
                    unit,
                    precision,
                    nb_digits: nonces.len() as u16,
                }),
                oracle_nonces: nonces,
                event_maturity_epoch: event_maturity.timestamp() as u32,
                event_id,
            }
        })
    }

    fn get_attestation(
        &self,
        event_id: &str,
    ) -> Result<OracleAttestation, dlc_manager::error::Error> {
        let (asset_id, date_time) = parse_event_id(event_id)?;
        let path = attestation_path(&self.host, &asset_id, &date_time);
        let AttestationResponse {
            event_id: _,
            signatures,
            values,
        } = get::<AttestationResponse>(&path)?;

        Ok(OracleAttestation {
            oracle_public_key: self.public_key,
            signatures: signatures,
            outcomes: values,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate mockito;
    use self::mockito::{mock, Mock};
    use super::*;

    #[test]
    fn parse_event_test() {
        let event_id = "btcusd1624943400";
        let expected_asset_id = "btcusd";
        let expected_date_time = DateTime::parse_from_rfc3339("2021-06-29T05:10:00Z").unwrap();

        let (asset_id, date_time) = parse_event_id(event_id).expect("Error parsing event id");

        assert_eq!(expected_asset_id, asset_id);
        assert_eq!(expected_date_time, date_time);
    }

    fn pubkey_mock() -> Mock {
        let path: &str = &pubkey_path("/");
        mock("GET", path).with_body(
            r#"{"publicKey":"ce4b7ad2b45de01f0897aa716f67b4c2f596e54506431e693f898712fe7e9bf3"}"#,
        ).create()
    }

    #[test]
    fn get_public_key_test() {
        let url = &mockito::server_url();
        let _m = pubkey_mock();
        let expected_pk: PublicKey =
            "ce4b7ad2b45de01f0897aa716f67b4c2f596e54506431e693f898712fe7e9bf3"
                .parse()
                .unwrap();

        let client = P2PDOracleClient::new(url).expect("Error creating client instance.");

        assert_eq!(expected_pk, client.get_public_key());
    }

    #[test]
    fn get_announcement_test() {
        let url = &mockito::server_url();
        let _pubkey_mock = pubkey_mock();
        let path: &str = &announcement_path(
            "/",
            "btcusd",
            &DateTime::parse_from_rfc3339("2021-06-29T05:10:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        let _m = mock("GET", path).with_body(r#"{"announcementSignature":"","oraclePublicKey":"ce4b7ad2b45de01f0897aa716f67b4c2f596e54506431e693f898712fe7e9bf3","oracleEvent":{"nonces":["67159dad98bdc1ee51169bece3b1da1ab7f918697a084afce3db639388757d1b","c16534f0d1af941c0ebf5ba6abfbc261e971c64760234dfd014ca3104ea92dd6","fabe57869a532b1c4897b6b0d91a46edf7aab42beba86222cd70938a01eaa31c","4b79ac4881f1d2a9fb08c8dba729efeac8dde8105beb52b8dc504e572c023cfc","2a70113f552fb13daeaede084f025c12b9adceec4b45cb9551786d0e1816f023","fc29bd5e51a3cd4d8e08fe048656902a7ec77faeb7ff7cceb87b61dcf0f836b3","cd02a305b00c56c3612a22f2e81229c57b8a485a7abd7bc392b6c65257004ee9","8db688a597a2093378756e8da5e9cdc197cbe9a1d4e9c2b574bb986c66d3d21b","97ad0813677160c2cb6c6edcbc56d5256522a03e26f64974bb22c85401ebfce3","4c74604c5c8d11948263f8071d7aa1cb89bfb495489775bea778eaa9612c1ba1","59970d93d54e75a1fecd2ce3394aed0c184ea4611d519411895874921172bf11","4a7e3e6bb7c2bc3e2e70c29f65ad7daf112229df0691ad4985e8d6f4fb2474ec","c2295ced31c1f0617717345c5177f7928e04ff35cf3d1ca45406efcfe52ed205","828f9cfa5fda87eccacea2514f21db6cbe952586b9124f10c605a5be8ebdc174","0fd3335a4314ff5fe03921fc25eb300613dfe57aedc5fa196a1027529aa1782b","eb97fa3225f9ef6a5c954f34754772691fe7b48b4c4e292c766fc83d8b2a7829","4fcc19540a059f240154357ba3a44966b32bd2696df34ce059e750fce15c2c91","93e932cd5c518f38ca36e87495f2bbd8926db3789f4c0cc6c0d7f585b0bf6107","b3b35b0ec2dc8b24812c67b77a5930960d606101b43b168e0f7b29fbfd5dc58b","167033cbecb3d07f23314e701de6728b5debbf568001317c06f74ae4355739ea"],"eventMaturity":"2021-06-29T05:10:00Z","eventDescriptor":{"base":2,"isSigned":false,"unit":"","precision":0},"eventId":"btcusd1624943400"}}"#).create();

        let client = P2PDOracleClient::new(url).expect("Error creating client instance");

        client
            .get_announcement("btcusd1624943400")
            .expect("Error getting announcement");
    }

    #[test]
    fn get_attestation_test() {
        let url = &mockito::server_url();
        let _pubkey_mock = pubkey_mock();
        let path: &str = &attestation_path(
            "/",
            "btcusd",
            &DateTime::parse_from_rfc3339("2021-06-29T05:10:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );

        let _m = mock("GET", path).with_body(r#"{"eventId":"btcusd1624943400","signatures":["67159dad98bdc1ee51169bece3b1da1ab7f918697a084afce3db639388757d1bfacf0a4d725fc8e09ed97dac559a0e89648e04cb64405ae5a3ba3280c3eef1ff","c16534f0d1af941c0ebf5ba6abfbc261e971c64760234dfd014ca3104ea92dd65aa17d3431ee703d2041105a35e9e7b4e240a329df672cd92253eba003c4bd73","fabe57869a532b1c4897b6b0d91a46edf7aab42beba86222cd70938a01eaa31c3cad8670e60961688ec861b19a23bac52dca5a3e32e20873fa5e70cbd0c4ecfc","4b79ac4881f1d2a9fb08c8dba729efeac8dde8105beb52b8dc504e572c023cfc0b8eef8299fab553b16bcef2a38b48ecd8d54b64cc8cc19a9f9ab5afa3a31412","2a70113f552fb13daeaede084f025c12b9adceec4b45cb9551786d0e1816f0230c593dcc4f7f5087ce55badb34f7735e7495884189b7cc6870b90463f91cd85a","fc29bd5e51a3cd4d8e08fe048656902a7ec77faeb7ff7cceb87b61dcf0f836b3111b13301efc5b95109171476259819569167d83b99bee50273f5abd2bcd9e63","cd02a305b00c56c3612a22f2e81229c57b8a485a7abd7bc392b6c65257004ee9e119307cc7f46e95e6355bcfa28778d016c6dab4e65f54e2c45df117b34df9f2","8db688a597a2093378756e8da5e9cdc197cbe9a1d4e9c2b574bb986c66d3d21b045ce89846fd7ab014795070c31c9dfaa1240400a85414899aa502fc0bf2353e","97ad0813677160c2cb6c6edcbc56d5256522a03e26f64974bb22c85401ebfce3e0cdb1e26d762904c9b86f8a21bbee517c3e32df65e6a8077c60efd4a2b07c00","4c74604c5c8d11948263f8071d7aa1cb89bfb495489775bea778eaa9612c1ba139af8cb7816a96b449b5b2df65e233492484430a434af7aacb14dffd310c2d27","59970d93d54e75a1fecd2ce3394aed0c184ea4611d519411895874921172bf1188a760cb680e93798430828817f4ccad8dab23b15101570498a622de5f204680","4a7e3e6bb7c2bc3e2e70c29f65ad7daf112229df0691ad4985e8d6f4fb2474ecde0542ade92f85682302ee9dde4a294128a71fe2e89e6ed3704b8b299405c1ea","c2295ced31c1f0617717345c5177f7928e04ff35cf3d1ca45406efcfe52ed2055806cbe37a19f9bea8440c6b6f46dc6f39f1534852eb17acbb1f2460ac5814e0","828f9cfa5fda87eccacea2514f21db6cbe952586b9124f10c605a5be8ebdc174eee7eb28a32447a3556542709e0f6f1f31dccbc07bce87ef2603d25d0332921d","0fd3335a4314ff5fe03921fc25eb300613dfe57aedc5fa196a1027529aa1782b3cb111011298ddd2bd3d6143b634b90d3cb357390e4a5cd8a9f572d0d77ab928","eb97fa3225f9ef6a5c954f34754772691fe7b48b4c4e292c766fc83d8b2a7829aa08565f425bd968cece42814391501d3911a297629cbd995fb0caf0616aadd5","4fcc19540a059f240154357ba3a44966b32bd2696df34ce059e750fce15c2c91246ec329b5ebe48a928e17d6c3c9a48bb5922dbadc2f8b53091690dc29aafa35","93e932cd5c518f38ca36e87495f2bbd8926db3789f4c0cc6c0d7f585b0bf6107a452635270dcdd81bb5f9d72c58332bdca0d24310b59c6e0dd73ca8b854d0930","b3b35b0ec2dc8b24812c67b77a5930960d606101b43b168e0f7b29fbfd5dc58bf82d9e459a68d4600474d4c0330ff4eb8e27b823f2b570742c83c96c0ec25af0","167033cbecb3d07f23314e701de6728b5debbf568001317c06f74ae4355739eae0fe1b1dae4f7df55a44250b730c40a2907e63dd96b7b0bcdf64c09bbda65c6e"],"values":["0","0","0","0","1","0","0","0","0","1","1","1","1","0","1","1","1","1","1","0"]}"#).create();

        let client = P2PDOracleClient::new(url).expect("Error creating client instance");

        client
            .get_attestation("btcusd1624943400")
            .expect("Error getting attestation");
    }
}
