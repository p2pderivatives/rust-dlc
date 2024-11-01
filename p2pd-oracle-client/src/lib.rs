//! # cg-oracle-client
//! Http client wrapper for the Crypto Garage DLC oracle

#![crate_name = "p2pd_oracle_client"]
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

use chrono::{DateTime, SecondsFormat, Utc};
use dlc_manager::error::Error as DlcManagerError;
use dlc_manager::Oracle;
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use secp256k1_zkp::{schnorr::Signature, XOnlyPublicKey};

/// Enables interacting with a DLC oracle.
pub struct P2PDOracleClient {
    host: String,
    public_key: XOnlyPublicKey,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PublicKeyResponse {
    public_key: XOnlyPublicKey,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct EventDescriptor {
    base: u16,
    is_signed: bool,
    unit: String,
    precision: i32,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct Event {
    nonces: Vec<XOnlyPublicKey>,
    event_maturity: DateTime<Utc>,
    event_id: String,
    event_descriptor: EventDescriptor,
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct AnnoucementResponse {
    oracle_public_key: XOnlyPublicKey,
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
    reqwest::blocking::get(path)
        .map_err(|x| {
            dlc_manager::error::Error::IOError(
                std::io::Error::new(std::io::ErrorKind::Other, x).into(),
            )
        })?
        .json::<T>()
        .map_err(|e| dlc_manager::error::Error::OracleError(e.to_string()))
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
        if host.is_empty() {
            return Err(DlcManagerError::InvalidParameters(
                "Invalid host".to_string(),
            ));
        }
        let host = if !host.ends_with('/') {
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
    let naive_date_time = DateTime::from_timestamp(timestamp, 0)
        .ok_or_else(|| {
            DlcManagerError::InvalidParameters(format!(
                "Invalid timestamp {} in event id",
                timestamp
            ))
        })?
        .naive_utc();
    let date_time = DateTime::from_naive_utc_and_offset(naive_date_time, Utc);
    Ok((asset_id.to_string(), date_time))
}

#[cfg(not(feature = "async"))]
impl Oracle for P2PDOracleClient {
    fn get_public_key(&self) -> XOnlyPublicKey {
        self.public_key
    }

    fn get_announcement(&self, event_id: &str) -> Result<OracleAnnouncement, DlcManagerError> {
        let (asset_id, date_time) = parse_event_id(event_id)?;
        let path = announcement_path(&self.host, &asset_id, &date_time);
        let announcement = get(&path)?;
        Ok(announcement)
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
            event_id: event_id.to_string(),
            oracle_public_key: self.public_key,
            signatures,
            outcomes: values,
        })
    }
}

#[cfg(feature = "async")]
#[async_trait::async_trait]
impl Oracle for P2PDOracleClient {
    fn get_public_key(&self) -> XOnlyPublicKey {
        self.public_key
    }

    async fn get_announcement(
        &self,
        event_id: &str,
    ) -> Result<OracleAnnouncement, DlcManagerError> {
        let (asset_id, date_time) = parse_event_id(event_id)?;
        let path = announcement_path(&self.host, &asset_id, &date_time);
        let announcement = reqwest::get(&path)
            .await
            .map_err(|x| {
                dlc_manager::error::Error::IOError(
                    std::io::Error::new(std::io::ErrorKind::Other, x).into(),
                )
            })?
            .json::<OracleAnnouncement>()
            .await
            .map_err(|e| DlcManagerError::OracleError(e.to_string()))?;

        Ok(announcement)
    }

    async fn get_attestation(
        &self,
        event_id: &str,
    ) -> Result<OracleAttestation, dlc_manager::error::Error> {
        let (asset_id, date_time) = parse_event_id(event_id)?;
        let path = attestation_path(&self.host, &asset_id, &date_time);
        let AttestationResponse {
            event_id: _,
            signatures,
            values,
        } = reqwest::get(&path)
            .await
            .map_err(|x| {
                dlc_manager::error::Error::IOError(
                    std::io::Error::new(std::io::ErrorKind::Other, x).into(),
                )
            })?
            .json::<AttestationResponse>()
            .await
            .map_err(|e| DlcManagerError::OracleError(e.to_string()))?;

        Ok(OracleAttestation {
            oracle_public_key: self.public_key,
            signatures,
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
        let expected_pk: XOnlyPublicKey =
            "ce4b7ad2b45de01f0897aa716f67b4c2f596e54506431e693f898712fe7e9bf3"
                .parse()
                .unwrap();

        let client = P2PDOracleClient::new(url).expect("Error creating client instance.");

        assert_eq!(expected_pk, client.get_public_key());
    }

    #[test]
    #[cfg(not(feature = "async"))]
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
        let _m = mock("GET", path).with_body(r#"{"announcementSignature":"f83db0ca25e4c209b55156737b0c65470a9702fe9d1d19a129994786384289397895e403ff37710095a04a0841a95738e3e8bc35bdef6bce50bf34eeb182bd9b","oraclePublicKey":"10dc8cf51ae3ee1c7967ffb9c9633a5ab06206535d8e1319f005a01ba33bc05d","oracleEvent":{"oracleNonces":["aca32fc8dead13983c655638ef921f1d38ef2f5286e58b2a1dab32b6e086e208","89603f8179830590fdce45eb17ba8bdf74e295a4633b58b46c9ede8274774164","5f3fcdfbba9ec75cb0868e04ec1f97089b4153fb2076bd1e017048e9df633aa1","8436d00f7331491dc6512e560a1f2414be42e893992eccb495642eefc7c5bf37","0d2593764c9c27eba0be3ca6c71a2de4e49a5f4aa1ce1e2cc379be3939547501","414318491e96919e67583db7a47eb1f8b4f1194bcb5b5dcc4fd10492d89926e4","b9a5ded7295e0343f385e5abedfd9e5f4137de8f67de0afa9396f7e0f996ef79","badf0bfe230ed605161630d8e3a092d7448461042db38912bc6c6a0ab195ff71","6e4780213cd7ed9de1300146079b897cae89dec7800065f615974193f58aa6db","7b12b48ad95634ee4ca476dd57e634fddc328e10276e71d27e0ae626fad7d699","a8058604adf590a1c38f8be19aa44175eb2d1130eb4d7f39a34f89f0a3fbed27","ffc3208f60b585cdc778be1290b352c34c22652d5348a87885816bcf17a80116","cb34c13f80b49e729e863035f30e1f8ea7777618eedb6d666c3b1c85a5b8a637","5000991f4631c0bba5d026f02125fdbe77e019dde57d31ce7f23ae3601a18623","094433a2432b81bbb6d6b7d65dc3498e2a7c9de5f35672d67097d54d920eadd2","11dff6b40b0938e1943c7888633d88871c2a2a1c16f412b22b80ba7ed8af8788","d5957f1a199b4abbc06894479c722ad0c4f120f0d5afeb76d589127213e33170","80e09bb453e6a0a444ec3ba222a62ecd59540b9dd8280566a17bebdfdfbd7a9e","0fe775b79b2172cb961e7c1aa54d521360903680680aaa55ea8be0404ee3768c","bfcdbb2cbcffba41048149d4bcf2a41cd5fd0a713df6f48104ade3022c284575"],"eventMaturityEpoch":1653865200,"eventDescriptor":{"digitDecompositionEvent":{"base":2,"isSigned":false,"unit":"usd/btc","precision":0,"nbDigits":20}},"eventId":"btcusd1653865200"}}"#).create();

        let client = P2PDOracleClient::new(url).expect("Error creating client instance");

        client
            .get_announcement("btcusd1624943400")
            .expect("Error getting announcement");
    }

    #[test]
    #[cfg(not(feature = "async"))]
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

        let _m = mock("GET", path).with_body(r#"{"eventId":"btcusd1653517020","signatures":["ee05b1211d5f974732b10107dd302da062be47cd18f061c5080a50743412f9fd590cad90cfea762472e6fe865c4223bd388c877b7881a27892e15843ff1ac360","59ab83597089b48f5b3c2fd07c11edffa6b1180bdb6d9e7d6924979292d9c53fe79396ceb0782d5941c284d1642377136c06b2d9c2b85bda5969a773a971b5b0","d1f8c31a83bb34433da5b9808bb3692dd212b9022b7bc8f269fc817e96a7195db18262e934bebd4e68a3f2c96550826a5530350662df4c86c004f5cf1121ca67","e5cec554c39c4dd544d70175128271eecad77c1e3eaa6994c657e257d5c1c9dcd19b041ea8030e75448245b7f91705ad914c32761671a6172f928904b439ea6b","a209116d20f0931113c0880e8cd22d3f003609a32322ff8df241ef16e7d4efd1a9b723f582a22073e21188635f09f41f270f3126014542861be14b62b09c0ecc","f1da0b482f08f545a92338392b71cec33d948a5e5732ee4d5c0a87bd6b6cc12feeb1498da7afd93ae48ec4ce581ee79c0e92f338d3777c2ef06578e4ec1a853c","d9ab68244a3b47cc8cbd5a972f2f5059fc6b9711dba8d4a7a23607a99b9655593bab3abc1d3b02402cd0809c3c7016c741742efb363227de2bcfdcf290a053b3","c1146c1767a947f77794d05a2f58e50af824e3c8d70adde883e58d2dc1ddb157323b0aaf8cfb5b076a12395756bdcda64ab5d4799e43c88a41993659e6d49471","0d29d9383c9ee41055e1cb40104c9ca75280162779c0162cb6bf9aca2b223aba17de4b3f0f29ae6b749f22ba467b7e9f05456e8abb3ec328f62b7a924c6d4828","2bcc54002ceb271a940f24bc6dd0562b99c2d76cfb8f145f42ac37bc34fd3e94adba1194c5be91932b818c5715c73f287e066e228d796a373c4aec67fd777070","a91f77e3435c577682ff744d6f7da66c865a42e8645276dedf2ed2b8bc4c80285dff4b553b2231592e0fa8b4f242acb6888519fe82c457cc5204e5d9d511303a","546409d6bcdcfd5bef39957c8b1b09f7805b08ec2311bc73cf6927ae11f3567ffe8428aa7faa661518e9c02a702212ab05e494aab84624c3dd1a710f8c4c369b","9d601ee8a3d28dcdfdd05581f1b24d6e5a576f0b5544eb7c9921cb87a23fdb293c1edca89b43b5b84c1e305fbe52facbe6b03575aed8f95b4faccc90e0eb45ef","636b8028e9cd6cba6be5b3c1789b62aecfc17e9c28d7a621cfad2c3cf751046528028e1dbd6cee050d5d570cf5a3d8986471d73e7edca4093e36fc8e1097fb65","57c6337b52dc7fd8f49b29105f168fc9b4cb88ed2ba5f0e9a80a21e20836f87f875c3fe92afb437dd5647630b54eda6ba1be76ba6df8b641eb2e8be8ff1182dc","9e8843e32f9de4cd6d5bb9e938fd014babe11bb1faf35fc411d754259bc374f34dd841ed91f6bb3f030bc55a4791cdc41471c33b3f05fd35b9d1768fd381f953","97da4963747ab5e50534b93274065cba4fd24e6b7a9d3310db2596af24f70961fb03535e2a5ae272f7ea14e86daafa57073631596fecf7ceadf4ae3e6941b69e","94a414569743f87f1462a503be8cff1f229096d190b8b1349519c612b74eea872d5d763570aaaa54fad0605a43d742203bce489deea5570750030191e293c253","4d7117b89aad73eca7b341749bd54ffdd459b9b8b4ff128344d09273f66a3d2c01d2c86b61f7642d6e81f488580b456685cd68660458cff83b8858a05c9a1f4d","b12153a393a4fddac3079c1878cb89afccfe0ac8f539743c0608049f445e49ac7c89e33fcf832cda8d7e8a4f4dae94a303170f16c697feed8b78015873bd5ffc"],"values":["0","0","0","0","0","1","1","1","0","1","0","0","0","0","1","1","1","0","1","0"]}"#).create();

        let client = P2PDOracleClient::new(url).expect("Error creating client instance");

        client
            .get_attestation("btcusd1624943400")
            .expect("Error getting attestation");
    }
}
