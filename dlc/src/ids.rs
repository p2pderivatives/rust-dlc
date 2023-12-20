use lightning::ln::msgs::DecodeError;
use lightning::ln::ChannelId;
use lightning::util::ser::Readable;
use lightning::util::ser::Writeable;
use lightning::util::ser::Writer;

// TODO: Implement Debug/Display as hex string

/// The identifier for a DLC channel.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DlcChannelId(
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    [u8; 32],
);

impl DlcChannelId {
    /// Create a new DLC channel ID from the provided data.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the 32-byte array representation of the DLC channel ID.
    pub fn inner(&self) -> [u8; 32] {
        self.0
    }
}

impl Writeable for DlcChannelId {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.0.write(writer)
    }
}

impl Readable for DlcChannelId {
    fn read<R: std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let mut buf = [0; 32];
        reader.read_exact(&mut buf)?;

        Ok(Self(buf))
    }
}

/// The identifier for a subchannel.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubChannelId(
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::serde_utils::serialize_hex",
            deserialize_with = "crate::serde_utils::deserialize_hex_array"
        )
    )]
    [u8; 32],
);

impl SubChannelId {
    /// Create a new subchannel ID from the provided data.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get the 32-byte array representation of the subchannel ID.
    pub fn inner(&self) -> [u8; 32] {
        self.0
    }
}

impl Writeable for SubChannelId {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.0.write(writer)
    }
}

impl Readable for SubChannelId {
    fn read<R: std::io::Read>(reader: &mut R) -> Result<Self, DecodeError> {
        let mut buf = [0; 32];
        reader.read_exact(&mut buf)?;

        Ok(Self(buf))
    }
}

impl From<ChannelId> for SubChannelId {
    fn from(value: ChannelId) -> Self {
        Self::from_bytes(value.0)
    }
}

impl From<&ChannelId> for SubChannelId {
    fn from(value: &ChannelId) -> Self {
        SubChannelId::from_bytes(value.0)
    }
}

impl From<SubChannelId> for ChannelId {
    fn from(value: SubChannelId) -> Self {
        Self(value.inner())
    }
}

impl From<&SubChannelId> for ChannelId {
    fn from(value: &SubChannelId) -> Self {
        Self(value.inner())
    }
}
