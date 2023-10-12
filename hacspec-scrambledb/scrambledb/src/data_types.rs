pub struct FinalizedPseudonym(pub(crate) [u8; 64]);
pub struct BlindedIdentifiableHandle(pub(crate) oprf::coprf::coprf_online::BlindInput);
pub struct BlindedPseudonymizedHandle(pub(crate) oprf::coprf::coprf_online::BlindOutput);

pub struct DataValue {
    pub(crate) attribute_name: String,
    pub(crate) value: Vec<u8>,
}

pub struct EncryptedDataValue {
    pub(crate) attribute_name: String,
    pub(crate) value: Vec<u8>,
}

pub struct IdentifiableDatum {
    pub(crate) handle: String,
    pub(crate) data_value: DataValue,
}

pub struct BlindedIdentifiableDatum {
    pub(crate) handle: BlindedIdentifiableHandle,
    pub(crate) data_value: EncryptedDataValue,
}

pub struct BlindedPseudonymizedDatum {
    pub(crate) handle: BlindedPseudonymizedHandle,
    pub(crate) data_value: EncryptedDataValue,
}

pub struct PseudonymizedDatum {
    pub(crate) handle: FinalizedPseudonym,
    pub(crate) data_value: DataValue,
}
