pub struct Pseudonym(oprf::coprf::coprf_online::Output);
pub struct BlindedIdentifiableHandle(oprf::coprf::coprf_online::BlindInput);
pub struct BlindedPseudonymizedHandle(oprf::coprf::coprf_online::BlindOutput);

pub struct DataValue {
    attribute_name: String,
    value: Vec<u8>,
}

pub struct EncryptedDataValue {
    attribute_name: String,
    value: Vec<u8>,
}

pub struct IdentifiableDatum {
    handle: String,
    data_value: DataValue,
}

pub struct BlindedIdentifiableDatum {
    handle: BlindedIdentifiableHandle,
    data_value: EncryptedDataValue,
}

pub struct BlindedPseudonymizedDatum {
    handle: BlindedPseudonymizedHandle,
    data_value: EncryptedDataValue,
}

pub struct PseudonymizedDatum {
    handle: Pseudonym,
    data_value: DataValue,
}
