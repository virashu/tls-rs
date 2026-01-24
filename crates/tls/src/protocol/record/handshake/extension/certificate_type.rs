use crate::protocol::parse::DataVec8;

pub struct ClientCertTypeExtensionClientHello {
    pub client_certificate_types: DataVec8<u8>,
}

pub struct ClientCertTypeExtensionServerHello {
    pub client_certificate_type: u8,
}

pub struct ServerCertTypeExtensionClientHello {
    pub server_certificate_types: DataVec8<u8>,
}

pub struct ServerCertTypeExtensionServerHello {
    pub server_certificate_type: u8,
}
