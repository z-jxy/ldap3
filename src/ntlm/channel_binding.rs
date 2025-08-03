use crate::ntlm::{parse_av_pairs, rebuild_av_pairs, to_utf16le};
use sha2::{Digest, Sha256};

// Channel binding types
pub const CBT_NONE: u32 = 0;
pub const CBT_TLS_SERVER_END_POINT: u32 = 1;
pub const CBT_TLS_UNIQUE: u32 = 2;

pub const NTLMSSP_AV_CHANNEL_BINDINGS: u16 = 0x0a;

pub struct ChannelBindingInfo {
    pub binding_type: u32,
    pub binding_data: Vec<u8>,
}

impl ChannelBindingInfo {
    pub fn new_tls_server_end_point(cert_der: &[u8]) -> Self {
        let binding_data = Self::generate_channel_binding_value(cert_der);
        ChannelBindingInfo {
            binding_type: CBT_TLS_SERVER_END_POINT,
            binding_data,
        }
    }

    pub fn new_tls_unique(cert_der: &[u8]) -> Self {
        let binding_data = Self::generate_channel_binding_value(cert_der);
        ChannelBindingInfo {
            binding_type: CBT_TLS_UNIQUE,
            binding_data,
        }
    }

    pub fn generate_channel_binding_value(cert_der: &[u8]) -> Vec<u8> {
        use md5::Md5;

        // Calculate SHA-256 hash of the server certificate
        let mut hasher = Sha256::new();
        hasher.update(cert_der);
        let binding_data = hasher.finalize().to_vec();

        let mut channel_binding_struct = Vec::new();
        let initiator_address = [0u8; 8];
        let acceptor_address = [0u8; 8];

        // RFC 5929 section 4
        let mut application_data_raw = b"tls-server-end-point:".to_vec();
        application_data_raw.extend_from_slice(&binding_data);

        let len_application_data = (application_data_raw.len() as u32).to_le_bytes();

        let mut application_data = Vec::new();
        application_data.extend_from_slice(&len_application_data);
        application_data.extend_from_slice(&application_data_raw);

        channel_binding_struct.extend_from_slice(&initiator_address);
        channel_binding_struct.extend_from_slice(&acceptor_address);
        channel_binding_struct.extend_from_slice(&application_data);

        let mut hasher = Md5::new();
        hasher.update(&channel_binding_struct);

        hasher.finalize().to_vec()
    }
}

// Modified function to include channel binding in AV pairs
pub fn modify_av_pairs_for_ldap_with_channel_binding(
    server_name: &[u8],
    channel_binding: Option<ChannelBindingInfo>,
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut av_pairs = parse_av_pairs(server_name)?;

    if let Some(dns_hostname) = av_pairs.get(&3) {
        let service_prefix = to_utf16le("ldap/");
        let target_name = [&service_prefix[..], dns_hostname].concat();
        av_pairs.insert(9, target_name); // NTLMSSP_AV_TARGET_NAME = 9
    }

    if let Some(cb_info) = channel_binding {
        av_pairs.insert(NTLMSSP_AV_CHANNEL_BINDINGS, cb_info.binding_data);
    }

    rebuild_av_pairs(&av_pairs)
}
