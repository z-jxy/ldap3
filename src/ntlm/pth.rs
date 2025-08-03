//! Pass-The-Hash (PTH) module for NTLM authentication

use super::constants::*;
use crate::{
    ntlm::{
        channel_binding::{modify_av_pairs_for_ldap_with_channel_binding, ChannelBindingInfo},
        NtlmHashBytes,
    },
    result::Result,
};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use hmac::{Hmac, Mac};
use md5::Md5;
// use sspi::Ntlm;
use std::io::{Cursor, Read};

type HmacMd5 = Hmac<Md5>;

// struct NtlmAuthNegotiate {
//     #[allow(dead_code)]
//     flags: u32,
// }

// impl Default for NtlmAuthNegotiate {
//     fn default() -> Self {
//         Self {
//             flags: NTLMSSP_NEGOTIATE_128
//                 | NTLMSSP_NEGOTIATE_KEY_EXCH
//                 | NTLMSSP_NEGOTIATE_NTLM
//                 | NTLMSSP_NEGOTIATE_UNICODE
//                 | NTLMSSP_NEGOTIATE_SIGN
//                 | NTLMSSP_NEGOTIATE_SEAL,
//         }
//     }
// }

pub fn create_ntlmv1_type1_message(domain: &str) -> Result<Vec<u8>> {
    let mut msg = Vec::new();

    // NTLM signature
    msg.extend_from_slice(b"NTLMSSP\0");

    // Message type (1)
    msg.write_u32::<LittleEndian>(1)?;

    // Flags for NTLMv1
    let flags = 0x00000002 | // OEM
                0x00000004 | // Request Target
                0x00000200 | // NTLM
                0x00008000; // Always Sign
    msg.write_u32::<LittleEndian>(flags)?;

    // Domain length and allocation
    msg.write_u16::<LittleEndian>(domain.len() as u16)?;
    msg.write_u16::<LittleEndian>(domain.len() as u16)?;
    msg.write_u32::<LittleEndian>(32)?; // Offset

    // Workstation length and allocation (empty)
    msg.write_u16::<LittleEndian>(0)?;
    msg.write_u16::<LittleEndian>(0)?;
    msg.write_u32::<LittleEndian>(32 + domain.len() as u32)?;

    // Domain string (uppercase)
    msg.extend_from_slice(domain.to_uppercase().as_bytes());

    Ok(msg)
}

pub fn parse_ntlmv1_type2_message(msg: &[u8]) -> Result<([u8; 8], Vec<u8>)> {
    let mut cursor = Cursor::new(msg);

    // Skip signature and message type
    cursor.set_position(8);
    let _msg_type = cursor.read_u32::<LittleEndian>()?;

    // Skip target name info
    cursor.set_position(20);
    let _flags = cursor.read_u32::<LittleEndian>()?;

    // Read server challenge
    let mut challenge = [0u8; 8];
    cursor.read_exact(&mut challenge)?;

    // Skip reserved
    cursor.set_position(cursor.position() + 8);

    // Read target info
    let target_info_len = cursor.read_u16::<LittleEndian>()? as usize;
    let _target_info_alloc = cursor.read_u16::<LittleEndian>()?;
    let target_info_offset = cursor.read_u32::<LittleEndian>()? as usize;

    let mut target_info = vec![0u8; target_info_len];
    if target_info_len > 0 && target_info_offset < msg.len() {
        let end_offset = std::cmp::min(target_info_offset + target_info_len, msg.len());
        target_info.copy_from_slice(&msg[target_info_offset..end_offset]);
    }

    Ok((challenge, target_info))
}

pub fn create_ntlmv1_type3_message(
    username: &str,
    domain: &str,
    ntlm_hash: &NtlmHashBytes,
    server_challenge: &[u8; 8],
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    let ntlm_response = calculate_ntlmv1_response(ntlm_hash, server_challenge)?;

    // 3x8 DES blocks
    assert_eq!(
        ntlm_response.len(),
        24,
        "NTLMv1 (type3) response should be 24 bytes"
    );

    // For LM response, use the same as NTLM response when using NTLM hash
    let lm_response = ntlm_response;

    // UTF-16LE encoding for strings with NEGOTIATE_UNICODE flag
    let domain_utf16 = to_utf16le(domain);
    let username_utf16 = to_utf16le(username);
    let workstation_utf16 = Vec::new(); // Empty workstation
    let session_key = Vec::new(); // Empty session key

    // Calculate data offsets
    let base_offset = 64; // Standard Type 3 header size

    let domain_offset = base_offset;
    let user_offset = domain_offset + domain_utf16.len();
    let host_offset = user_offset + username_utf16.len();
    let lanman_offset = host_offset + workstation_utf16.len();
    let ntlm_offset = lanman_offset + lm_response.len();
    let session_key_offset = ntlm_offset + ntlm_response.len();

    // Build Type 3 message
    let mut msg = Vec::new();

    // NTLM signature
    msg.extend_from_slice(b"NTLMSSP\0");

    // Message type (3)
    msg.write_u32::<LittleEndian>(3)?;

    // LM Response
    msg.write_u16::<LittleEndian>(lm_response.len() as u16)?;
    msg.write_u16::<LittleEndian>(lm_response.len() as u16)?;
    msg.write_u32::<LittleEndian>(lanman_offset as u32)?;

    // NTLM Response
    msg.write_u16::<LittleEndian>(ntlm_response.len() as u16)?;
    msg.write_u16::<LittleEndian>(ntlm_response.len() as u16)?;
    msg.write_u32::<LittleEndian>(ntlm_offset as u32)?;

    // Domain
    msg.write_u16::<LittleEndian>(domain_utf16.len() as u16)?;
    msg.write_u16::<LittleEndian>(domain_utf16.len() as u16)?;
    msg.write_u32::<LittleEndian>(domain_offset as u32)?;

    // Username
    msg.write_u16::<LittleEndian>(username_utf16.len() as u16)?;
    msg.write_u16::<LittleEndian>(username_utf16.len() as u16)?;
    msg.write_u32::<LittleEndian>(user_offset as u32)?;

    // Workstation (empty)
    msg.write_u16::<LittleEndian>(workstation_utf16.len() as u16)?;
    msg.write_u16::<LittleEndian>(workstation_utf16.len() as u16)?;
    msg.write_u32::<LittleEndian>(host_offset as u32)?;

    // Session Key (empty)
    msg.write_u16::<LittleEndian>(session_key.len() as u16)?;
    msg.write_u16::<LittleEndian>(session_key.len() as u16)?;
    msg.write_u32::<LittleEndian>(session_key_offset as u32)?;

    let flags = 0x62088215u32; // NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_ALWAYS_SIGN | others
    msg.write_u32::<LittleEndian>(flags)?;

    // Pad to base offset
    while msg.len() < base_offset {
        msg.push(0);
    }

    msg.extend_from_slice(&domain_utf16);
    msg.extend_from_slice(&username_utf16);
    msg.extend_from_slice(&workstation_utf16);
    msg.extend_from_slice(&lm_response);
    msg.extend_from_slice(&ntlm_response);
    msg.extend_from_slice(&session_key);

    Ok(msg)
}

#[inline]
fn calculate_ntlmv1_response(
    ntlm_hash: &NtlmHashBytes,
    challenge: &[u8; 8],
) -> std::result::Result<[u8; 24], Box<dyn std::error::Error>> {
    trace!("NTLM hash: {}", hex::encode(ntlm_hash));
    trace!("Challenge: {}", hex::encode(challenge));

    let response = ntlmssp_des_encrypt(ntlm_hash, challenge)?;

    trace!("Final NTLM response: {}", hex::encode(response));

    Ok(response)
}

pub fn calculate_ntlmv2_hash(
    username: &str,
    domain: &str,
    nt_hash: &[u8],
) -> std::result::Result<[u8; 16], Box<dyn std::error::Error>> {
    // NTLMv2 hash = HMAC-MD5(NT_hash, uppercase(username) + uppercase(domain))
    let user_domain = format!("{}{}", username.to_uppercase(), domain);
    let user_domain_utf16 = to_utf16le(&user_domain);

    let mut hmac = HmacMd5::new_from_slice(nt_hash)?;
    hmac.update(&user_domain_utf16);
    let result = hmac.finalize().into_bytes();

    let mut hash = [0u8; 16];
    hash.copy_from_slice(&result);
    Ok(hash)
}

pub fn create_ntlmv2_type3_message(
    username: &str,
    domain: &str,
    lm_challenge_response: &[u8],
    ntlm_challenge_response: &[u8],
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut type3_msg = Vec::new();
    type3_msg.extend_from_slice(b"NTLMSSP\0");
    type3_msg.write_u32::<LittleEndian>(3)?;

    // Use the responses from computeResponseNTLMv2
    let domain_utf16 = to_utf16le(domain);
    let username_utf16 = to_utf16le(username);
    let workstation_utf16 = Vec::new();
    let session_key = Vec::new();

    // Calculate offsets
    let base_offset = 64;
    let domain_offset = base_offset;
    let user_offset = domain_offset + domain_utf16.len();
    let host_offset = user_offset + username_utf16.len();
    let lanman_offset = host_offset + workstation_utf16.len();
    let ntlm_offset = lanman_offset + lm_challenge_response.len();
    let session_key_offset = ntlm_offset + ntlm_challenge_response.len();

    // LM Response
    type3_msg.write_u16::<LittleEndian>(lm_challenge_response.len() as u16)?;
    type3_msg.write_u16::<LittleEndian>(lm_challenge_response.len() as u16)?;
    type3_msg.write_u32::<LittleEndian>(lanman_offset as u32)?;

    // NTLM Response
    type3_msg.write_u16::<LittleEndian>(ntlm_challenge_response.len() as u16)?;
    type3_msg.write_u16::<LittleEndian>(ntlm_challenge_response.len() as u16)?;
    type3_msg.write_u32::<LittleEndian>(ntlm_offset as u32)?;

    // Domain
    type3_msg.write_u16::<LittleEndian>(domain_utf16.len() as u16)?;
    type3_msg.write_u16::<LittleEndian>(domain_utf16.len() as u16)?;
    type3_msg.write_u32::<LittleEndian>(domain_offset as u32)?;

    // Username
    type3_msg.write_u16::<LittleEndian>(username_utf16.len() as u16)?;
    type3_msg.write_u16::<LittleEndian>(username_utf16.len() as u16)?;
    type3_msg.write_u32::<LittleEndian>(user_offset as u32)?;

    // Workstation
    type3_msg.write_u16::<LittleEndian>(0)?;
    type3_msg.write_u16::<LittleEndian>(0)?;
    type3_msg.write_u32::<LittleEndian>(host_offset as u32)?;

    // Session Key
    type3_msg.write_u16::<LittleEndian>(0)?;
    type3_msg.write_u16::<LittleEndian>(0)?;
    type3_msg.write_u32::<LittleEndian>(session_key_offset as u32)?;

    // Flags
    type3_msg.write_u32::<LittleEndian>(0x62088215)?;

    // Pad to 64 bytes
    while type3_msg.len() < 64 {
        type3_msg.push(0);
    }

    // Add data
    type3_msg.extend_from_slice(&domain_utf16);
    type3_msg.extend_from_slice(&username_utf16);
    type3_msg.extend_from_slice(&workstation_utf16);
    type3_msg.extend_from_slice(lm_challenge_response);
    type3_msg.extend_from_slice(ntlm_challenge_response);
    type3_msg.extend_from_slice(&session_key);

    Ok(type3_msg)
}

fn get_windows_filetime() -> u64 {
    // Convert Unix timestamp to Windows FILETIME
    let unix_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Windows FILETIME is 100-nanosecond intervals since Jan 1, 1601
    (unix_time + 11644473600) * 10_000_000
}

pub fn create_ntlmv2_type1_message(
    domain: &str,
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut msg = Vec::new();

    // NTLM signature
    msg.extend_from_slice(b"NTLMSSP\0");

    // Message type (1)
    msg.write_u32::<LittleEndian>(1)?;

    // // // Flags - Use the exact flags that work for NTLMv2
    // // // These flags must match what the server expects
    // let _flags = 0xa2088207u32; // NEGOTIATE_UNICODE | NEGOTIATE_NTLM | NEGOTIATE_ALWAYS_SIGN | NEGOTIATE_EXTENDED_SESSIONSECURITY | NEGOTIATE_TARGET_INFO | NEGOTIATE_128 | NEGOTIATE_56

    // let mut auth = NtlmAuthNegotiate::default();
    // let mut flags = auth.flags;

    let mut flags = 0;

    // for ntlmv2
    flags |= NTLMSSP_NEGOTIATE_TARGET_INFO;

    flags |= NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_56;

    msg.write_u32::<LittleEndian>(flags)?;

    let domain_bytes = domain.as_bytes();
    msg.write_u16::<LittleEndian>(domain_bytes.len() as u16)?; // Domain length
    msg.write_u16::<LittleEndian>(domain_bytes.len() as u16)?; // Domain max length
    msg.write_u32::<LittleEndian>(32)?; // Domain offset (after header)

    // Workstation fields (empty)
    msg.write_u16::<LittleEndian>(0)?; // Workstation length
    msg.write_u16::<LittleEndian>(0)?; // Workstation max length
    msg.write_u32::<LittleEndian>((32 + domain_bytes.len()) as u32)?; // Workstation offset

    // Add domain string
    msg.extend_from_slice(domain_bytes);

    Ok(msg)
}

pub fn str_to_utf16le(s: &str) -> Vec<u8> {
    let utf16: Vec<u16> = s.encode_utf16().collect();
    let mut bytes = Vec::with_capacity(utf16.len() * 2);
    for word in utf16 {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[inline]
pub fn to_utf16le(s: &str) -> Vec<u8> {
    str_to_utf16le(s)
}

fn ntlmssp_des_encrypt(
    key: &[u8],
    challenge: &[u8; 8],
) -> std::result::Result<[u8; 24], Box<dyn std::error::Error>> {
    use des::{
        cipher::{BlockEncrypt, KeyInit},
        Des,
    };
    let mut answer = [0u8; 24];

    // Split key into 3 parts and encrypt with each
    let key1 = __expand_des_key(&key[0..7]);
    let key2 = __expand_des_key(&key[7..14]);
    let key3 = __expand_des_key(&key[14..]);

    let cipher1 = Des::new_from_slice(&key1)?;
    let mut block1 = *challenge;
    cipher1.encrypt_block((&mut block1).into());
    answer[0..8].copy_from_slice(&block1);

    let cipher2 = Des::new_from_slice(&key2)?;
    let mut block2 = *challenge;
    cipher2.encrypt_block((&mut block2).into());
    answer[8..16].copy_from_slice(&block2);

    let cipher3 = Des::new_from_slice(&key3)?;
    let mut block3 = *challenge;
    cipher3.encrypt_block((&mut block3).into());
    answer[16..24].copy_from_slice(&block3);

    trace!("DES Block1: {}", hex::encode(block1));
    trace!("DES Block2: {}", hex::encode(block2));
    trace!("DES Block3: {}", hex::encode(block3));

    Ok(answer)
}

fn __expand_des_key(key: &[u8]) -> [u8; 8] {
    let mut key_bytes = [0u8; 7];
    let len = std::cmp::min(key.len(), 7);
    key_bytes[..len].copy_from_slice(&key[..len]);

    let mut s = [0u8; 8];
    s[0] = ((key_bytes[0] >> 1) & 0x7f) << 1;
    s[1] = ((key_bytes[0] & 0x01) << 6 | ((key_bytes[1] >> 2) & 0x3f)) << 1;
    s[2] = ((key_bytes[1] & 0x03) << 5 | ((key_bytes[2] >> 3) & 0x1f)) << 1;
    s[3] = ((key_bytes[2] & 0x07) << 4 | ((key_bytes[3] >> 4) & 0x0f)) << 1;
    s[4] = ((key_bytes[3] & 0x0f) << 3 | ((key_bytes[4] >> 5) & 0x07)) << 1;
    s[5] = ((key_bytes[4] & 0x1f) << 2 | ((key_bytes[5] >> 6) & 0x03)) << 1;
    s[6] = ((key_bytes[5] & 0x3f) << 1 | ((key_bytes[6] >> 7) & 0x01)) << 1;
    s[7] = (key_bytes[6] & 0x7f) << 1;

    s
}

pub fn extract_ntlm_from_spnego(
    data: &[u8],
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    data.windows(8)
        .position(|w| w == b"NTLMSSP\0")
        .map(|pos| data[pos..].to_vec())
        .ok_or("No NTLM signature found in SPNEGO data".into())
}

pub fn compute_response_ntlmv2(
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    server_name: &[u8], // TargetInfo from Type 2
    domain: &str,
    user: &str,
    nt_hash: &[u8],
    channel_binding: Option<ChannelBindingInfo>,
) -> std::result::Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    trace!("computeResponseNTLMv2 inputs:");
    trace!("   server_challenge: {}", hex::encode(server_challenge));
    trace!("   client_challenge: {}", hex::encode(client_challenge));
    trace!("   user: '{user}'");
    trace!("   domain: '{domain}'");
    trace!("   nt_hash: {}", hex::encode(nt_hash));
    trace!("   original server_name length: {}", server_name.len());

    // calculate NTLMv2 hash
    let response_key_nt = calculate_ntlmv2_hash(user, domain, nt_hash)?;
    trace!("   response_key_nt: {}", hex::encode(response_key_nt));

    let modified_server_name = match channel_binding {
        Some(cbi) => {
            // debug!("Using channel binding data: {}", hex::encode(bytes));
            // let channel_binding = ChannelBindingInfo {
            //     binding_type: CBT_TLS_UNIQUE, // Assuming TLS_UNIQUE for simplicity
            //     binding_data: bytes.to_vec(), // Use the provided channel binding data
            // };
            modify_av_pairs_for_ldap_with_channel_binding(server_name, Some(cbi))?
        }
        None => modify_av_pairs_for_ldap(server_name)?,
    };
    // let modified_server_name = modify_av_pairs_for_ldap(server_name)?;
    trace!(
        "   modified server_name length: {}",
        modified_server_name.len()
    );

    let timestamp = get_windows_filetime();
    let a_time = timestamp.to_le_bytes();
    trace!("   timestamp: {}", hex::encode(a_time));

    let mut temp =
        Vec::with_capacity(12 + a_time.len() + client_challenge.len() + modified_server_name.len());
    temp.push(0x01); // responseServerVersion
    temp.push(0x01); // hiResponseServerVersion
    temp.extend_from_slice(&[0x00, 0x00]); // Reserved1 (2 bytes)
    temp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved2 (4 bytes)
    temp.extend_from_slice(&a_time); // TimeStamp (8 bytes)
    temp.extend_from_slice(client_challenge); // ChallengeFromClient (8 bytes)
    temp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // Reserved3 (4 bytes)
    temp.extend_from_slice(&modified_server_name); // Modified AvPairs

    trace!("   temp blob length: {}", temp.len());
    trace!(
        "   temp blob (first 32 bytes): {}",
        hex::encode(&temp[..32.min(temp.len())])
    );

    // Calculate ntProofStr = HMAC_MD5(ResponseKeyNT, ServerChallenge + temp)
    let challenge_temp = [&server_challenge[..], &temp[..]].concat();
    let mut hmac = HmacMd5::new_from_slice(&response_key_nt)?;
    hmac.update(&challenge_temp);
    let nt_proof_str = hmac.finalize().into_bytes();

    trace!("   nt_proof_str: {}", hex::encode(nt_proof_str));

    // NTLMv2 response = ntProofStr + temp
    let ntlm_challenge_response = [&nt_proof_str[..], &temp[..]].concat();

    // LMv2 response = HMAC_MD5(ResponseKeyNT, ServerChallenge + ClientChallenge) + ClientChallenge
    let challenge_data = [&server_challenge[..], &client_challenge[..]].concat();
    let mut hmac2 = HmacMd5::new_from_slice(&response_key_nt)?;
    hmac2.update(&challenge_data);
    let lm_response_part = hmac2.finalize().into_bytes();
    let lm_challenge_response = [&lm_response_part[..], &client_challenge[..]].concat();

    trace!("   lm_response_part: {}", hex::encode(lm_response_part));
    trace!(
        "   final ntlm_challenge_response length: {}",
        ntlm_challenge_response.len()
    );
    trace!(
        "   final lm_challenge_response length: {}",
        lm_challenge_response.len()
    );

    Ok((ntlm_challenge_response, lm_challenge_response))
}

fn modify_av_pairs_for_ldap(
    server_name: &[u8],
    // channel_binding: Option<&[u8]>,
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Parse the existing AV_PAIRS
    let mut av_pairs = parse_av_pairs(server_name)?;

    // Add SPN target name
    // av_pairs[NTLMSSP_AV_TARGET_NAME] = f"{service}/".encode('utf-16le') + av_pairs[NTLMSSP_AV_DNS_HOSTNAME][1]
    if let Some(dns_hostname) = av_pairs.get(&3) {
        // NTLMSSP_AV_DNS_HOSTNAME = 3
        let service_prefix = to_utf16le("ldap/");
        let target_name = [&service_prefix[..], dns_hostname].concat();
        av_pairs.insert(9, target_name); // NTLMSSP_AV_TARGET_NAME = 9
    }

    // Rebuild the AV_PAIRS data
    rebuild_av_pairs(&av_pairs)
}

pub fn parse_av_pairs(
    data: &[u8],
) -> std::result::Result<std::collections::HashMap<u16, Vec<u8>>, Box<dyn std::error::Error>> {
    let mut pairs = std::collections::HashMap::new();
    let mut cursor = std::io::Cursor::new(data);

    loop {
        let av_id = cursor.read_u16::<LittleEndian>()?;
        let av_len = cursor.read_u16::<LittleEndian>()? as usize;

        if av_id == 0 {
            // NTLMSSP_AV_EOL
            break;
        }

        let mut av_value = vec![0u8; av_len];
        cursor.read_exact(&mut av_value)?;

        pairs.insert(av_id, av_value);
    }

    Ok(pairs)
}

pub fn rebuild_av_pairs(
    pairs: &std::collections::HashMap<u16, Vec<u8>>,
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut data = Vec::new();

    for (&av_id, av_value) in pairs {
        data.write_u16::<LittleEndian>(av_id)?;
        data.write_u16::<LittleEndian>(av_value.len() as u16)?;
        data.extend_from_slice(av_value);
    }

    // End with NTLMSSP_AV_EOL
    data.write_u16::<LittleEndian>(0)?; // AV_EOL
    data.write_u16::<LittleEndian>(0)?; // Length 0

    Ok(data)
}

pub fn generate_client_challenge() -> [u8; 8] {
    use rand::Rng;
    let mut rng = rand::rng();
    let mut challenge = [0u8; 8];
    rng.fill(&mut challenge);
    challenge
}
