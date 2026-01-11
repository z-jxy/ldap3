//! This example requires the "ntlm" feature to be enabled
//! Run with: cargo run --example ntlm_hash_bind --features ntlm

use ldap3::{LdapConn, result::Result};

/// Convert domain to LDAP base DN format
fn domain_to_base(domain: &str) -> String {
    domain
        .split('.')
        .map(|part| format!("dc={part}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn main() -> Result<()> {
    #[cfg(not(feature = "ntlm"))]
    {
        println!("This example requires the 'ntlm' feature to be enabled.");
        println!("Run with: cargo run --example ntlm_hash_bind --features ntlm");
        return Ok(());
    }

    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 5 {
        eprintln!("Usage: {} <host> <username> <domain> <ntlm_hash>", args[0]);
        return Ok(());
    }

    let host = &args[1];
    let username = &args[2];
    let domain = &args[3];
    let ntlm_hash: ldap3::NtlmHash = args[4].as_str().try_into().map_err(|_| {
        eprintln!("Invalid NTLM hash format. Expected format: <hash>");
        ldap3::LdapError::InvalidNtlmHash(args[4].clone())
    })?;

    let base = domain_to_base(domain);

    println!("[*] NTLMv1 authentication");
    #[cfg(feature = "ntlm")]
    {
        let mut ldap = LdapConn::new(&format!("ldap://{host}:389"))?;

        let res = ldap.sasl_ntlm_bind_with_hash_sspi(username, domain, &ntlm_hash)?;

        if res.rc != 0 {
            eprintln!("NTLMv1 hash authentication failed: {res}");
            return Err(res.into());
        }

        println!("[+] NTLMv1 hash authentication successful");

        // Now you can perform LDAP operations
        // For example, search for entries
        let (entries, _) = ldap
            .search(
                &base,
                ldap3::Scope::Subtree,
                "(objectClass=person)",
                vec!["cn", "name"],
            )?
            .success()?;

        println!("[+] Num entries (objectClass=person): {:?}", entries.len());

        ldap.unbind()?;
    }

    Ok(())
}
