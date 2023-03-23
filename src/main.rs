use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::process::ExitCode;
use std::str::FromStr;

use clap::Parser;
use pem::Pem;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;
use x509_parser::x509::X509Name;


#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
struct UnmatchedValue {
    value: String,
}
impl UnmatchedValue {
    pub fn new(
        value: String,
    ) -> Self {
        Self {
            value,
        }
    }
}
impl fmt::Display for UnmatchedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unmatched value: {}", self.value)
    }
}
impl Error for UnmatchedValue {
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum Output {
    HostCertificate,
    IntermediateCertificatesFromRoot,
    IntermediateCertificatesToRoot,
    RootCertificate,
    PrivateKey,
    OtherData,
}
impl FromStr for Output {
    type Err = UnmatchedValue;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "host" => Ok(Output::HostCertificate),
            "imedfromroot" => Ok(Output::IntermediateCertificatesFromRoot),
            "imedtoroot" => Ok(Output::IntermediateCertificatesToRoot),
            "root" => Ok(Output::RootCertificate),
            "key" => Ok(Output::PrivateKey),
            "other" => Ok(Output::OtherData),
            _ => Err(UnmatchedValue::new(String::from(s))),
        }
    }
}


#[derive(Clone, Debug, Eq, Parser, PartialEq)]
struct Opts {
    #[arg(
        required = true,
        help = "The names of the files from which to read the certificates and related data.",
    )]
    files: Vec<OsString>,

    #[arg(
        short = 'O', long = "order", value_delimiter = ',',
        default_values = &["host", "imedtoroot", "key", "other"],
        help = "The order in which to output the data. Takes a comma-separated string consisting of the values:

* \"host\" (the host certificate)
* \"imedtoroot\" (intermediate certificates, ordered by decreasing distance toward the root)
* \"imedfromroot\" (intermediate certificates, ordered by increasing distance away from the root)
* \"key\" (the private key)
* \"root\" (the root certificate)
* \"other\" (any other data that is neither key nor certificate)",
    )]
    order: Vec<Output>,

    #[arg(
        short = 'd', long = "debug",
        help = "Prefix every PEM structure with human-readable information about its content."
    )]
    debug: bool,
}


#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RawX509Name {
    name_bytes: Vec<u8>,
}
impl RawX509Name {
    pub fn new(name_bytes: Vec<u8>) -> RawX509Name {
        RawX509Name { name_bytes }
    }
    pub fn from_bytes(bytes: &[u8]) -> RawX509Name {
        RawX509Name::new(Vec::from(bytes))
    }
    pub fn from_x509_name(name: &X509Name) -> RawX509Name {
        RawX509Name::from_bytes(name.as_raw())
    }
    pub fn as_x509_name(&self) -> X509Name {
        let (_rest, name) = X509Name::from_der(&self.name_bytes)
            .unwrap();
        name
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RawDerCert {
    cert_bytes: Vec<u8>,
}
impl RawDerCert {
    pub fn new(cert_bytes: Vec<u8>) -> RawDerCert {
        RawDerCert { cert_bytes }
    }
    pub fn from_bytes(bytes: &[u8]) -> RawDerCert {
        RawDerCert::new(Vec::from(bytes))
    }
    pub fn as_pem(&self) -> Pem {
        Pem::new(
            String::from("CERTIFICATE"),
            self.cert_bytes.clone(),
        )
    }
    pub fn as_x509_cert(&self) -> X509Certificate {
        let (_rest, cert) = X509Certificate::from_der(&self.cert_bytes)
            .unwrap();
        cert
    }
}


fn ordered_intermediate_subjects(
    subject_to_issuer: &HashMap<RawX509Name, RawX509Name>,
    anchor_subject: &RawX509Name,
    deep_first: bool,
) -> Vec<RawX509Name> {
    let anchor_issuer = match subject_to_issuer.get(anchor_subject) {
        Some(ai) => ai,
        None => {
            // issuer is not known; no need to keep searching
            return Vec::new();
        },
    };

    let mut ret = Vec::new();

    if deep_first {
        ret.push(anchor_issuer.clone());
    }

    // try the parent next
    let mut sub_vec = ordered_intermediate_subjects(
        subject_to_issuer,
        &anchor_issuer,
        deep_first,
    );
    ret.append(&mut sub_vec);

    if !deep_first {
        ret.push(anchor_issuer.clone());
    }

    ret
}


fn main() -> ExitCode {
    let opts = Opts::parse();

    // read in all the certificates/PEM structures
    let mut subject_to_cert: HashMap<RawX509Name, RawDerCert> = HashMap::new();
    let mut keys: Vec<pem::Pem> = Vec::new();
    let mut others: Vec<pem::Pem> = Vec::new();
    for path in opts.files {
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("failed to read {:?}: {}", path, e);
                return ExitCode::FAILURE;
            },
        };

        let mut something_loaded = false;

        // PEM?
        let pems = match pem::parse_many(&bytes) {
            Ok(ps) => ps,
            Err(e) => {
                eprintln!("failed to parse PEM file {:?}: {}", path, e);
                continue;
            },
        };
        for pem in pems {
            something_loaded = true;
            if pem.tag() == "CERTIFICATE" {
                let (_rest, cert) = match X509Certificate::from_der(pem.contents()) {
                    Ok(rc) => rc,
                    Err(e) => {
                        eprintln!("failed to load PEM-encoded certificate data in {:?}: {}", path, e);
                        continue;
                    },
                };

                let raw_subject = RawX509Name::from_x509_name(cert.subject());
                let raw_cert = RawDerCert::from_bytes(pem.contents());
                if let Some(fallout) = subject_to_cert.insert(raw_subject, raw_cert) {
                    let fallout_cert = fallout.as_x509_cert();
                    eprintln!("multiple certificates found for subject: {}", fallout_cert.subject());
                }
            } else if pem.tag().contains("PRIVATE KEY") {
                keys.push(pem)
            } else {
                others.push(pem)
            }
        }

        if !something_loaded {
            // DER?
            let mut der_rest_bytes = bytes.as_slice();
            while der_rest_bytes.len() > 0 {
                let (rest, cert) = match X509Certificate::from_der(der_rest_bytes) {
                    Ok(rc) => rc,
                    Err(e) => {
                        eprintln!("failed to load DER-encoded certificate data in {:?}: {}", path, e);
                        der_rest_bytes = &der_rest_bytes[1..];
                        continue;
                    },
                };

                let this_cert_slice = &der_rest_bytes[..der_rest_bytes.len()-rest.len()];

                // assume certificate
                let raw_subject = RawX509Name::from_x509_name(cert.subject());
                let raw_cert = RawDerCert::from_bytes(this_cert_slice);
                if let Some(fallout) = subject_to_cert.insert(raw_subject, raw_cert) {
                    let fallout_cert = fallout.as_x509_cert();
                    eprintln!("multiple certificates found for subject: {}", fallout_cert.subject());
                }

                der_rest_bytes = rest;
            }
        }
    }

    // map issuer to the certificates it has issued
    let mut subject_to_issuer: HashMap<RawX509Name, RawX509Name> = HashMap::new();
    let mut issuer_to_subjects: HashMap<RawX509Name, Vec<RawX509Name>> = HashMap::new();
    let mut root_subjects: HashSet<RawX509Name> = HashSet::new();
    for (raw_subject, cert_raw) in &subject_to_cert {
        let cert = cert_raw.as_x509_cert();

        let raw_issuer = RawX509Name::from_x509_name(cert.issuer());

        if raw_issuer == *raw_subject {
            // if the issuer and the subject are the same, it is a root certificate
            root_subjects.insert(raw_subject.clone());
        } else if !subject_to_cert.contains_key(&raw_issuer) {
            // for the sake of simplicity, if we don't have the issuer's certificate,
            // consider it a root certificate as well
            root_subjects.insert(raw_subject.clone());
        } else {
            subject_to_issuer.insert(raw_subject.clone(), raw_issuer.clone());
            issuer_to_subjects.entry(raw_issuer)
                .or_insert_with(|| Vec::new())
                .push(raw_subject.clone());
        }
    }

    // leaf certs are those that are neither roots nor have they issued certificates themselves
    let leaf_subjects: Vec<RawX509Name> = subject_to_cert.keys()
        .filter(|subj| !root_subjects.contains(subj))
        .filter(|subj| !issuer_to_subjects.contains_key(*subj))
        .map(|subj| subj.clone())
        .collect();

    // output certificates in the correct order
    for entry in opts.order {
        match entry {
            Output::PrivateKey => {
                // output all private keys
                for key in &keys {
                    if opts.debug {
                        println!();
                        println!(">>> private key");
                    }
                    print!("{}", pem::encode(key));
                }
            },
            Output::OtherData => {
                // output any non-key data
                for other in &others {
                    if opts.debug {
                        println!();
                        println!(">>> other data");
                    }
                    print!("{}", pem::encode(other));
                }
            },
            Output::RootCertificate => {
                // output any root certificates
                for root_subject in &root_subjects {
                    let cert = subject_to_cert.get(root_subject).unwrap();
                    if opts.debug {
                        println!();
                        println!(">>> root certificate: {}", root_subject.as_x509_name());
                        println!(">>>        issued by: {}", cert.as_x509_cert().issuer());
                    }
                    let pkv = cert.as_pem();
                    print!("{}", pem::encode(&pkv));
                }
            },
            Output::IntermediateCertificatesFromRoot => {
                // output intermediate (i.e. non-root and non-host) certificates
                // ordered by increasing distance away from root
                for leaf_subject in &leaf_subjects {
                    let ois = ordered_intermediate_subjects(
                        &subject_to_issuer,
                        leaf_subject,
                        false,
                    );
                    for imed_subject in &ois {
                        let cert = subject_to_cert.get(imed_subject).unwrap();
                        if opts.debug {
                            println!();
                            println!(">>> intermediate certificate: {}", imed_subject.as_x509_name());
                            println!(">>>                issued by: {}", cert.as_x509_cert().issuer());
                        }
                        let pkv = cert.as_pem();
                        print!("{}", pem::encode(&pkv));
                    }
                }
            },
            Output::IntermediateCertificatesToRoot => {
                // output intermediate (i.e. non-root and non-host) certificates
                // ordered by decreasing distance to root
                for leaf_subject in &leaf_subjects {
                    let ois = ordered_intermediate_subjects(
                        &subject_to_issuer,
                        leaf_subject,
                        true,
                    );
                    for imed_subject in &ois {
                        if root_subjects.contains(imed_subject) {
                            // only intermediates, not roots
                            continue;
                        }
                        let cert = subject_to_cert.get(imed_subject).unwrap();
                        if opts.debug {
                            println!();
                            println!(">>> intermediate certificate: {}", imed_subject.as_x509_name());
                            println!(">>>                issued by: {}", cert.as_x509_cert().issuer());
                        }
                        let pkv = cert.as_pem();
                        print!("{}", pem::encode(&pkv));
                    }
                }
            },
            Output::HostCertificate => {
                // output host (leaf) certificates
                for leaf_subject in &leaf_subjects {
                    let cert = subject_to_cert.get(leaf_subject).unwrap();
                    if opts.debug {
                        println!();
                        println!(">>> host certificate: {}", leaf_subject.as_x509_name());
                        println!(">>>        issued by: {}", cert.as_x509_cert().issuer());
                    }
                    let pkv = cert.as_pem();
                    print!("{}", pem::encode(&pkv));
                }
            },
        }
    }
    ExitCode::SUCCESS
}
