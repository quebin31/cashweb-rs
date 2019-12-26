pub mod address_metadata {
    include!(concat!(env!("OUT_DIR"), "/addressmetadata.rs"));
}

pub mod bip70 {
    include!(concat!(env!("OUT_DIR"), "/bip70.rs"));
}
