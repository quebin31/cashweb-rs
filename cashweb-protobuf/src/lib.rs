pub mod keyserver {
    include!(concat!(env!("OUT_DIR"), "/keyserver.rs"));
}

pub mod wrapper {
    include!(concat!(env!("OUT_DIR"), "/wrapper.rs"));
}

pub mod relay {
    pub mod filters {
        include!(concat!(env!("OUT_DIR"), "/filters.rs"));
    }

    pub mod messaging {
        include!(concat!(env!("OUT_DIR"), "/messaging.rs"));
    }

    pub mod stealth {
        include!(concat!(env!("OUT_DIR"), "/stealth.rs"));
    }
}

pub mod bip70 {
    include!(concat!(env!("OUT_DIR"), "/bip70.rs"));
}
