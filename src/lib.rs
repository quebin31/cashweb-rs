pub mod models {
    include!(concat!(env!("OUT_DIR"), "/models.rs"));
}

pub mod payment_processor;
pub mod resource_guard;
