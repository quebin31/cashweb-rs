pub mod models {
    include!(concat!(env!("OUT_DIR"), "/models.rs"));
}

pub mod bitcoin;
pub mod payment_processor;
pub mod resource_guard;
