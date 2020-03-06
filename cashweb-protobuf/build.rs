fn main() {
    prost_build::compile_protos(
        &[
            "src/proto/pop/wrapper.proto",
            "src/proto/pop/paymentrequest.proto",
            "src/proto/keyserver/addressmetadata.proto",
            "src/proto/relay/filters.proto",
            "src/proto/relay/messaging.proto",
            "src/proto/relay/stealth.proto",
        ],
        &["src/"],
    )
    .unwrap();
}
