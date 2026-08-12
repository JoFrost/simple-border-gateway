use simple_border_gateway::config::BorderGatewayConfig;

#[test]
fn test_base_url_deserialization() {
    let config_toml = r#"
        [inbound_proxy]
        listen_adress = "0.0.0.0:8000"
        
        [outbound_proxy]
        listen_adress = "0.0.0.0:3128"

        ca_priv_key = "ca.pem"
        ca_cert = "ca.crt"
        
        allowed_non_matrix_regexes_dangerous = [
            "https://ntfy\\.sh/.*"
        ]
        
        [[internal_homeservers]]
        server_name = "Tout.IM"
        federation_domain = "Matrix.TOUT.im"
        target_base_url = "http://LOCALHOST:8008/chat/Test/"
        
        [[external_homeservers]]
        server_name = "Matrix.org"
        federation_domain = "matrix-federation.MATRIX.org"
        client_domain = "matrix-CLient.MATRIX.org"
        verify_keys = { "ed25519:a_RXGa" = "l8Hft5qXKn1vfHrg3p4+W8gELQVo8N13JkluMfmn2sQ" }
    "#;

    let config: BorderGatewayConfig = toml::from_str(config_toml).unwrap();
    // The base url is lowercased, but the path should be preserved as-is, minus the final slash...
    assert_eq!(
        config.internal_homeservers[0].target_base_url,
        "http://localhost:8008/chat/Test"
    );
}

#[test]
fn test_config_deserialization() {
    let config_toml = r#"
        [inbound_proxy]
        listen_adress = "0.0.0.0:8000"
        
        [outbound_proxy]
        listen_adress = "0.0.0.0:3128"

        ca_priv_key = "ca.pem"
        ca_cert = "ca.crt"
        
        allowed_non_matrix_regexes_dangerous = [
            "https://ntfy\\.sh/.*"
        ]
        
        [[internal_homeservers]]
        server_name = "Tout.IM"
        federation_domain = "Matrix.TOUT.im"
        target_base_url = "http://localhost:8008"
        
        [[external_homeservers]]
        server_name = "Matrix.org"
        federation_domain = "matrix-federation.MATRIX.org"
        client_domain = "matrix-CLient.MATRIX.org"
        verify_keys = { "ed25519:a_RXGa" = "l8Hft5qXKn1vfHrg3p4+W8gELQVo8N13JkluMfmn2sQ" }
    "#;

    let config: BorderGatewayConfig = toml::from_str(config_toml).unwrap();

    // Testing lowercasing for both internal and external homeservers
    assert_eq!(config.internal_homeservers[0].server_name, "tout.im");
    assert_eq!(
        config.internal_homeservers[0].federation_domain,
        "matrix.tout.im"
    );
    assert_eq!(
        config.external_homeservers[0].federation_domain,
        "matrix-federation.matrix.org"
    );
    assert_eq!(config.external_homeservers[0].server_name, "matrix.org");

    // Checking if the verify_keys are correctly deserialized
    assert_eq!(
        *config.external_homeservers[0]
            .verify_keys
            .get("ed25519:a_RXGa")
            .unwrap(),
        "l8Hft5qXKn1vfHrg3p4+W8gELQVo8N13JkluMfmn2sQ"
    );

    // Checking the listen addresses and the proxy configurations
    let inbound = config.inbound_proxy.as_ref().unwrap();
    let outbound = config.outbound_proxy.as_ref().unwrap();
    assert_eq!(inbound.listen_address, "0.0.0.0:8000");
    assert_eq!(outbound.listen_address, "0.0.0.0:3128");

    // Checking CA configuration
    assert_eq!(outbound.ca_cert, "ca.crt");
    assert_eq!(outbound.ca_priv_key, "ca.pem");

    // Checking the allowed non-matrix regexes
    assert_eq!(
        outbound.allowed_non_matrix_regexes_dangerous,
        vec!["https://ntfy\\.sh/.*"]
    );
}
