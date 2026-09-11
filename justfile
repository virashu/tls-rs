test:
    curl https://127.0.0.1:3001 --tlsv1.3 -v
test_cert:
    curl https://127.0.0.1:3001 --tlsv1.3 -v --cacert cert.pem

run:
    cargo run

[env("RUST_LIB_BACKTRACE", "1")]
run_trace:
    cargo run

generate_cert:
    openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -sha256 -days 7 -nodes \
        -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=127.0.0.1"
    openssl x509 -outform der -in cert.pem -out cert.cer
    openssl rsa -outform der -in key.pem -out key.der

generate_cert_pss:
    openssl genpkey -algorithm RSA-PSS \
        -pkeyopt rsa_keygen_bits:2048 \
        -pkeyopt rsa_keygen_pubexp:65537 \
        -out key.pem
    openssl req -x509 -key key.pem -out cert.pem -sha256 -days 7 -nodes \
        -sigopt rsa_padding_mode:pss \
        -sigopt rsa_pss_saltlen:-1 \
        -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=127.0.0.1"
    openssl x509 -outform der -in cert.pem -out cert.cer
    openssl rsa -outform der -in key.pem -out key.der

clean_cert:
    rm key.pem key.der cert.pem cert.cer

