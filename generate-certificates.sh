#!/usr/bin/env bash

# Remove existing certificates
rm -r certs

# Create the directory again
mkdir certs
cd certs

# Generate a key for the CA as well as a self-signed certificate
openssl genrsa -out ca.key 2048
openssl req -new -x509 -key ca.key -out ca.crt -subj "/C=GB/ST=England/L=London/O=root/CN=localhost"

# Generate a key, CSR and certificate for the server
openssl genrsa -out localhost.key 2048
openssl req -new -key localhost.key -subj "/C=GB/ST=England/L=London/O=server/CN=localhost" -addext "subjectAltName = DNS:localhost" -out localhost.csr
openssl x509 -req -in localhost.csr -CA ca.crt -CAkey ca.key -CAcreateserial -extfile <(printf "subjectAltName=DNS:localhost") -out localhost.crt

# Generate a key, CSR and certificate for the client
openssl genrsa -out client_0.key 2048
openssl req -new -key client_0.key -subj "/C=GB/ST=England/L=London/O=client/CN=localhost" -addext "subjectAltName = DNS:localhost" -out client_0.csr
openssl x509 -req -in client_0.csr -CA ca.crt -CAkey ca.key -CAcreateserial -extfile <(printf "subjectAltName=DNS:localhost") -out client_0.crt

cd ..
