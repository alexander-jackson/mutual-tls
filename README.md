mTLS experimentations for a load balancer where some downstreams are publicly
available and others require mutual authentication.

Uses SNI to determine which `rustls` configuration to use.
