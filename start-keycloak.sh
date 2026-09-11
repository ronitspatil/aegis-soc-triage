#!/bin/sh
# Local Keycloak for identity enrichment. Development mode: no TLS, in-memory
# defaults. Not a production configuration.
KC_HOME="$HOME/.local/share/aegis/keycloak-26.7.3"
export KC_BOOTSTRAP_ADMIN_USERNAME=admin
export KC_BOOTSTRAP_ADMIN_PASSWORD=admin
exec "$KC_HOME/bin/kc.sh" start-dev --http-port 8081
