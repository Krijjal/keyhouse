#!/bin/sh
# Creates the integration-test database next to the dev database.
# Only runs when the Postgres volume is first initialized.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
  CREATE DATABASE ${POSTGRES_DB}_test OWNER "$POSTGRES_USER";
EOSQL
