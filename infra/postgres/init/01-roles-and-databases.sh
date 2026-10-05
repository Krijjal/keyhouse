#!/bin/sh
# Runs once, when the Postgres volume is first initialized, as the bootstrap superuser.
#
# Roles:
#   keyhouse_owner  owns the databases and schema; runs migrations. Not a superuser.
#   keyhouse_app    used by the running idp. Gets only the grants each migration gives it.
#
# The superuser ($POSTGRES_USER) is for bootstrap only and is never used by the app.
set -eu

# Quoted heredoc: the shell does not expand anything inside it. Passwords are passed as
# psql variables and quoted by psql (:'name'), so special characters are safe.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v owner_pw="$KEYHOUSE_OWNER_PASSWORD" \
  -v app_pw="$KEYHOUSE_APP_PASSWORD" <<-'EOSQL'
  CREATE ROLE keyhouse_owner LOGIN CREATEDB PASSWORD :'owner_pw';
  CREATE ROLE keyhouse_app LOGIN PASSWORD :'app_pw';

  ALTER DATABASE keyhouse OWNER TO keyhouse_owner;
  CREATE DATABASE keyhouse_test OWNER keyhouse_owner;

  -- Only our two roles may connect. PUBLIC (every role) loses the default CONNECT.
  REVOKE ALL ON DATABASE keyhouse FROM PUBLIC;
  REVOKE ALL ON DATABASE keyhouse_test FROM PUBLIC;
  GRANT CONNECT ON DATABASE keyhouse TO keyhouse_owner, keyhouse_app;
  GRANT CONNECT ON DATABASE keyhouse_test TO keyhouse_owner, keyhouse_app;
EOSQL

# Schema-level settings must be applied inside each database.
for db in keyhouse keyhouse_test; do
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db" <<-'EOSQL'
    -- The owner role owns the public schema (so it can create tables and extensions).
    ALTER SCHEMA public OWNER TO keyhouse_owner;
    -- Nobody else may create objects in it; the app may only use what it is granted.
    REVOKE ALL ON SCHEMA public FROM PUBLIC;
    GRANT USAGE ON SCHEMA public TO keyhouse_app;
EOSQL
done
