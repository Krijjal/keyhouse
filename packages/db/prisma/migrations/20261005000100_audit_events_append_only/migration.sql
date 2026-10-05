-- Rule 8: audit_events is append-only.
-- Rejects every UPDATE, DELETE and TRUNCATE at the database level, so neither
-- application bugs nor an attacker with app-level access can rewrite history.
--
-- Limitation: the table OWNER can still `ALTER TABLE ... DISABLE TRIGGER`.
-- Full protection needs the app to connect as a role that only has
-- INSERT/SELECT on this table (tracked as a hardening item).

CREATE OR REPLACE FUNCTION audit_events_reject_modification()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only: % is not allowed', TG_OP
    USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER audit_events_no_update_delete
  BEFORE UPDATE OR DELETE ON "audit_events"
  FOR EACH ROW
  EXECUTE FUNCTION audit_events_reject_modification();

CREATE TRIGGER audit_events_no_truncate
  BEFORE TRUNCATE ON "audit_events"
  FOR EACH STATEMENT
  EXECUTE FUNCTION audit_events_reject_modification();
