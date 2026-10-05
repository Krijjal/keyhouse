-- Least-privilege grants for the runtime role (keyhouse_app).
-- The role itself is created by infrastructure (infra/postgres/init), not by migrations.
-- Rule: every migration that adds a table also grants keyhouse_app exactly what it needs.

-- Phase 1 never deletes rows: revoking a session or consuming a token is an UPDATE.
-- DELETE is granted later only when a feature needs it.
GRANT SELECT, INSERT, UPDATE ON "users" TO keyhouse_app;
GRANT SELECT, INSERT, UPDATE ON "sessions" TO keyhouse_app;
GRANT SELECT, INSERT, UPDATE ON "email_tokens" TO keyhouse_app;

-- Append-only: write and read history, never change it. Not being the table owner,
-- the app also cannot DISABLE or DROP the append-only trigger.
GRANT SELECT, INSERT ON "audit_events" TO keyhouse_app;
-- USAGE allows nextval() for inserts; withholding UPDATE blocks setval() (ID reuse).
GRANT USAGE ON SEQUENCE "audit_events_id_seq" TO keyhouse_app;
