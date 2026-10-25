-- CreateTable
CREATE TABLE "mfa_tickets" (
    "id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "token_hash" CHAR(64) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "consumed_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "mfa_tickets_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "mfa_tickets_token_hash_key" ON "mfa_tickets"("token_hash");

-- CreateIndex
CREATE INDEX "mfa_tickets_user_id_idx" ON "mfa_tickets"("user_id");

-- AddForeignKey
ALTER TABLE "mfa_tickets" ADD CONSTRAINT "mfa_tickets_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- Least-privilege grants: read, issue and mark tickets used; never delete (rule: no DELETE).
GRANT SELECT, INSERT, UPDATE ON "mfa_tickets" TO keyhouse_app;