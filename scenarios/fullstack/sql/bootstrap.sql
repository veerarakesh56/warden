-- Wave 4 schema + roles. Applied by `python scripts/deploy_fullstack_apps.py bootstrap-db` as the
-- master user postgres (an IAM token from the operator's own identity), NOT by terraform.
-- Idempotent: safe to run again.
--
-- ⛔ NO PASSWORDS (2026-09-26). Aurora in express configuration authenticates with IAM only: every
-- role below logs in with a token its AWS identity signs, which rds_iam requires. The file is sent
-- as it is - it has no placeholders, and none may be added.

CREATE TABLE IF NOT EXISTS orders (
    order_id    text PRIMARY KEY,
    cart_id     text NOT NULL,
    customer_id text NOT NULL,
    sku         text NOT NULL,
    qty         integer NOT NULL CHECK (qty > 0),
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- fs-16 drops orders_customer_id_idx (scenarios/ops_fullstack.py Target.slow_index) and the
-- reconciler's by_customer lookup starts scanning; the fix is CREATE INDEX CONCURRENTLY.
CREATE INDEX IF NOT EXISTS orders_customer_id_idx ON orders (customer_id);
CREATE INDEX IF NOT EXISTS orders_created_at_idx ON orders (created_at);

-- 3M seed rows, once, so a lookup without its index is measurably slow (fs-16).
INSERT INTO orders (order_id, cart_id, customer_id, sku, qty, created_at)
SELECT 'seed-' || g, 'cart-' || (g % 50000), 'cust-' || (1 + g % 50000), 'sku-' || (1 + g % 20),
       1 + g % 3, now() - interval '1 day' - (g || ' seconds')::interval
FROM generate_series(1, 3000000) AS g
WHERE NOT EXISTS (SELECT 1 FROM orders WHERE order_id = 'seed-1');

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app') THEN
        CREATE ROLE app LOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'catalog') THEN
        CREATE ROLE catalog LOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'warden_ro') THEN
        CREATE ROLE warden_ro LOGIN;
    END IF;
END
$$;

-- IAM authentication for all three (express configuration refuses password logins anyway).
GRANT rds_iam TO app, catalog, warden_ro;

-- The application: exactly the tables it reads and writes. Signed in by the order-processor
-- Lambda's role and orders-api's ECS task role (rds-db:connect on dbuser:*/app).
GRANT USAGE ON SCHEMA public TO app;
GRANT SELECT, INSERT ON orders TO app;

-- catalog-api (EKS Pod Identity) and the reconciler: their own user, read-only. fs-21 revokes
-- orders-api's login as `app`; nothing that logs in as catalog may be a second victim.
GRANT USAGE ON SCHEMA public TO catalog;
GRANT SELECT ON orders TO catalog;

-- WARDEN: pg_monitor and nothing more (Wave 3 read as the master user; this closes that gap).
-- CONNECT comes from PUBLIC's default; it gets no grant on any table. Its token is signed with the
-- warden-pg-fs-reader role's credentials - the role WARDEN runs as.
GRANT pg_monitor TO warden_ro;
