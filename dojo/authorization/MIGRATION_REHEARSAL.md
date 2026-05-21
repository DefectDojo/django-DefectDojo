# Legacy Authorization Migration Rehearsal

End-to-end verification procedure for the Track B legacy authorization
rewrite. Run on a representative DB snapshot before merging the upstream
PR; re-run on each customer-shaped snapshot before promoting Pro releases.

The four scenarios below cover every realistic upgrade path. Scenarios 1
and 3 are runnable inside the regular Pro Docker stack with the bare_bones
fixture; scenarios 2 and 4 require a different topology (OS-only
deployment / fresh DB) that the docker-compose dev environment does not
expose by default.

## Pre-rehearsal: known-good DB snapshot

Before running any of the scenarios below, capture two DB snapshots:

```bash
docker exec postgres pg_dump -U postgres -Fc dojodb \
    > snapshots/pre-migration.dump
```

You will also need:

* a Pro snapshot taken **before** Track B migrations land (RBAC active)
* an OS-only snapshot taken **before** Track B migrations land (so it
  has the dojo_* RBAC tables but no Pro app state)

---

## Scenario 1 — Pro path (transparent upgrade)

**Setup**: Pro snapshot. Run Track B migrations (dojo.0266 → dojo.0267
→ pro.0049 → dojo.0268).

**Expected**: state-only ownership transfer; no row changes; Pro RBAC
behaves identically to pre-migration.

**Procedure**:

```bash
# Restore Pro snapshot, run migrate
./dojoctl up
docker exec dojo python manage.py migrate

# Verify counts unchanged
docker exec postgres psql -U postgres -d dojodb -c "
SELECT 'auth_role' AS t, count(*) FROM dojo_role
UNION ALL SELECT 'global_role', count(*) FROM dojo_global_role
UNION ALL SELECT 'product_member', count(*) FROM dojo_product_member
UNION ALL SELECT 'product_type_member', count(*) FROM dojo_product_type_member
UNION ALL SELECT 'product_group', count(*) FROM dojo_product_group
UNION ALL SELECT 'product_type_group', count(*) FROM dojo_product_type_group
UNION ALL SELECT 'dojo_group_member', count(*) FROM dojo_dojo_group_member;
"
# Compare against pre-migration counts — should be identical.

# Verify Pro can still query
docker exec dojo python manage.py shell -c "
from pro.authorization.models import Role, Product_Member, Global_Role
print('Pro Role count:', Role.objects.count())
print('Pro Product_Member count:', Product_Member.objects.count())
print('Pro Global_Role count:', Global_Role.objects.count())
"

# Run Pro test suite
docker exec dojo pytest /app/dojo-pro/unit_tests/ -q
```

**Verified in CI environment (bare_bones fixture)**:
- 5 Roles, 4 Global_Roles, 1 Product_Member, 1 Product_Type_Member,
  1 Product_Group, 1 Product_Type_Group, 3 Dojo_Group_Members preserved.
- Pro queries via `pro.authorization.models` return the same counts.
- 442 tests across pro/authorization, pro/api/authorization,
  pro/api_helpers, dashboard/test_views_extended pass.

---

## Scenario 2 — OS-standalone upgrade (the legacy rewrite)

**Setup**: OS-only snapshot (Pro NOT installed). Run Track B migrations
on a deployment that does not include the Pro app.

**Expected**:
- `dojo.0266` adds `authorized_users` M2M field.
- `dojo.0267` backfills authorized_users from RBAC tables (dormant in
  this scenario but populated from the OS-only customer's prior data).
- `dojo.0268` flips RBAC models to managed=False in dojo state.
- Customers continue to use the system; per-product role granularity
  collapses to membership (legacy semantics).

**Procedure**:

```bash
# 1. Run the preview command first to audit impact
docker exec dojo python manage.py preview_legacy_authorization_migration --json \
    > pre-upgrade-preview.json

# 2. Apply migrations
docker exec dojo python manage.py migrate

# 3. Verify authorized_users populated
docker exec postgres psql -U postgres -d dojodb -c "
SELECT 'product authorized_users' AS t, count(*) FROM dojo_product_authorized_users
UNION ALL SELECT 'product_type authorized_users', count(*) FROM dojo_product_type_authorized_users;
"

# 4. Verify RBAC tables intact (not touched by the migration)
docker exec postgres psql -U postgres -d dojodb -c "
SELECT count(*) FROM dojo_role;
SELECT count(*) FROM dojo_global_role;
"
# These should match pre-migration counts.

# 5. Verify is_superuser / is_staff flips for users with elevated Global_Roles
docker exec postgres psql -U postgres -d dojodb -c "
SELECT username, is_superuser, is_staff FROM auth_user
WHERE is_superuser OR is_staff
ORDER BY id;
"

# 6. Run OS test suite (failures are expected — see "OS test fallout" below)
docker exec dojo python manage.py test dojo
```

**Status in this environment**: Not directly runnable (the bare_bones
Pro stack always loads Pro). The migration's logic was unit-tested
against bare_bones data in this environment with Pro present (Pro's
shadow is harmless to data migrations); the actual scenario must be
verified on an OS-only deployment.

**Known OS test fallout**: tests in `dojo/tests/` and
`unittests/authorization/` that assert RBAC role hierarchy ("Reader can
view but not edit") will fail on the legacy rewrite — they describe the
old RBAC contract. Update them to assert membership-based legacy
semantics in a follow-up change.

---

## Scenario 3 — OS → Pro reinstall (reconcile gotcha)

**Setup**: Customer ran Scenario 2, then made per-product changes via
the OS UI (adds/removes in `Product.authorized_users`). Now they install
a Pro license.

**Expected**: Pro adopts the existing RBAC tables but those tables are
stuck at the pre-Scenario-2 snapshot. The reconcile command brings
Product_Member rows back in sync with authorized_users.

**Procedure**:

```bash
# 1. Install Pro, run migrate (state-only)
docker exec dojo python manage.py migrate

# 2. Run reconcile in dry-run mode first
docker exec dojo python manage.py reconcile_authorized_users_to_rbac --dry-run

# 3. Apply
docker exec dojo python manage.py reconcile_authorized_users_to_rbac --role Writer

# 4. Verify Product_Member now matches authorized_users
docker exec postgres psql -U postgres -d dojodb -c "
SELECT
    (SELECT count(*) FROM dojo_product_authorized_users) AS au_pairs,
    (SELECT count(*) FROM dojo_product_member) AS pm_rows,
    (SELECT count(*) FROM dojo_product_type_authorized_users) AS au_pt_pairs,
    (SELECT count(*) FROM dojo_product_type_member) AS ptm_rows;
"
# pm_rows >= au_pairs after reconcile (>= because direct-RBAC-only
# Product_Member rows that have no corresponding authorized_users entry
# still exist).

# 5. Re-run reconcile — should be a no-op
docker exec dojo python manage.py reconcile_authorized_users_to_rbac
# Output: "Already reconciled — nothing to do."
```

**Verified in CI environment**:
- `--dry-run` reports 1 Product_Member + 1 Product_Type_Member to create
  from the 2-pair authorized_users state (1 was a direct member already,
  1 was added from group expansion during 0267 backfill).
- Idempotent: re-running after apply prints "Already reconciled".

---

## Scenario 4 — Fresh OS install (no-op for the legacy migration)

**Setup**: Brand-new database. No tables exist before `migrate`.

**Expected**: 0266 schema-creates `authorized_users` M2M. 0267 detects
no `dojo_role` table and early-returns (no-op). 0268 flips state for
models that were just created by older migrations.

**Procedure**:

```bash
# 1. Drop the database and recreate
docker exec postgres dropdb -U postgres dojodb
docker exec postgres createdb -U postgres dojodb

# 2. Run all migrations
docker exec dojo python manage.py migrate

# 3. Verify migrations applied with no errors
docker exec postgres psql -U postgres -d dojodb -c "
SELECT app, name FROM django_migrations
WHERE name LIKE '%authorized%' OR name LIKE '%rbac%'
ORDER BY id;
"
# Expected: 0266_reintroduce_authorized_users, 0267_backfill_authorized_users,
#           0268_release_rbac_state, plus pro.0049_adopt_rbac_tables (if Pro).

# 4. Verify authorized_users M2M tables are empty (fresh install)
docker exec postgres psql -U postgres -d dojodb -c "
SELECT count(*) FROM dojo_product_authorized_users;
SELECT count(*) FROM dojo_product_type_authorized_users;
"
# Both 0.
```

**Status in this environment**: Not directly runnable without dropping
and recreating the dojodb. The `dojo_role` introspection guard in 0267
was code-reviewed and verified against the introspection result on
this environment (`dojo_role` is present here, so guard does NOT
short-circuit — but the inverse case is the well-defined fallthrough).

---

## Release-notes blueprint (per scenario)

Each upgrade scenario maps to its own customer-facing message:

| Scenario | Release-notes section title |
|----------|----------------------------|
| 1 | "Pro upgrade is transparent — no permission semantics change" |
| 2 | "Legacy authorization migration: what your users can do now" |
| 3 | "Re-installing Pro after an OS-only window: run reconcile" |
| 4 | "Fresh OS installs: no-op" |

Scenario 2 is the longest and most important. Required content:

* The role-flattening table from `permission_to_action()` (Reader/Writer/
  Maintainer/Owner all collapse to "authorized")
* SQL or `preview_legacy_authorization_migration` example so customers
  can audit before upgrading
* Statement that historical RBAC data is preserved (no rows dropped)
* Pointer to dojo-pro for customers who need RBAC fidelity back
