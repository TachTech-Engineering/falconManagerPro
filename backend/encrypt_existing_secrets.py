# backend/encrypt_existing_secrets.py
"""
One-off migration: encrypt tenant credentials that are still stored as plaintext.

Usage (needs the same DB_* and TENANT_ENCRYPTION_KEYS env as the API):
    python encrypt_existing_secrets.py --dry-run   # report only
    python encrypt_existing_secrets.py             # encrypt plaintext rows
    python encrypt_existing_secrets.py --rotate    # also re-encrypt with the primary key

Safe to re-run: values that are already encrypted are skipped (unless --rotate).
Each value is verified by decrypting it before the row is written.
"""
import argparse
import logging
import sys

from dotenv import load_dotenv

load_dotenv()

from database import db  # noqa: E402
from secrets_crypto import (  # noqa: E402
    SECRET_FIELDS, decrypt_secret, encrypt_secret, is_encrypted, rotate_secret,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("encrypt_secrets")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dry-run", action="store_true", help="report what would change without writing")
    parser.add_argument("--rotate", action="store_true", help="re-encrypt already-encrypted values with the primary key")
    args = parser.parse_args()

    changed = skipped = 0
    with db.get_cursor(commit=not args.dry_run) as cursor:
        cursor.execute(f"SELECT id, {', '.join(SECRET_FIELDS)} FROM tenants")
        for row in cursor.fetchall():
            updates = {}
            for field in SECRET_FIELDS:
                value = row[field]
                if not value:
                    continue
                if is_encrypted(value) and not args.rotate:
                    continue
                new_value = rotate_secret(value) if args.rotate else encrypt_secret(value)
                # Verify the round trip before writing anything
                if decrypt_secret(new_value) != decrypt_secret(value):
                    logger.error("Round-trip check failed for tenant %s field %s; aborting", row["id"], field)
                    sys.exit(1)
                updates[field] = new_value

            if not updates:
                skipped += 1
                continue

            logger.info("Tenant %s: %s", row["id"], ", ".join(sorted(updates)))
            changed += 1
            if not args.dry_run:
                assignments = ", ".join(f"{f} = %s" for f in updates)
                cursor.execute(f"UPDATE tenants SET {assignments} WHERE id = %s", [*updates.values(), row["id"]])

    logger.info("%s: %d tenant(s) %s, %d unchanged",
                "DRY RUN" if args.dry_run else "Done", changed,
                "would change" if args.dry_run else "updated", skipped)


if __name__ == "__main__":
    main()
