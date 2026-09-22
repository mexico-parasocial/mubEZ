-- CD-12: remove the unused person-to-account correlation.
-- Apply only through the normal reviewed migration process.
DROP TABLE IF EXISTS person_aliases;
