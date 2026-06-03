ALTER TABLE pajareo_entries ADD COLUMN subject_kind TEXT NOT NULL DEFAULT 'person';
ALTER TABLE pajareo_entries ADD COLUMN subject_id TEXT;
ALTER TABLE pajareo_entries ADD COLUMN subject_name TEXT;
ALTER TABLE pajareo_entries ADD COLUMN institution_id TEXT;
ALTER TABLE pajareo_entries ADD COLUMN institution_name TEXT;
ALTER TABLE pajareo_entries ADD COLUMN jurisdiction_level TEXT NOT NULL DEFAULT 'representative_area';
ALTER TABLE pajareo_entries ADD COLUMN jurisdiction_label TEXT NOT NULL DEFAULT 'México';

CREATE INDEX IF NOT EXISTS idx_pajareo_entries_subject ON pajareo_entries(subject_kind, subject_id, institution_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_pajareo_entries_jurisdiction ON pajareo_entries(jurisdiction_level, jurisdiction_label, status, created_at);
