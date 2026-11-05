-- Worker-only database, independently versioned from the application schema.
BEGIN;
CREATE TABLE aria_worker_schema (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    version integer NOT NULL CHECK (version = 1)
);
INSERT INTO aria_worker_schema VALUES (true, 1);
CREATE TABLE aria_worker_jobs (
    job_id uuid PRIMARY KEY,
    record jsonb NOT NULL CHECK (jsonb_typeof(record) = 'object')
);
CREATE INDEX aria_worker_jobs_state ON aria_worker_jobs ((record->>'state'));
COMMIT;
