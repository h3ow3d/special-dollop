INSERT INTO roles (name, slug) VALUES
    ('Administrator', 'administrator'),
    ('Assessor',      'assessor'),
    ('Reader',        'reader')
ON CONFLICT (slug) DO NOTHING;
