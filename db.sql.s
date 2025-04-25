    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0
CREATE TABLE IF NOT EXISTS product (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    price TEXT NOT NULL,
    image_url TEXT,
    seller_id TEXT NOT NULL
)
