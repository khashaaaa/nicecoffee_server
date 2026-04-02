require("dotenv").config();
const { Pool } = require("pg");

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const initDb = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        points INTEGER DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS shops (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        area TEXT NOT NULL,
        tag TEXT,
        rating NUMERIC DEFAULT 0,
        mins INTEGER DEFAULT 10,
        img TEXT
      );
      CREATE TABLE IF NOT EXISTS items (
        id TEXT PRIMARY KEY,
        shop_id TEXT REFERENCES shops(id),
        name TEXT NOT NULL,
        "desc" TEXT,
        price NUMERIC NOT NULL,
        category TEXT,
        img TEXT
      );
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        shop_id TEXT REFERENCES shops(id),
        total NUMERIC NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE TABLE IF NOT EXISTS order_items (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id),
        item_id TEXT REFERENCES items(id),
        name TEXT NOT NULL,
        price NUMERIC NOT NULL,
        qty INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS saved (
        user_id INTEGER REFERENCES users(id),
        item_id TEXT REFERENCES items(id),
        PRIMARY KEY (user_id, item_id)
      );
    `);
    console.log("✅ Database tables initialized");
  } catch (err) {
    console.error("❌ Database initialization error:", err);
  }
};

initDb();

module.exports = pool;
