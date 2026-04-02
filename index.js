require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("./db");

const app = express();
app.use(express.json());

// ─── CORS ─────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// ─── HELPERS ──────────────────────────────────────────────────
const wrap = (fn) => async (req, res, next) => {
  try {
    await fn(req, res, next);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};

const sign = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "30d" });

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
};

// ─── AUTH ─────────────────────────────────────────────────────
app.post(
  "/auth/register",
  wrap(async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res
        .status(400)
        .json({ error: "Name, email and password are required" });
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      "INSERT INTO users (name,email,password) VALUES ($1,$2,$3) RETURNING id,name,email,points",
      [name, email, hash],
    );
    res.json({ token: sign(rows[0].id), user: rows[0] });
  }),
);

app.post(
  "/auth/login",
  wrap(async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password are required" });
    const { rows } = await pool.query("SELECT * FROM users WHERE email=$1", [
      email,
    ]);
    const user = rows[0];
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: "Invalid credentials" });
    res.json({
      token: sign(user.id),
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        points: user.points,
      },
    });
  }),
);

// ─── SHOPS ────────────────────────────────────────────────────
app.get(
  "/shops",
  wrap(async (req, res) => {
    const { rows } = await pool.query(
      "SELECT * FROM shops ORDER BY rating DESC",
    );
    res.json(rows);
  }),
);

// ─── MENU ITEMS ───────────────────────────────────────────────
app.get(
  "/items",
  wrap(async (req, res) => {
    const { shop_id, category, q } = req.query;
    let query = "SELECT * FROM items WHERE 1=1";
    const params = [];
    if (shop_id) {
      params.push(shop_id);
      query += ` AND shop_id=$${params.length}`;
    }
    if (category) {
      params.push(category);
      query += ` AND category=$${params.length}`;
    }
    if (q) {
      params.push(`%${q}%`);
      query += ` AND (name ILIKE $${params.length} OR "desc" ILIKE $${params.length})`;
    }
    query += " ORDER BY name";
    const { rows } = await pool.query(query, params);
    res.json(rows);
  }),
);

// ─── ORDERS ───────────────────────────────────────────────────
app.post(
  "/orders",
  auth,
  wrap(async (req, res) => {
    const { shop_id, items } = req.body;
    if (!items?.length) return res.status(400).json({ error: "No items" });
    const total = items.reduce((sum, i) => sum + i.price * i.qty, 0);

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      const { rows } = await client.query(
        "INSERT INTO orders (user_id,shop_id,total) VALUES ($1,$2,$3) RETURNING *",
        [req.user.id, shop_id, total],
      );
      const order = rows[0];

      // FIX: Use a loop instead of Promise.all to avoid concurrent queries on one client
      for (const i of items) {
        await client.query(
          "INSERT INTO order_items (order_id,item_id,name,price,qty) VALUES ($1,$2,$3,$4,$5)",
          [order.id, i.id, i.name, i.price, i.qty],
        );
      }

      await client.query("UPDATE users SET points = points + $1 WHERE id=$2", [
        Math.floor(total),
        req.user.id,
      ]);

      await client.query("COMMIT");
      res.json(order);
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }
  }),
);

app.get(
  "/orders",
  auth,
  wrap(async (req, res) => {
    const { rows } = await pool.query(
      `SELECT o.*, s.name as shop_name,
      json_agg(json_build_object('name',oi.name,'price',oi.price,'qty',oi.qty)) as items
     FROM orders o
     JOIN shops s ON s.id = o.shop_id
     JOIN order_items oi ON oi.order_id = o.id
     WHERE o.user_id=$1
     GROUP BY o.id, s.name
     ORDER BY o.created_at DESC`,
      [req.user.id],
    );
    res.json(rows);
  }),
);

// ─── SAVED ITEMS ──────────────────────────────────────────────
app.get(
  "/saved",
  auth,
  wrap(async (req, res) => {
    const { rows } = await pool.query(
      `SELECT i.id, i.name, i."desc", i.price, i.category, i.img
     FROM saved s JOIN items i ON i.id=s.item_id WHERE s.user_id=$1`,
      [req.user.id],
    );
    res.json(rows);
  }),
);

app.post(
  "/saved/:itemId",
  auth,
  wrap(async (req, res) => {
    await pool.query(
      "INSERT INTO saved (user_id,item_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
      [req.user.id, req.params.itemId],
    );
    res.json({ ok: true });
  }),
);

app.delete(
  "/saved/:itemId",
  auth,
  wrap(async (req, res) => {
    await pool.query("DELETE FROM saved WHERE user_id=$1 AND item_id=$2", [
      req.user.id,
      req.params.itemId,
    ]);
    res.json({ ok: true });
  }),
);

// ─── REDEEM POINTS ────────────────────────────────────────────
app.post(
  "/redeem",
  auth,
  wrap(async (req, res) => {
    const { points } = req.body;
    if (!points || points <= 0)
      return res.status(400).json({ error: "Invalid points" });
    const { rows } = await pool.query("SELECT points FROM users WHERE id=$1", [
      req.user.id,
    ]);
    const balance = rows[0]?.points ?? 0;
    if (balance < points)
      return res.status(400).json({ error: "Insufficient points" });
    await pool.query("UPDATE users SET points = points - $1 WHERE id=$2", [
      points,
      req.user.id,
    ]);
    res.json({ ok: true, remaining: balance - points });
  }),
);

// ─── USER ─────────────────────────────────────────────────────
app.get(
  "/me",
  auth,
  wrap(async (req, res) => {
    const { rows } = await pool.query(
      "SELECT id,name,email,points,created_at FROM users WHERE id=$1",
      [req.user.id],
    );
    if (!rows[0]) return res.status(404).json({ error: "User not found" });
    res.json(rows[0]);
  }),
);

// ─── SEED (dev only) ──────────────────────────────────────────
app.post(
  "/seed",
  wrap(async (req, res) => {
    const { SHOPS, ITEMS } = require("../data/data");

    // Using loops here is safer for large datasets and avoids the warning
    for (const s of SHOPS) {
      await pool.query(
        "INSERT INTO shops (id,name,area,tag,rating,mins,img) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING",
        [s.id, s.name, s.area, s.tag, s.rating, s.mins, s.img],
      );
    }

    for (const i of ITEMS) {
      await pool.query(
        'INSERT INTO items (id,shop_id,name,"desc",price,category,img) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING',
        [i.id, i.shopId, i.name, i.desc, i.price, i.cat, i.img],
      );
    }

    res.json({ ok: true });
  }),
);

// ─── START ────────────────────────────────────────────────────
app.listen(process.env.PORT || 3000, () =>
  console.log(`☕ Coffee server running on port ${process.env.PORT || 3000}`),
);
