require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("./db");

const app = express();
app.use(express.json());

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

const wrap = (fn) => async (req, res, next) => {
  try {
    await fn(req, res, next);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};

const sign = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "30d" });

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

app.get(
  "/shops",
  wrap(async (req, res) => {
    const { rows } = await pool.query(
      "SELECT * FROM shops ORDER BY rating DESC",
    );
    res.json(rows);
  }),
);

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

app.post(
  "/seed",
  wrap(async (req, res) => {
    const SHOPS = [
      {
        id: "s1",
        name: "Ember & Oak",
        area: "Downtown",
        rating: 4.8,
        mins: 12,
        tag: "Specialty roaster",
        img: "https://images.unsplash.com/photo-1495474472287-4d71bcdd2085?w=600",
      },
      {
        id: "s2",
        name: "The Grind",
        area: "Midtown",
        rating: 4.6,
        mins: 8,
        tag: "Cold brew experts",
        img: "https://images.unsplash.com/photo-1509042239860-f550ce710b93?w=600",
      },
      {
        id: "s3",
        name: "Volta Espresso",
        area: "East Side",
        rating: 4.9,
        mins: 18,
        tag: "Italian style",
        img: "https://images.unsplash.com/photo-1554118811-1e0d58224f24?w=600",
      },
      {
        id: "s4",
        name: "Ritual Brew",
        area: "West Village",
        rating: 4.7,
        mins: 22,
        tag: "Single origin",
        img: "https://images.unsplash.com/photo-1445116572660-236099ec97a0?w=600",
      },
      {
        id: "s5",
        name: "Moka House",
        area: "Uptown",
        rating: 4.5,
        mins: 10,
        tag: "Family owned",
        img: "https://images.unsplash.com/photo-1521017432531-fbd92d768814?w=600",
      },
    ];

    const ITEMS = [
      // --- Ember & Oak (s1) ---
      {
        id: "1",
        shopId: "s1",
        name: "Flat White",
        desc: "Double ristretto, velvety microfoam",
        price: "4.50",
        cat: "Espresso",
        img: "https://images.unsplash.com/photo-1577968897966-3d4325b36b61?w=400",
      },
      {
        id: "2",
        shopId: "s1",
        name: "Oak Latte",
        desc: "Smoked vanilla, oat milk",
        price: "5.50",
        cat: "Latte",
        img: "https://images.unsplash.com/photo-1593444202241-24da7af70a4a?w=400",
      },
      {
        id: "3",
        shopId: "s1",
        name: "Ember Cold Brew",
        desc: "20-hr steep, chocolate notes",
        price: "5.00",
        cat: "Cold Brew",
        img: "https://images.unsplash.com/photo-1461023058943-07fcbe16d735?w=400",
      },
      {
        id: "4",
        shopId: "s1",
        name: "Maple Cortado",
        desc: "Equal parts espresso & warm milk",
        price: "4.20",
        cat: "Espresso",
        img: "https://images.unsplash.com/photo-1510707577719-5d6833039747?w=400",
      },
      {
        id: "5",
        shopId: "s1",
        name: "Hojicha Latte",
        desc: "Roasted green tea, steamed milk",
        price: "5.80",
        cat: "Tea",
        img: "https://images.unsplash.com/photo-1515823662972-da6a2e4d3002?w=400",
      },
      {
        id: "31",
        shopId: "s1",
        name: "Black Sesame Latte",
        desc: "Toasted charcoal notes, almond milk",
        price: "6.00",
        cat: "Latte",
        img: "https://images.unsplash.com/photo-1572286258217-400f89ffc7fa?w=400",
      },
      {
        id: "32",
        shopId: "s1",
        name: "Smoked Americano",
        desc: "Oak-smoked water, house blend",
        price: "3.80",
        cat: "Espresso",
        img: "https://images.unsplash.com/photo-1551030173-122aabc4489c?w=400",
      },

      // --- The Grind (s2) ---
      {
        id: "6",
        shopId: "s2",
        name: "Nitro Cold Brew",
        desc: "Nitrogen-infused, creamy texture",
        price: "5.50",
        cat: "Cold Brew",
        img: "https://images.unsplash.com/photo-1517701604599-bb29b565090c?w=400",
      },
      {
        id: "7",
        shopId: "s2",
        name: "Grind Espresso",
        desc: "Dark roast, rich crema",
        price: "3.20",
        cat: "Espresso",
        img: "https://images.unsplash.com/photo-1510591509098-f4fdc6d0ff04?w=400",
      },
      {
        id: "8",
        shopId: "s2",
        name: "Brown Sugar Latte",
        desc: "House brown sugar syrup, cinnamon",
        price: "5.70",
        cat: "Latte",
        img: "https://images.unsplash.com/photo-1541167760496-162955ed8a9f?w=400",
      },
      {
        id: "9",
        shopId: "s2",
        name: "Cold Tonic",
        desc: "Espresso over sparkling tonic",
        price: "5.00",
        cat: "Cold Brew",
        img: "https://images.unsplash.com/photo-1499961024600-ad094db305cc?w=400",
      },
      {
        id: "10",
        shopId: "s2",
        name: "Chai Latte",
        desc: "Masala spiced, oat milk",
        price: "5.20",
        cat: "Tea",
        img: "https://images.unsplash.com/photo-1576092768241-dec231879fc3?w=400",
      },
      {
        id: "33",
        shopId: "s2",
        name: "Iced Dirty Chai",
        desc: "Chai tea with a shot of espresso",
        price: "6.20",
        cat: "Tea",
        img: "https://images.unsplash.com/photo-1553909489-cd47e0907d3f?w=400",
      },
      {
        id: "34",
        shopId: "s2",
        name: "Midnight Mocha",
        desc: "Extra dark cocoa, heavy cream",
        price: "5.50",
        cat: "Latte",
        img: "https://images.unsplash.com/photo-1544787210-2211d403ef35?w=400",
      },

      // --- Volta Espresso (s3) ---
      {
        id: "11",
        shopId: "s3",
        name: "Doppio",
        desc: "Classic Italian double shot",
        price: "3.00",
        cat: "Espresso",
        img: "https://images.unsplash.com/photo-1579992357154-faf4bfe95b3d?w=400",
      },
      {
        id: "12",
        shopId: "s3",
        name: "Macchiato",
        desc: "Espresso, dash of foam",
        price: "3.50",
        cat: "Espresso",
        img: "https://images.unsplash.com/photo-1485808191679-5f86510bd9d4?w=400",
      },
      {
        id: "13",
        shopId: "s3",
        name: "Affogato",
        desc: "Vanilla gelato, hot espresso",
        price: "6.00",
        cat: "Espresso",
        img: "https://images.unsplash.com/photo-1594132225352-7067f1fe6d83?w=400",
      },
      {
        id: "14",
        shopId: "s3",
        name: "Volta Latte",
        desc: "Hazlenut, silky steamed milk",
        price: "5.40",
        cat: "Latte",
        img: "https://images.unsplash.com/photo-1536939459926-301728717817?w=400",
      },
      {
        id: "15",
        shopId: "s3",
        name: "Sparkling Lemon Tea",
        desc: "Earl grey, lemon, soda",
        price: "4.80",
        cat: "Tea",
        img: "https://images.unsplash.com/photo-1556679343-c7306c1976bc?w=400",
      },
      {
        id: "35",
        shopId: "s3",
        name: "Cappuccino Roma",
        desc: "Perfect foam, dusted with cocoa",
        price: "4.80",
        cat: "Espresso",
        img: "https://images.unsplash.com/photo-1572442388796-11668a67e53d?w=400",
      },

      // --- Ritual Brew (s4) ---
      {
        id: "16",
        shopId: "s4",
        name: "Ethiopian Pour Over",
        desc: "Single origin, floral & citrus",
        price: "6.50",
        cat: "Espresso",
        img: "https://images.unsplash.com/photo-1544666059-869f6ae7336d?w=400",
      },
      {
        id: "17",
        shopId: "s4",
        name: "Iced Matcha",
        desc: "Ceremonial grade, oat milk, ice",
        price: "5.80",
        cat: "Tea",
        img: "https://images.unsplash.com/photo-1515823064-d6e0c04616a7?w=400",
      },
      {
        id: "18",
        shopId: "s4",
        name: "Ritual Cold Brew",
        desc: "Colombian blend, 24-hr brew",
        price: "5.20",
        cat: "Cold Brew",
        img: "https://images.unsplash.com/photo-1499338673552-7eb485a3c03a?w=400",
      },
      {
        id: "19",
        shopId: "s4",
        name: "Spiced Latte",
        desc: "Cardamom, clove, steamed milk",
        price: "5.60",
        cat: "Latte",
        img: "https://images.unsplash.com/photo-1592663527359-cf6642f54cff?w=400",
      },
      {
        id: "20",
        shopId: "s4",
        name: "Cascara Fizz",
        desc: "Coffee cherry tea, sparkling water",
        price: "5.00",
        cat: "Tea",
        img: "https://images.unsplash.com/photo-1513558161293-cdaf765ed2fd?w=400",
      },
      {
        id: "36",
        shopId: "s4",
        name: "Cloud Brew",
        desc: "Cold brew with vanilla sweet foam",
        price: "5.90",
        cat: "Cold Brew",
        img: "https://images.unsplash.com/photo-1517701550927-30cf4ae1dba5?w=400",
      },

      {
        id: "21",
        shopId: "s5",
        name: "Moka Pot Brew",
        desc: "Traditional stovetop, bold body",
        price: "3.80",
        cat: "Espresso",
        img: "https://images.unsplash.com/photo-1544025162-d76694265947?w=400",
      },
      {
        id: "22",
        shopId: "s5",
        name: "Caramel Latte",
        desc: "Salted caramel drizzle, whole milk",
        price: "5.20",
        cat: "Latte",
        img: "https://images.unsplash.com/photo-1599398054066-846f28917f38?w=400",
      },
      {
        id: "23",
        shopId: "s5",
        name: "Vanilla Cold Brew",
        desc: "House vanilla, slow cold steep",
        price: "4.90",
        cat: "Cold Brew",
        img: "https://images.unsplash.com/photo-1461023058943-07fcbe16d735?w=400",
      },
      {
        id: "24",
        shopId: "s5",
        name: "Rose Latte",
        desc: "Rose water, honey, oat milk",
        price: "5.80",
        cat: "Latte",
        img: "https://images.unsplash.com/photo-1585445490387-f47934b73b54?w=400",
      },
      {
        id: "25",
        shopId: "s5",
        name: "Mint Green Tea",
        desc: "Sencha, fresh mint, honey",
        price: "4.50",
        cat: "Tea",
        img: "https://images.unsplash.com/photo-1563823251941-b9989d1e8d97?w=400",
      },
      {
        id: "37",
        shopId: "s5",
        name: "Honey Lavender Latte",
        desc: "Infused lavender, local honey",
        price: "6.00",
        cat: "Latte",
        img: "https://images.unsplash.com/photo-1512568448817-79a0d29c9683?w=400",
      },
      {
        id: "38",
        shopId: "s5",
        name: "Vietnamese Coffee",
        desc: "Strong brew with condensed milk",
        price: "5.50",
        cat: "Espresso",
        img: "https://images.unsplash.com/photo-1493925410384-84f842e616fb?w=400",
      },
    ];

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

app.listen(process.env.PORT || 3000, () =>
  console.log(`☕ Coffee server running on port ${process.env.PORT || 3000}`),
);
