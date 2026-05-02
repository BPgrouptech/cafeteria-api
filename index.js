require("dotenv").config();

const http = require("http");
const { Server } = require("socket.io");

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const crypto = require("crypto");
const {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
} = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

const pool = require("./db");

const app = express();

app.use(cors({ origin: "*" }));
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "cafeteria_secret";
const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024,
  },
});

const s3 = new S3Client({
  region: "auto",
  endpoint: process.env.R2_ENDPOINT,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
  },
});

async function uploadToR2(file) {
  const ext = path.extname(file.originalname || "").toLowerCase() || ".jpg";
  const key = `products/product_${Date.now()}_${crypto.randomUUID()}${ext}`;

  await s3.send(
    new PutObjectCommand({
      Bucket: R2_BUCKET_NAME,
      Key: key,
      Body: file.buffer,
      ContentType: file.mimetype,
    })
  );

  return key;
}

async function getSignedImageUrl(key) {
  if (!key) return null;

  const command = new GetObjectCommand({
    Bucket: R2_BUCKET_NAME,
    Key: key,
  });

  return getSignedUrl(s3, command, { expiresIn: 60 * 10 });
}

function auth(requiredRoles = []) {
  return (req, res, next) => {
    const header = req.headers.authorization;

    if (!header) {
      return res.status(401).json({ error: "Token requerido" });
    }

    const token = header.replace("Bearer ", "");

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = decoded;

      if (requiredRoles.length > 0 && !requiredRoles.includes(decoded.role)) {
        return res.status(403).json({ error: "No autorizado" });
      }

      next();
    } catch (error) {
      return res.status(401).json({ error: "Token inválido" });
    }
  };
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    message: "API Cafetería BP Group funcionando con R2 privado",
  });
});

app.get("/create-tables", async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('admin', 'mesero', 'barista')),
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS products (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT,
        price NUMERIC(10,2) NOT NULL DEFAULT 0,
        category TEXT,
        image_key TEXT,
        active BOOLEAN DEFAULT TRUE,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS product_options (
        id SERIAL PRIMARY KEY,
        product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        values_json JSONB NOT NULL DEFAULT '[]'::jsonb
      );

      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        waiter_id INTEGER REFERENCES users(id),
        status TEXT NOT NULL DEFAULT 'pendiente' CHECK (status IN ('pendiente', 'completado', 'cancelado')),
        total NUMERIC(10,2) NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW(),
        completed_at TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS order_items (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES orders(id) ON DELETE CASCADE,
        product_id INTEGER REFERENCES products(id),
        product_name TEXT NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 1,
        unit_price NUMERIC(10,2) NOT NULL DEFAULT 0,
        notes TEXT,
        options_json JSONB NOT NULL DEFAULT '{}'::jsonb
      );
    `);

    res.json({ ok: true, message: "Tablas creadas correctamente" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error creando tablas" });
  }
});

app.post("/create-admin", async (req, res) => {
  try {
    const { name, username, password } = req.body;

    const hash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (name, username, password_hash, role)
       VALUES ($1, $2, $3, 'admin')
       RETURNING id, name, username, role`,
      [name, username, hash]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);

    if (error.code === "23505") {
      return res.status(400).json({ error: "Ese usuario ya existe" });
    }

    res.status(500).json({ error: "Error creando admin" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);

    if (!valid) {
      return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
    }

    const token = jwt.sign(
      {
        id: user.id,
        name: user.name,
        username: user.username,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        username: user.username,
        role: user.role,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error en login" });
  }
});

app.post("/users", auth(["admin"]), async (req, res) => {
  try {
    const { name, username, password, role } = req.body;

    if (!["admin", "mesero", "barista"].includes(role)) {
      return res.status(400).json({ error: "Rol inválido" });
    }

    const hash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (name, username, password_hash, role)
       VALUES ($1, $2, $3, $4)
       RETURNING id, name, username, role`,
      [name, username, hash, role]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);

    if (error.code === "23505") {
      return res.status(400).json({ error: "Ese usuario ya existe" });
    }

    res.status(500).json({ error: "Error creando usuario" });
  }
});

app.get("/products", auth(["admin", "mesero", "barista"]), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        p.*,
        COALESCE(
          json_agg(
            json_build_object(
              'id', po.id,
              'name', po.name,
              'values', po.values_json
            )
          ) FILTER (WHERE po.id IS NOT NULL),
          '[]'
        ) AS options
      FROM products p
      LEFT JOIN product_options po ON po.product_id = p.id
      WHERE p.active = TRUE
      GROUP BY p.id
      ORDER BY p.category, p.name
    `);

    const products = await Promise.all(
      result.rows.map(async (product) => ({
        ...product,
        image_url: await getSignedImageUrl(product.image_key),
      }))
    );

    res.json(products);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error obteniendo productos" });
  }
});

app.post("/products", auth(["admin"]), upload.single("image"), async (req, res) => {
  try {
    const { name, description, price, category } = req.body;

    let imageKey = null;

    if (req.file) {
      imageKey = await uploadToR2(req.file);
    }

    const result = await pool.query(
      `INSERT INTO products (name, description, price, category, image_key)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [name, description, price, category, imageKey]
    );

    const product = result.rows[0];

    res.json({
      ...product,
      image_url: await getSignedImageUrl(product.image_key),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error creando producto" });
  }
});

app.put("/products/:id", auth(["admin"]), upload.single("image"), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, price, category, active } = req.body;

    let imageKey = req.body.image_key || null;

    if (req.file) {
      imageKey = await uploadToR2(req.file);
    }

    const result = await pool.query(
      `UPDATE products
       SET name = $1,
           description = $2,
           price = $3,
           category = $4,
           active = $5,
           image_key = COALESCE($6, image_key)
       WHERE id = $7
       RETURNING *`,
      [name, description, price, category, active ?? true, imageKey, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Producto no encontrado" });
    }

    const product = result.rows[0];

    res.json({
      ...product,
      image_url: await getSignedImageUrl(product.image_key),
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error actualizando producto" });
  }
});

app.delete("/products/:id", auth(["admin"]), async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query("UPDATE products SET active = FALSE WHERE id = $1", [id]);

    res.json({ ok: true, message: "Producto desactivado" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error eliminando producto" });
  }
});

app.post("/products/:id/options", auth(["admin"]), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, values } = req.body;

    const result = await pool.query(
      `INSERT INTO product_options (product_id, name, values_json)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [id, name, JSON.stringify(values || [])]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error creando opción" });
  }
});

app.delete("/product-options/:id", auth(["admin"]), async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query("DELETE FROM product_options WHERE id = $1", [id]);

    res.json({ ok: true, message: "Opción eliminada" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error eliminando opción" });
  }
});

app.post("/orders", auth(["admin", "mesero"]), async (req, res) => {
  const client = await pool.connect();

  try {
    const { items } = req.body;

    if (!items || items.length === 0) {
      return res.status(400).json({ error: "La orden no tiene productos" });
    }

    await client.query("BEGIN");

    let total = 0;

    const orderResult = await client.query(
      `INSERT INTO orders (waiter_id, status, total)
       VALUES ($1, 'pendiente', 0)
       RETURNING *`,
      [req.user.id]
    );

    const order = orderResult.rows[0];

    for (const item of items) {
      const productResult = await client.query(
        "SELECT * FROM products WHERE id = $1 AND active = TRUE",
        [item.product_id]
      );

      if (productResult.rows.length === 0) {
        throw new Error("Producto no encontrado");
      }

      const product = productResult.rows[0];
      const quantity = Number(item.quantity || 1);
      const unitPrice = Number(product.price);
      const lineTotal = quantity * unitPrice;

      total += lineTotal;

      await client.query(
        `INSERT INTO order_items 
         (order_id, product_id, product_name, quantity, unit_price, notes, options_json)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          order.id,
          product.id,
          product.name,
          quantity,
          unitPrice,
          item.notes || "",
          JSON.stringify(item.options || {}),
        ]
      );
    }

    const finalOrder = await client.query(
      "UPDATE orders SET total = $1 WHERE id = $2 RETURNING *",
      [total, order.id]
    );

    await client.query("COMMIT");
io.emit("new_order", finalOrder.rows[0]);

    res.json(finalOrder.rows[0]);
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(error);
    res.status(500).json({ error: "Error creando orden" });
  } finally {
    client.release();
  }
});

app.get("/orders/pending", auth(["admin", "barista", "mesero"]), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        o.*,
        u.name AS waiter_name,
        COALESCE(
          json_agg(
            json_build_object(
              'id', oi.id,
              'product_id', oi.product_id,
              'product_name', oi.product_name,
              'quantity', oi.quantity,
              'unit_price', oi.unit_price,
              'notes', oi.notes,
              'options', oi.options_json
            )
          ) FILTER (WHERE oi.id IS NOT NULL),
          '[]'
        ) AS items
      FROM orders o
      LEFT JOIN users u ON u.id = o.waiter_id
      LEFT JOIN order_items oi ON oi.order_id = o.id
      WHERE o.status = 'pendiente'
      GROUP BY o.id, u.name
      ORDER BY o.created_at ASC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error obteniendo órdenes" });
  }
});

app.put("/orders/:id", auth(["admin", "mesero"]), async (req, res) => {
  const client = await pool.connect();

  try {
    const { id } = req.params;
    const { items } = req.body;

    if (!items || items.length === 0) {
      return res.status(400).json({ error: "La orden no tiene productos" });
    }

    await client.query("BEGIN");

    const orderResult = await client.query(
      `SELECT * FROM orders 
       WHERE id = $1 AND status = 'pendiente'`,
      [id]
    );

    if (orderResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        error: "Orden no encontrada o ya fue completada",
      });
    }

    await client.query("DELETE FROM order_items WHERE order_id = $1", [id]);

    let total = 0;

    for (const item of items) {
      const productResult = await client.query(
        "SELECT * FROM products WHERE id = $1 AND active = TRUE",
        [item.product_id]
      );

      if (productResult.rows.length === 0) {
        throw new Error("Producto no encontrado");
      }

      const product = productResult.rows[0];
      const quantity = Number(item.quantity || 1);
      const unitPrice = Number(product.price);
      const lineTotal = quantity * unitPrice;

      total += lineTotal;

      await client.query(
        `INSERT INTO order_items 
         (order_id, product_id, product_name, quantity, unit_price, notes, options_json)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
          id,
          product.id,
          product.name,
          quantity,
          unitPrice,
          item.notes || "",
          JSON.stringify(item.options || {}),
        ]
      );
    }

    const updatedOrder = await client.query(
      `UPDATE orders 
       SET total = $1
       WHERE id = $2
       RETURNING *`,
      [total, id]
    );

    await client.query("COMMIT");

    io.emit("order_updated", updatedOrder.rows[0]);

    res.json(updatedOrder.rows[0]);
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(error);
    res.status(500).json({ error: "Error actualizando orden" });
  } finally {
    client.release();
  }
});

app.put("/orders/:id/complete", auth(["admin", "barista"]), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `UPDATE orders
       SET status = 'completado',
           completed_at = NOW()
       WHERE id = $1
       RETURNING *`,
      [id]
    );
io.emit("order_completed", result.rows[0]);
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error completando orden" });
  }
});

app.put("/orders/:id/cancel", auth(["admin"]), async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `UPDATE orders
       SET status = 'cancelado'
       WHERE id = $1
       RETURNING *`,
      [id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error cancelando orden" });
  }
});

app.get("/orders/history", auth(["admin"]), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        o.*,
        u.name AS waiter_name,
        COALESCE(
          json_agg(
            json_build_object(
              'product_name', oi.product_name,
              'quantity', oi.quantity,
              'unit_price', oi.unit_price,
              'notes', oi.notes,
              'options', oi.options_json
            )
          ) FILTER (WHERE oi.id IS NOT NULL),
          '[]'
        ) AS items
      FROM orders o
      LEFT JOIN users u ON u.id = o.waiter_id
      LEFT JOIN order_items oi ON oi.order_id = o.id
      GROUP BY o.id, u.name
      ORDER BY o.created_at DESC
      LIMIT 200
    `);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error obteniendo historial" });
  }
});

const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*",
  },
});

io.on("connection", (socket) => {
  console.log("Cliente conectado");
});

server.listen(PORT, () => {
  console.log(`API Cafetería corriendo en puerto ${PORT}`);
});