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

let ultimoEstadoSistema = null; // null = no verificado aún

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

async function isSistemaAbierto() {
  return { abierto: true };
}

async function verificarSistemaAbierto(req, res, next) {
  const estado = await isSistemaAbierto();
  if (!estado.abierto) {
    return res.status(503).json({
      error: `El sistema está cerrado hasta las ${estado.hora_apertura}.`,
      hora_apertura: estado.hora_apertura,
      sistema_cerrado: true,
    });
  }
  next();
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
        role TEXT NOT NULL CHECK (role IN ('admin', 'mesero', 'barista', 'cajero')),
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
        status TEXT NOT NULL DEFAULT 'pendiente' CHECK (status IN ('pendiente', 'completado', 'cancelado', 'pagado')),
        total NUMERIC(10,2) NOT NULL DEFAULT 0,
        table_number INTEGER,
        payment_method TEXT CHECK (payment_method IN ('efectivo', 'tarjeta')),
        amount_paid NUMERIC(10,2),
        change_given NUMERIC(10,2),
        created_at TIMESTAMP DEFAULT NOW(),
        completed_at TIMESTAMP,
        paid_at TIMESTAMP
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

      CREATE TABLE IF NOT EXISTS caja_diaria (
        id SERIAL PRIMARY KEY,
        fecha DATE UNIQUE NOT NULL,
        caja_chica_apertura NUMERIC(10,2) NOT NULL DEFAULT 0,
        caja_chica_cierre NUMERIC(10,2),
        cerrado_por INTEGER REFERENCES users(id),
        cerrado_at TIMESTAMP,
        notas TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    res.json({ ok: true, message: "Tablas creadas correctamente" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error creando tablas" });
  }
});

app.get("/fix-orders-table-number", async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE orders 
      ADD COLUMN IF NOT EXISTS table_number INTEGER;
    `);

    res.json({
      ok: true,
      message: "Campo table_number agregado correctamente",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error agregando table_number" });
  }
});

app.get("/fix-cajero", async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
      ALTER TABLE users ADD CONSTRAINT users_role_check
        CHECK (role IN ('admin', 'mesero', 'barista', 'cajero'));

      ALTER TABLE orders DROP CONSTRAINT IF EXISTS orders_status_check;
      ALTER TABLE orders ADD CONSTRAINT orders_status_check
        CHECK (status IN ('pendiente', 'completado', 'cancelado', 'pagado'));

      ALTER TABLE orders ADD COLUMN IF NOT EXISTS paid_at TIMESTAMP;
    `);

    res.json({ ok: true, message: "Migración cajero completada" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error en migración cajero" });
  }
});

app.get("/fix-payment-columns", async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS amount_paid NUMERIC(10,2);
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS change_given NUMERIC(10,2);
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS payment_method TEXT;
      ALTER TABLE orders ADD COLUMN IF NOT EXISTS pickup_name TEXT;
    `);

    res.json({ ok: true, message: "Columnas de pago, cambio y método agregadas" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error en migración de columnas de pago" });
  }
});

app.get("/reset-orders", async (req, res) => {
  try {
    await pool.query(`
      TRUNCATE order_items, orders RESTART IDENTITY CASCADE;
    `);
    res.json({ ok: true, message: "Historial de pedidos eliminado" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error eliminando pedidos" });
  }
});

app.get("/reset-sistema", async (req, res) => {
  try {
    await pool.query(`
      TRUNCATE order_items, orders RESTART IDENTITY CASCADE;
      TRUNCATE caja_diaria RESTART IDENTITY;
    `);
    res.json({ ok: true, message: "Sistema reiniciado: órdenes y caja eliminados" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error reiniciando sistema" });
  }
});

app.get("/fix-inventory", async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ingredients (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        unit TEXT NOT NULL DEFAULT 'pza',
        stock NUMERIC(10,3) NOT NULL DEFAULT 0,
        min_stock NUMERIC(10,3) NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS product_ingredients (
        id SERIAL PRIMARY KEY,
        product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
        ingredient_id INTEGER REFERENCES ingredients(id) ON DELETE CASCADE,
        quantity NUMERIC(10,3) NOT NULL DEFAULT 0,
        UNIQUE(product_id, ingredient_id)
      );
    `);
    res.json({ ok: true, message: "Tablas de inventario creadas" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error creando tablas de inventario" });
  }
});

app.get("/fix-ingredients-unique", async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE ingredients ADD CONSTRAINT ingredients_name_unique UNIQUE (name);
    `);
    res.json({ ok: true, message: "Constraint único en nombre de ingrediente agregado" });
  } catch (error) {
    if (error.code === "42P07") return res.json({ ok: true, message: "El constraint ya existía" });
    console.error(error);
    res.status(500).json({ error: "Error agregando constraint" });
  }
});

// ─── Ingredientes ────────────────────────────────────────────────────────────

app.get("/ingredients", auth(["admin"]), async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM ingredients ORDER BY name ASC"
    );
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error obteniendo ingredientes" });
  }
});

app.post("/ingredients", auth(["admin"]), async (req, res) => {
  try {
    const { name, unit, stock, min_stock } = req.body;
    if (!name || !unit) return res.status(400).json({ error: "Nombre y unidad requeridos" });
    const result = await pool.query(
      `INSERT INTO ingredients (name, unit, stock, min_stock)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [name, unit, Number(stock) || 0, Number(min_stock) || 0]
    );
    res.json(result.rows[0]);
  } catch (error) {
    if (error.code === "23505") {
      return res.status(400).json({ error: `Ya existe un ingrediente llamado "${req.body.name}"` });
    }
    console.error(error);
    res.status(500).json({ error: "Error creando ingrediente" });
  }
});

app.put("/ingredients/:id", auth(["admin"]), async (req, res) => {
  try {
    const { id } = req.params;
    const { name, unit, min_stock } = req.body;
    const result = await pool.query(
      `UPDATE ingredients SET name = $1, unit = $2, min_stock = $3 WHERE id = $4 RETURNING *`,
      [name, unit, Number(min_stock) || 0, id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Ingrediente no encontrado" });
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error actualizando ingrediente" });
  }
});

app.delete("/ingredients/:id", auth(["admin"]), async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query("DELETE FROM ingredients WHERE id = $1", [id]);
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error eliminando ingrediente" });
  }
});

app.put("/ingredients/:id/stock", auth(["admin"]), async (req, res) => {
  try {
    const { id } = req.params;
    const { cantidad } = req.body; // positivo = agregar, negativo = restar
    if (cantidad === undefined) return res.status(400).json({ error: "Cantidad requerida" });
    const result = await pool.query(
      `UPDATE ingredients SET stock = GREATEST(0, stock + $1) WHERE id = $2 RETURNING *`,
      [Number(cantidad), id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: "Ingrediente no encontrado" });
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error ajustando stock" });
  }
});

// ─── Recetas ─────────────────────────────────────────────────────────────────

app.get("/products/:id/recipe", auth(["admin"]), async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `SELECT pi.id, pi.ingredient_id, pi.quantity, i.name, i.unit
       FROM product_ingredients pi
       JOIN ingredients i ON i.id = pi.ingredient_id
       WHERE pi.product_id = $1
       ORDER BY i.name ASC`,
      [id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error obteniendo receta" });
  }
});

app.post("/products/:id/recipe", auth(["admin"]), async (req, res) => {
  try {
    const { id } = req.params;
    const { ingredient_id, quantity } = req.body;
    if (!ingredient_id || !quantity) return res.status(400).json({ error: "ingredient_id y quantity requeridos" });
    const result = await pool.query(
      `INSERT INTO product_ingredients (product_id, ingredient_id, quantity)
       VALUES ($1, $2, $3)
       ON CONFLICT (product_id, ingredient_id) DO UPDATE SET quantity = $3
       RETURNING *`,
      [id, ingredient_id, Number(quantity)]
    );
    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error guardando receta" });
  }
});

app.delete("/products/:id/recipe/:ingredientId", auth(["admin"]), async (req, res) => {
  try {
    const { id, ingredientId } = req.params;
    await pool.query(
      "DELETE FROM product_ingredients WHERE product_id = $1 AND ingredient_id = $2",
      [id, ingredientId]
    );
    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error eliminando ingrediente de receta" });
  }
});

app.get("/inventory/alerts", auth(["admin"]), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM ingredients WHERE stock <= min_stock ORDER BY (stock / NULLIF(min_stock, 0)) ASC`
    );
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error obteniendo alertas" });
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

    const result = await pool.query("SELECT * FROM users WHERE username = $1", [
      username,
    ]);

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

    if (!["admin", "mesero", "barista", "cajero"].includes(role)) {
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

app.get("/products", auth(["admin", "mesero", "barista", "cajero"]), async (req, res) => {
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

app.post(
  "/products",
  auth(["admin"]),
  upload.single("image"),
  async (req, res) => {
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
  }
);

app.put(
  "/products/:id",
  auth(["admin"]),
  upload.single("image"),
  async (req, res) => {
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
  }
);

app.delete("/products/:id", auth(["admin"]), async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ error: "Contraseña requerida" });
    }

    const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    const valid = await bcrypt.compare(password, userResult.rows[0].password_hash);

    if (!valid) {
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    await pool.query("UPDATE products SET active = FALSE WHERE id = $1", [id]);

    res.json({ ok: true, message: "Elemento eliminado del menú" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error eliminando elemento del menú" });
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

app.post("/seed-menu-maranba", auth(["admin"]), async (req, res) => {
  try {
    const menu = [
      { name: "Expreso sencillo", category: "Con Café", price: 35 },
      { name: "Expreso pistache", category: "Con Café", price: 90 },
      { name: "Café de olla", category: "Con Café", price: 65 },
      { name: "Americano", category: "Con Café", price: 45 },
      { name: "Capuchino", category: "Con Café", price: 65 },
      { name: "Latte", category: "Con Café", price: 75 },
      { name: "Caramel macchiato", category: "Con Café", price: 75 },
      { name: "Mocha / Vainilla", category: "Con Café", price: 75 },
      { name: "Dirty chai", category: "Con Café", price: 90 },
      { name: "Americano limón", category: "Con Café", price: 60 },
      { name: "Choko nube", category: "Con Café", price: 125 },
      { name: "Zuca nube", category: "Con Café", price: 125 },
      { name: "Dalgona coffee", category: "Con Café", price: 100 },
      { name: "Chocolate", category: "Con Café", price: 80 },
      { name: "Miss Coffee", category: "Con Café", price: 100 },
      { name: "Cookie nube", category: "Con Café", price: 125 },
      { name: "White mocha", category: "Con Café", price: 95 },
      { name: "Chai", category: "Sin Café", price: 80 },
      { name: "Matcha", category: "Sin Café", price: 90 },
      { name: "Tisanate", category: "Sin Café", price: 80 },
      { name: "Oreo frappé", category: "Sin Café", price: 90 },
      { name: "Soda italiana", category: "Sin Café", price: 90 },
      { name: "Taro", category: "Sin Café", price: 90 },
      { name: "Jugo de naranja", category: "Jugos", price: 60 },
      { name: "Jugo verde", category: "Jugos", price: 75 },
      { name: "Agua fresca", category: "Jugos", price: 35 },
      { name: "Shot inmune", category: "Jugos", price: 40 },
      { name: "Shot detox", category: "Jugos", price: 35 },
      { name: "Chunky Monkey", category: "Smoothie", price: 80 },
      { name: "Frutos rojos", category: "Smoothie", price: 80 },
      { name: "Tropical", category: "Smoothie", price: 75 },
      { name: "Carajillo", category: "Traguitos", price: 120 },
      {
        name: "Carajillo plátano Turin-Mazapán",
        category: "Traguitos",
        price: 150,
      },
      { name: "Vino rosado", category: "Traguitos", price: 140 },
      { name: "Vino tinto", category: "Traguitos", price: 140 },
      { name: "Mimosa", category: "Traguitos", price: 130 },
      { name: "Beso de ángel", category: "Traguitos", price: 160 },
      { name: "Vaso de leche", category: "Otras Bebidas", price: 25 },
      { name: "Botella de agua", category: "Otras Bebidas", price: 25 },
      { name: "Coca Cola", category: "Otras Bebidas", price: 30 },
      { name: "Avocado toast de salmón", category: "Alimentos", price: 220 },
      { name: "Avocado toast con huevo", category: "Alimentos", price: 150 },
      { name: "Panini jamón y queso", category: "Alimentos", price: 120 },
      {
        name: "Panini con pepperoni y queso español",
        category: "Alimentos",
        price: 140,
      },
      { name: "Panini 4 quesos", category: "Alimentos", price: 130 },
      { name: "Yogurt con fruta", category: "Alimentos", price: 100 },
      { name: "Cóctel de frutas", category: "Alimentos", price: 90 },
      { name: "Hot cakes", category: "Alimentos", price: 140 },
      { name: "Ensalada de pollo", category: "Alimentos", price: 130 },
      { name: "Ensalada de atún", category: "Alimentos", price: 110 },
      { name: "Pizza pepperoni", category: "Alimentos", price: 130 },
      { name: "Rol de canela", category: "Postres", price: 65 },
      { name: "Galleta chocochip", category: "Postres", price: 40 },
      { name: "Choco flan", category: "Postres", price: 95 },
      { name: "Panqué de elote", category: "Postres", price: 55 },
      { name: "Brownie", category: "Postres", price: 45 },
      { name: "Concha", category: "Postres", price: 45 },
      { name: "Concha especial", category: "Postres", price: 70 },
      { name: "Pay de queso", category: "Postres", price: 60 },
      { name: "Cupcake de zanahoria", category: "Postres", price: 40 },
      { name: "Cheese cake guayaba", category: "Postres", price: 120 },
      { name: "Panqué de plátano", category: "Postres", price: 60 },
      { name: "Rebanada de zanahoria", category: "Postres", price: 120 },
      { name: "Rebanada de chocolate", category: "Postres", price: 115 },
    ];

    for (const item of menu) {
      await pool.query(
        `
        INSERT INTO products (name, description, price, category, active)
        VALUES ($1, $2, $3, $4, TRUE)
        ON CONFLICT DO NOTHING
        `,
        [item.name, "", item.price, item.category]
      );
    }

    res.json({
      ok: true,
      message: "Menú Maranba cargado correctamente",
      total: menu.length,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error cargando menú Maranba" });
  }
});

app.post("/orders", auth(["admin", "mesero"]), verificarSistemaAbierto, async (req, res) => {
  const client = await pool.connect();

  try {
    const { items, table_number, pickup_name } = req.body;

    if (table_number === undefined) {
      return res.status(400).json({ error: "Número de mesa requerido" });
    }

    if (!items || items.length === 0) {
      return res.status(400).json({ error: "La orden no tiene productos" });
    }

    await client.query("BEGIN");

    let total = 0;

    const orderResult = await client.query(
      `INSERT INTO orders (waiter_id, status, total, table_number, pickup_name)
       VALUES ($1, 'pendiente', 0, $2, $3)
       RETURNING *`,
      [req.user.id, table_number != null ? Number(table_number) : null, pickup_name || null]
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

app.get(
  "/orders/pending",
  auth(["admin", "barista", "mesero"]),
  async (req, res) => {
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
  }
);

app.get("/orders/open", auth(["admin", "cajero"]), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        o.*,
        u.name AS waiter_name,
        COALESCE(
          json_agg(
            json_build_object(
              'id', oi.id,
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
      WHERE o.status IN ('pendiente', 'completado')
      GROUP BY o.id, u.name
      ORDER BY o.created_at ASC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error obteniendo cuentas abiertas" });
  }
});

app.put("/orders/pay-table/:tableNumber", auth(["admin", "cajero"]), verificarSistemaAbierto, async (req, res) => {
  const client = await pool.connect();
  try {
    const { tableNumber } = req.params;
    const { payment_method, amount_paid } = req.body;
    const isLlevar = tableNumber === "llevar";

    if (!["efectivo", "tarjeta"].includes(payment_method)) {
      return res.status(400).json({ error: "Método de pago inválido" });
    }

    const ordersResult = await client.query(
      isLlevar
        ? "SELECT * FROM orders WHERE table_number IS NULL AND status IN ('pendiente', 'completado')"
        : "SELECT * FROM orders WHERE table_number = $1 AND status IN ('pendiente', 'completado')",
      isLlevar ? [] : [tableNumber]
    );

    if (ordersResult.rows.length === 0) {
      return res.status(404).json({ error: "No hay órdenes abiertas para esta mesa" });
    }

    const total = ordersResult.rows.reduce((sum, o) => sum + Number(o.total), 0);

    let paid = total;
    let change = 0;

    if (payment_method === "efectivo") {
      paid = Number(amount_paid);
      if (isNaN(paid) || paid < total) {
        return res.status(400).json({
          error: "Monto insuficiente",
          total,
          faltante: Number((total - paid).toFixed(2)),
        });
      }
      change = Number((paid - total).toFixed(2));
    }

    await client.query("BEGIN");

    const updatedOrders = [];
    for (const order of ordersResult.rows) {
      const result = await client.query(
        `UPDATE orders
         SET status = 'pagado', paid_at = NOW(),
             payment_method = $2, amount_paid = $3, change_given = $4
         WHERE id = $1 RETURNING *`,
        [order.id, payment_method, Number(order.total), 0]
      );
      updatedOrders.push(result.rows[0]);
      io.emit("order_paid", result.rows[0]);
    }

    await client.query("COMMIT");

    res.json({ ok: true, total, cambio: change, orders: updatedOrders });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(error);
    res.status(500).json({ error: "Error registrando pago" });
  } finally {
    client.release();
  }
});

app.put("/orders/:id/pay", auth(["admin", "cajero"]), verificarSistemaAbierto, async (req, res) => {
  try {
    const { id } = req.params;
    const { payment_method, amount_paid } = req.body;

    if (!["efectivo", "tarjeta"].includes(payment_method)) {
      return res.status(400).json({ error: "Método de pago inválido. Usa 'efectivo' o 'tarjeta'" });
    }

    const orderResult = await pool.query(
      "SELECT * FROM orders WHERE id = $1 AND status IN ('pendiente', 'completado')",
      [id]
    );

    if (orderResult.rows.length === 0) {
      return res.status(404).json({ error: "Cuenta no encontrada o ya fue pagada" });
    }

    const order = orderResult.rows[0];
    const total = Number(order.total);

    let paid = total;
    let change = 0;

    if (payment_method === "efectivo") {
      if (amount_paid === undefined || amount_paid === null) {
        return res.status(400).json({ error: "Con efectivo debes enviar el monto recibido (amount_paid)" });
      }

      paid = Number(amount_paid);

      if (isNaN(paid) || paid < 0) {
        return res.status(400).json({ error: "Monto recibido inválido" });
      }

      if (paid < total) {
        return res.status(400).json({
          error: "El monto recibido es menor al total",
          total,
          amount_paid: paid,
          faltante: Number((total - paid).toFixed(2)),
        });
      }

      change = Number((paid - total).toFixed(2));
    }

    const result = await pool.query(
      `UPDATE orders
       SET status = 'pagado',
           paid_at = NOW(),
           payment_method = $2,
           amount_paid = $3,
           change_given = $4
       WHERE id = $1
       RETURNING *`,
      [id, payment_method, paid, change]
    );

    io.emit("order_paid", result.rows[0]);

    res.json({
      ...result.rows[0],
      cambio: change,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error registrando pago" });
  }
});

app.put("/orders/:id", auth(["admin", "mesero"]), verificarSistemaAbierto, async (req, res) => {
  const client = await pool.connect();

  try {
    const { id } = req.params;
    const { items, table_number, pickup_name } = req.body;

    if (table_number === undefined) {
      return res.status(400).json({ error: "Número de mesa requerido" });
    }

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
       SET total = $1,
           table_number = $2,
           pickup_name = $3
       WHERE id = $4
       RETURNING *`,
      [total, table_number != null ? Number(table_number) : null, pickup_name || null, id]
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

app.put("/orders/:id/complete", auth(["admin", "barista"]), verificarSistemaAbierto, async (req, res) => {
  const client = await pool.connect();
  try {
    const { id } = req.params;

    await client.query("BEGIN");

    const result = await client.query(
      `UPDATE orders SET status = 'completado', completed_at = NOW() WHERE id = $1 RETURNING *`,
      [id]
    );

    // Descontar ingredientes según receta de cada producto de la orden
    const items = await client.query(
      "SELECT product_id, quantity FROM order_items WHERE order_id = $1",
      [id]
    );
    for (const item of items.rows) {
      const recipe = await client.query(
        "SELECT * FROM product_ingredients WHERE product_id = $1",
        [item.product_id]
      );
      for (const ri of recipe.rows) {
        await client.query(
          "UPDATE ingredients SET stock = GREATEST(0, stock - $1) WHERE id = $2",
          [ri.quantity * Number(item.quantity), ri.ingredient_id]
        );
      }
    }

    await client.query("COMMIT");

    io.emit("order_completed", result.rows[0]);

    res.json(result.rows[0]);
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(error);
    res.status(500).json({ error: "Error completando orden" });
  } finally {
    client.release();
  }
});

app.put("/orders/:id/reopen", auth(["admin", "cajero"]), verificarSistemaAbierto, async (req, res) => {
  try {
    const { id } = req.params;

    const current = await pool.query("SELECT status FROM orders WHERE id = $1", [id]);
    if (current.rows.length === 0) {
      return res.status(404).json({ error: "Orden no encontrada" });
    }
    if (current.rows[0].status !== "completado") {
      return res.status(400).json({ error: "Solo se pueden reabrir órdenes con estado 'completado'" });
    }

    const result = await pool.query(
      `UPDATE orders
       SET status = 'pendiente',
           completed_at = NULL
       WHERE id = $1
       RETURNING *`,
      [id]
    );

    io.emit("order_reopened", result.rows[0]);

    res.json(result.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error reabriendo orden" });
  }
});

app.delete("/orders/:id", auth(["admin"]), async (req, res) => {
  try {
    const { id } = req.params;
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({ error: "Contraseña requerida" });
    }

    const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    const valid = await bcrypt.compare(password, userResult.rows[0].password_hash);

    if (!valid) {
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    const result = await pool.query(
      "DELETE FROM orders WHERE id = $1 RETURNING id",
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Orden no encontrada" });
    }

    res.json({ ok: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error eliminando orden" });
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
    const { month, year } = req.query;

    const conditions = [];
    const params = [];

    if (year) {
      params.push(Number(year));
      conditions.push(`EXTRACT(YEAR FROM o.created_at) = $${params.length}`);
    }

    if (month) {
      params.push(Number(month));
      conditions.push(`EXTRACT(MONTH FROM o.created_at) = $${params.length}`);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

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
      ${where}
      GROUP BY o.id, u.name
      ORDER BY o.created_at DESC
      LIMIT 500
    `, params);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error obteniendo historial" });
  }
});

app.get("/ventas/resumen", auth(["admin"]), async (req, res) => {
  try {
    const { month, year } = req.query;

    const conditions = ["o.status = 'pagado'"];
    const params = [];

    if (year) {
      params.push(Number(year));
      conditions.push(`EXTRACT(YEAR FROM o.paid_at) = $${params.length}`);
    }

    if (month) {
      params.push(Number(month));
      conditions.push(`EXTRACT(MONTH FROM o.paid_at) = $${params.length}`);
    }

    const where = `WHERE ${conditions.join(" AND ")}`;

    const [productsResult, totalsResult] = await Promise.all([
      pool.query(`
        SELECT
          oi.product_name,
          SUM(oi.quantity) AS total_cantidad,
          SUM(oi.quantity * oi.unit_price) AS total_vendido
        FROM order_items oi
        JOIN orders o ON o.id = oi.order_id
        ${where}
        GROUP BY oi.product_name
        ORDER BY total_vendido DESC
      `, params),
      pool.query(`
        SELECT
          COUNT(*) AS total_ordenes,
          COALESCE(SUM(o.total), 0) AS total_ingresos
        FROM orders o
        ${where}
      `, params),
    ]);

    res.json({
      resumen: totalsResult.rows[0],
      productos: productsResult.rows,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error obteniendo resumen de ventas" });
  }
});

app.get("/fix-session-start", async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE caja_diaria ADD COLUMN IF NOT EXISTS session_start_at TIMESTAMP;
      UPDATE caja_diaria SET session_start_at = created_at WHERE session_start_at IS NULL;
    `);
    res.json({ ok: true, message: "Columna session_start_at agregada" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error agregando columna" });
  }
});

app.get("/fix-next-opening", async (req, res) => {
  try {
    await pool.query(`
      ALTER TABLE caja_diaria ADD COLUMN IF NOT EXISTS next_opening_at TIMESTAMP;
    `);
    res.json({ ok: true, message: "Columna next_opening_at agregada" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error agregando columna" });
  }
});

app.get("/fix-configuracion", async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS configuracion (
        clave TEXT PRIMARY KEY,
        valor TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT NOW()
      );
      INSERT INTO configuracion (clave, valor)
      VALUES ('hora_apertura', '07:00')
      ON CONFLICT (clave) DO NOTHING;
    `);
    res.json({ ok: true, message: "Tabla configuracion creada" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error creando tabla configuracion" });
  }
});

app.get("/sistema/estado", auth(["admin", "mesero", "barista", "cajero"]), async (req, res) => {
  try {
    const estado = await isSistemaAbierto();

    if (ultimoEstadoSistema === false && estado.abierto) {
      io.emit("sistema_abierto", { hora_apertura: estado.hora_apertura });
    }
    ultimoEstadoSistema = estado.abierto;

    res.json(estado);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error verificando estado del sistema" });
  }
});

app.put("/configuracion/hora-apertura", auth(["admin"]), async (req, res) => {
  try {
    const { hora_apertura } = req.body;

    if (!hora_apertura || !/^\d{2}:\d{2}$/.test(hora_apertura)) {
      return res.status(400).json({ error: "Formato de hora inválido. Usa HH:MM (ej: 07:00)" });
    }

    await pool.query(`
      INSERT INTO configuracion (clave, valor, updated_at)
      VALUES ('hora_apertura', $1, NOW())
      ON CONFLICT (clave) DO UPDATE SET valor = $1, updated_at = NOW()
    `, [hora_apertura]);

    res.json({ ok: true, hora_apertura });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error actualizando hora de apertura" });
  }
});

app.get("/fix-caja-chica", async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS caja_diaria (
        id SERIAL PRIMARY KEY,
        fecha DATE UNIQUE NOT NULL,
        caja_chica_apertura NUMERIC(10,2) NOT NULL DEFAULT 0,
        caja_chica_cierre NUMERIC(10,2),
        cerrado_por INTEGER REFERENCES users(id),
        cerrado_at TIMESTAMP,
        notas TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    res.json({ ok: true, message: "Tabla caja_diaria creada correctamente" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error creando tabla caja_diaria" });
  }
});

app.get("/caja/hoy", auth(["admin", "cajero"]), async (req, res) => {
  try {
    // 1. Obtener o crear el registro de caja del día
    let cajaResult = await pool.query(
      "SELECT * FROM caja_diaria WHERE fecha = CURRENT_DATE"
    );

    let caja;
    if (cajaResult.rows.length === 0) {
      // Nuevo día: crear registro con la caja chica del cierre anterior
      const anteriorResult = await pool.query(`
        SELECT COALESCE(
          (SELECT caja_chica_cierre FROM caja_diaria
           WHERE caja_chica_cierre IS NOT NULL
           ORDER BY cerrado_at DESC LIMIT 1),
          0
        ) AS apertura_valor
      `);
      const apertura = Number(anteriorResult.rows[0]?.apertura_valor || 0);

      const insertResult = await pool.query(`
        INSERT INTO caja_diaria (fecha, caja_chica_apertura, session_start_at)
        VALUES (CURRENT_DATE, $1, NOW())
        RETURNING *
      `, [apertura]);
      caja = insertResult.rows[0];
    } else {
      caja = cajaResult.rows[0];
    }

    // 2. Ventas solo desde el inicio de la sesión actual
    const sessionStart = caja.session_start_at || caja.created_at;
    const ventasResult = await pool.query(`
      SELECT
        COUNT(*) AS total_ordenes,
        COALESCE(SUM(total), 0) AS total_ventas,
        COALESCE(SUM(CASE WHEN payment_method = 'efectivo' THEN total ELSE 0 END), 0) AS ventas_efectivo,
        COALESCE(SUM(CASE WHEN payment_method = 'tarjeta' THEN total ELSE 0 END), 0) AS ventas_tarjeta
      FROM orders
      WHERE status = 'pagado'
        AND paid_at >= $1
    `, [sessionStart]);

    const ventas = ventasResult.rows[0];
    const ventasEfectivo = Number(ventas.ventas_efectivo);
    const apertura = Number(caja.caja_chica_apertura);

    res.json({
      fecha: caja.fecha,
      caja_chica_apertura: apertura,
      ventas: {
        efectivo: ventasEfectivo,
        tarjeta: Number(ventas.ventas_tarjeta),
        total: Number(ventas.total_ventas),
        total_ordenes: Number(ventas.total_ordenes),
      },
      total_en_caja: Number((apertura + ventasEfectivo).toFixed(2)),
      cerrado: caja.caja_chica_cierre !== null,
      caja_chica_cierre: caja.caja_chica_cierre !== null ? Number(caja.caja_chica_cierre) : null,
      cerrado_at: caja.cerrado_at || null,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error obteniendo resumen de caja" });
  }
});

app.post("/caja/cerrar", auth(["admin"]), async (req, res) => {
  try {
    const { caja_chica, notas, password } = req.body;

    const nextOpen = new Date();
    nextOpen.setDate(nextOpen.getDate() + 1);
    nextOpen.setHours(7, 0, 0, 0);
    const next_opening_at = nextOpen.toISOString();

    if (caja_chica === undefined || caja_chica === null) {
      return res.status(400).json({ error: "Monto de caja chica requerido" });
    }

    const monto = Number(caja_chica);
    if (isNaN(monto) || monto < 0) {
      return res.status(400).json({ error: "Monto de caja chica inválido" });
    }

    if (!password) {
      return res.status(400).json({ error: "Contraseña requerida" });
    }

    const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    const valid = await bcrypt.compare(password, userResult.rows[0].password_hash);
    if (!valid) {
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    await pool.query(`
      INSERT INTO caja_diaria (fecha, caja_chica_apertura, caja_chica_cierre, cerrado_por, cerrado_at, notas)
      VALUES (CURRENT_DATE, 0, $1, $2, NOW(), $3)
      ON CONFLICT (fecha) DO UPDATE
        SET caja_chica_cierre = $1,
            cerrado_por = $2,
            cerrado_at = NOW(),
            notas = COALESCE($3, caja_diaria.notas)
    `, [monto, req.user.id, notas || null]);

    await pool.query(`
      INSERT INTO caja_cierres (fecha, monto, notas, cerrado_por, cerrado_at)
      VALUES (CURRENT_DATE, $1, $2, $3, NOW())
    `, [monto, notas || null, req.user.id]);

    res.json({ ok: true, message: "Caja cerrada correctamente" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error cerrando caja" });
  }
});

app.get("/fix-caja-cierres", async (req, res) => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS caja_cierres (
        id SERIAL PRIMARY KEY,
        fecha DATE NOT NULL,
        monto NUMERIC(10,2) NOT NULL,
        notas TEXT,
        cerrado_por INTEGER REFERENCES users(id),
        cerrado_at TIMESTAMP DEFAULT NOW()
      );
    `);
    res.json({ ok: true, message: "Tabla caja_cierres creada" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error creando tabla caja_cierres" });
  }
});

app.get("/caja/historial", auth(["admin"]), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        cc.*,
        u.name AS cerrado_por_nombre
      FROM caja_cierres cc
      LEFT JOIN users u ON u.id = cc.cerrado_por
      ORDER BY cc.cerrado_at DESC
      LIMIT 90
    `);

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error obteniendo historial de caja" });
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

