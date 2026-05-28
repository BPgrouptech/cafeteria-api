const { Pool, types } = require("pg");

// TIMESTAMP WITHOUT TIME ZONE (OID 1114): el driver de pg las parsea como
// hora local del proceso Node. Como Railway corre en UTC, forzamos a tratarlas
// siempre como UTC agregando 'Z'. Así new Date() las interpreta correctamente.
types.setTypeParser(1114, (str) => (str ? new Date(str + "Z") : null));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false,
});

module.exports = pool;