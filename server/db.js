const mysql = require("mysql2/promise");

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  port: process.env.DB_PORT || 3360,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// 👇 AQUÍ ESTÁ LA CLAVE
const db = pool.promise();

// Verificación de conexión en modo async correcto
(async () => {
  try {
    const connection = await db.getConnection();
    console.log("Pool MySQL conectado correctamente");
    connection.release();
  } catch (err) {
    console.log("Error DB:", err);
  }
})();

module.exports = db;