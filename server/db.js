const mysql = require("mysql2");

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  port: process.env.DB_PORT || 3360, // usa tu puerto 3360
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,

  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Apply timezone per pooled connection. Named zones can fail on some MySQL setups,
// so a fixed offset is safer in VPS environments.
db.on("connection", (connection) => {
  connection.query("SET time_zone = '-07:00'", (err) => {
    if (err) {
      console.error("No se pudo establecer zona horaria de MySQL (-07:00):", err.message);
    }
  });
});

// Opcional: verificar que el pool puede conectarse
db.getConnection((err, connection) => {
  if (err) {
    console.log("Error DB:", err);
  } else {
    console.log("Pool MySQL conectado correctamente");
    connection.release();
  }
});

module.exports = db;
