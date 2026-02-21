const mysql = require("mysql2");

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});
console.log("HOST:", process.env.DB_HOST);
console.log("PORT:", process.env.DB_PORT);
db.connect(err => {
  if (err) {
    console.log("Error DB:", err);
    return;
  }
  console.log("Conectado a MySQL");
});

module.exports = db;
