require("dotenv").config();
const jwt = require("jsonwebtoken");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const db = require("./db");
const verifyToken = require("./middlewares/auth");
const requireAdmin = require('./middlewares/requireAdmin');
const requireRole = require('./middlewares/requireRole');

const app = express();

app.use(cors());
app.use(express.json());

/* ==========================
   FILTRO USUARIOS + MEMBRESÍA
========================== */

// PROTEGIDO 
app.get(
  "/usuarios/filtrar-con-membresia",
  verifyToken,
  requireRole(["admin", "recepcionista"]),
  (req, res) => {

    const { id, nombre, fecha_inicio, fecha_fin, estado } = req.query;

    let sql = `
      SELECT 
        u.id,
        u.nombre,
        u.apellido,
        u.telefono,
        u.email,
        i.fecha_fin,
        CASE 
          WHEN i.fecha_fin IS NULL THEN 'INACTIVO'
          WHEN i.fecha_fin >= CURDATE() THEN 'ACTIVO'
          ELSE 'INACTIVO'
        END AS estado
      FROM usuarios u
      LEFT JOIN (
        SELECT usuario_id, MAX(fecha_fin) AS fecha_fin
        FROM inscripciones
        GROUP BY usuario_id
      ) i ON u.id = i.usuario_id
      WHERE 1=1
    `;

    const params = [];

    // 🔎 Filtro por ID
    if (id && id.trim() !== "") {
      sql += " AND u.id = ?";
      params.push(id);
    }

    // 🔎 Filtro por nombre
    if (nombre && nombre.trim() !== "") {
      sql += " AND (u.nombre LIKE ? OR u.apellido LIKE ?)";
      params.push(`%${nombre}%`, `%${nombre}%`);
    }

    // 📅 Día exacto de REGISTRO
    if (fecha_inicio && fecha_inicio.trim() !== "") {
      sql += " AND DATE(u.fecha_registro) = ?";
      params.push(fecha_inicio);
    }

    // 📅 Día exacto de VENCIMIENTO
    if (fecha_fin && fecha_fin.trim() !== "") {
      sql += " AND DATE(i.fecha_fin) = ?";
      params.push(fecha_fin);
    }

    // 🟢🔴 Filtro por estado
    if (estado && estado !== "todos") {
      sql += `
        AND (
          CASE 
            WHEN i.fecha_fin IS NULL THEN 'INACTIVO'
            WHEN i.fecha_fin >= CURDATE() THEN 'ACTIVO'
            ELSE 'INACTIVO'
          END
        ) = ?
      `;
      params.push(estado.toUpperCase());
    }

    sql += " ORDER BY u.id DESC";

    db.query(sql, params, (err, results) => {
      if (err) return res.status(500).json(err);
      res.json(results);
    });
  }
);


// PROTEGIDO JWT + ADMIN 
app.post(
  "/recepcionistas",
  verifyToken,
  requireAdmin,
  async (req, res) => {
  const { nombre, usuario, password } = req.body;

  if (!nombre || !usuario || !password) {
    return res.status(400).json({ message: "Faltan datos" });
  }

  try {
    const hash = await bcrypt.hash(password, 10);

    const sql = `
      INSERT INTO recepcionistas (nombre, usuario, password, rol)
      VALUES (?, ?, ?, 'recepcionista')
    `;

    db.query(
      sql,
      [nombre, usuario, hash],
      (err, result) => {
        if (err) {
          if (err.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ message: "El usuario ya existe" });
          }
          return res.status(500).json(err);
        }

        res.status(201).json({
          message: "Recepcionista registrado",
          id: result.insertId,
          nombre,
          usuario,
          rol: "recepcionista"
        });
      }
    );
  } catch (error) {
    res.status(500).json({ message: "Error interno" });
  }
});


/* ==========================
   LOGIN RECEPCIONISTA
========================== */

// NO REQUIERE PROTECCION
app.post("/login", (req, res) => {
  const { usuario, password } = req.body;

  const sql = "SELECT * FROM recepcionistas WHERE usuario = ?";

  db.query(sql, [usuario], async (err, results) => {
    if (err) return res.status(500).json(err);

    if (results.length === 0)
      return res.status(401).json({ message: "Usuario no encontrado" });

    const recep = results[0];
    const ok = await bcrypt.compare(password, recep.password);

    if (!ok)
      return res.status(401).json({ message: "Contraseña incorrecta" });

    // 🔐 AQUÍ se crea el token
    const token = jwt.sign(
      {
        id: recep.id,
        nombre: recep.nombre,
        rol: recep.rol
      },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    // Se envía el token + datos básicos
    res.json({
      token,
      user: {
        id: recep.id,
        nombre: recep.nombre,
        rol: recep.rol
      }
    });
  });
});


/* ==========================
   REGISTRAR USUARIO + INSCRIPCIÓN
========================== */

// PROTEGIDO 
app.post(
  "/registrar_usuario",
  verifyToken,
  requireRole(['admin', 'recepcionista']),
  (req, res) => {

    const {
      nombre,
      apellido,
      telefono,
      email,
      membresia_id,
      foto,
      fecha_inicio,
      fecha_fin
    } = req.body;

    // 🔹 Validación básica
    if (!nombre || !apellido || !telefono || !membresia_id) {
      return res.status(400).json({ message: "Faltan datos obligatorios" });
    }

    // 🔹 Validación de fechas si se envían manualmente
    if (fecha_inicio && fecha_fin) {
      if (new Date(fecha_fin) <= new Date(fecha_inicio)) {
        return res.status(400).json({
          message: "La fecha de vencimiento debe ser mayor a la fecha de inicio"
        });
      }
    }

    const sqlUser = `
      INSERT INTO usuarios (nombre, apellido, telefono, email, foto)
      VALUES (?, ?, ?, ?, ?)
    `;

    db.query(
      sqlUser,
      [
        nombre,
        apellido,
        telefono,
        email || null,
        foto || null
      ],
      (err, result) => {
        if (err) return res.status(500).json(err);

        const usuario_id = result.insertId;

        let sqlIns;
        let params;

        // 🔹 MODO MANUAL
        if (fecha_inicio && fecha_fin) {

          sqlIns = `
            INSERT INTO inscripciones
            (usuario_id, membresia_id, fecha_inicio, fecha_fin)
            VALUES (?, ?, ?, ?)
          `;

          params = [
            usuario_id,
            membresia_id,
            fecha_inicio,
            fecha_fin
          ];

        } else {

          // 🔹 MODO AUTOMÁTICO (Día, Semana, Mes)
          sqlIns = `
            INSERT INTO inscripciones
            (usuario_id, membresia_id, fecha_inicio, fecha_fin)
            VALUES (
              ?, 
              ?, 
              CURDATE(),
              CASE
                WHEN ? = 1 THEN DATE_ADD(CURDATE(), INTERVAL 1 DAY)
                WHEN ? = 2 THEN DATE_ADD(CURDATE(), INTERVAL 7 DAY)
                WHEN ? = 3 THEN DATE_ADD(CURDATE(), INTERVAL 1 MONTH)
                ELSE DATE_ADD(CURDATE(), INTERVAL 1 MONTH)
              END
            )
          `;

          params = [
            usuario_id,
            membresia_id,
            membresia_id,
            membresia_id,
            membresia_id
          ];
        }

        db.query(sqlIns, params, (err2) => {
          if (err2) return res.status(500).json(err2);

          res.json({
            message: "Usuario e inscripción creada correctamente",
            usuario_id,
            membresia_id,
            modo: (fecha_inicio && fecha_fin) ? "manual" : "automatico"
          });
        });

      }
    );
  }
);



/* ==========================
   INSCRIBIR USUARIO MANUAL
========================== */
// PROTEGIDO 
app.post(
  "/inscripciones",
  verifyToken,
  requireRole(['admin', 'recepcionista']),
  (req, res) => {
  const { usuario_id, membresia_id, fecha_inicio, fecha_fin } = req.body;

  const sql = `
    INSERT INTO inscripciones (usuario_id, membresia_id, fecha_inicio, fecha_fin)
    VALUES (?, ?, ?, ?)
  `;

  db.query(sql, [usuario_id, membresia_id, fecha_inicio, fecha_fin], err => {
    if (err) return res.status(500).json(err);
    res.json({ message: "Inscripción creada" });
  });
});

/* ===========================
      RENOVAR MEMBRESÍA
=========================== */
/* ===========================
      RENOVAR MEMBRESÍA
=========================== */
app.post(
  "/inscripciones/renovar",
  verifyToken,
  requireRole(["admin", "recepcionista"]),
  (req, res) => {

    const {
      usuario_id,
      membresia_id,
      fecha_inicio_manual,
      fecha_fin_manual
    } = req.body;

    if (!usuario_id || !membresia_id) {
      return res.status(400).json({
        message: "usuario_id y membresia_id son obligatorios"
      });
    }

    const idMembresia = Number(membresia_id);

    /* =========================
       🔵 CASO MANUAL
    ========================= */
    if (idMembresia === 4) {

      if (!fecha_inicio_manual || !fecha_fin_manual) {
        return res.status(400).json({
          message: "Debes seleccionar ambas fechas"
        });
      }

      const fechaInicio = new Date(fecha_inicio_manual);
      const fechaFin = new Date(fecha_fin_manual);

      if (fechaFin <= fechaInicio) {
        return res.status(400).json({
          message: "La fecha fin debe ser mayor a la fecha inicio"
        });
      }

      const fechaInicioSQL = fechaInicio.toISOString().slice(0, 10);
      const fechaFinSQL = fechaFin.toISOString().slice(0, 10);

      const sqlManual = `
        INSERT INTO inscripciones 
        (usuario_id, membresia_id, fecha_inicio, fecha_fin)
        VALUES (?, ?, ?, ?)
      `;

      db.query(
        sqlManual,
        [usuario_id, idMembresia, fechaInicioSQL, fechaFinSQL],
        (err, result) => {

          if (err) {
            console.error("ERROR INSERT MANUAL:", err);
            return res.status(500).json({
              message: "Error en inserción manual",
              error: err.message
            });
          }

          return res.status(200).json({
            message: "Membresía personalizada creada correctamente"
          });
        }
      );

      return; // 🔴 IMPORTANTE
    }

    /* =========================
       🔵 CASO AUTOMÁTICO
    ========================= */

    const sqlUltima = `
      SELECT fecha_fin
      FROM inscripciones
      WHERE usuario_id = ?
      ORDER BY fecha_fin DESC
      LIMIT 1
    `;

    db.query(sqlUltima, [usuario_id], (err, result) => {

      if (err) {
        console.error("ERROR CONSULTA ULTIMA:", err);
        return res.status(500).json({
          message: "Error consultando última inscripción",
          error: err.message
        });
      }

      const hoy = new Date();
      hoy.setHours(0, 0, 0, 0);

      let fechaBase = hoy;

      if (result.length > 0) {
        const ultimaFecha = new Date(result[0].fecha_fin);
        ultimaFecha.setHours(0, 0, 0, 0);
        fechaBase = ultimaFecha >= hoy ? ultimaFecha : hoy;
      }

      let nuevaFechaFin = new Date(fechaBase);

      if (idMembresia === 1)
        nuevaFechaFin.setDate(nuevaFechaFin.getDate() + 1);

      if (idMembresia === 2)
        nuevaFechaFin.setDate(nuevaFechaFin.getDate() + 7);

      if (idMembresia === 3)
        nuevaFechaFin.setMonth(nuevaFechaFin.getMonth() + 1);

      const fechaInicioSQL = fechaBase.toISOString().slice(0, 10);
      const fechaFinSQL = nuevaFechaFin.toISOString().slice(0, 10);

      const sqlInsert = `
        INSERT INTO inscripciones
        (usuario_id, membresia_id, fecha_inicio, fecha_fin)
        VALUES (?, ?, ?, ?)
      `;

      db.query(
        sqlInsert,
        [usuario_id, idMembresia, fechaInicioSQL, fechaFinSQL],
        (err2, result2) => {

          if (err2) {
            console.error("ERROR INSERT AUTO:", err2);
            return res.status(500).json({
              message: "Error en inserción automática",
              error: err2.message
            });
          }

          return res.status(200).json({
            message: "Membresía renovada correctamente"
          });
        }
      );
    });
  }
);      
// PROTEGIDO
/* ==========================
   REGISTRAR ASISTENCIA
========================== */
app.post(
  "/asistencia/:usuario_id",
  verifyToken,
  requireRole(['admin', 'recepcionista']),
  (req, res) => {
  const { usuario_id } = req.params;

  const sqlInscripcion = `
    SELECT fecha_fin 
    FROM inscripciones
    WHERE usuario_id = ?
    ORDER BY fecha_fin DESC
    LIMIT 1
  `;

  db.query(sqlInscripcion, [usuario_id], (err, results) => {
    if (err) return res.status(500).json(err);

    if (results.length === 0) {
      return res.status(400).json({
        message: "El usuario no tiene membresía registrada ❌"
      });
    }

    const fechaFin = new Date(results[0].fecha_fin);
    const hoy = new Date();

    hoy.setHours(0, 0, 0, 0);
    fechaFin.setHours(0, 0, 0, 0);

    if (hoy > fechaFin) {
      return res.status(400).json({
        message: "Membresía vencida ❌"
      });
    }

    const sqlAsistencia = `
      INSERT INTO asistencia (usuario_id, fecha_asistencia)
      VALUES (?, NOW())
    `;

    db.query(sqlAsistencia, [usuario_id], (err2) => {
      if (err2) return res.status(500).json(err2);

      res.json({
        message: "Asistencia registrada correctamente ✔️"
      });
    });
  });
});


/* ==========================
   CONSULTAR ESTADO DE MEMBRESÍA
========================== */
//PROTEGIDO
app.get(
  "/inscripcion/:usuario_id",
  verifyToken,
  requireRole(["admin", "recepcionista"]),
  (req, res) => {
  const { usuario_id } = req.params;

  const sql = `
    SELECT *
    FROM inscripciones
    WHERE usuario_id = ?
    ORDER BY fecha_fin DESC
    LIMIT 1
  `;

  db.query(sql, [usuario_id], (err, result) => {
    if (err) return res.status(500).json(err);
    if (result.length === 0)
      return res.status(404).json({ message: "Sin membresía" });

    res.json(result[0]);
  });
});


/* ==========================
   USUARIOS FILTRADOS
========================== */
//PROTEGIDO
app.get(
  "/usuarios/filtrar",
  verifyToken,
  requireRole(["admin", "recepcionista"]),
  (req, res) => {
  const { id, nombre, fecha_inicio, fecha_fin } = req.query;

  let sql = `
    SELECT DISTINCT u.*
    FROM usuarios u
    LEFT JOIN inscripciones i ON u.id = i.usuario_id
    WHERE 1=1
  `;

  const params = [];

  if (id) {
    sql += " AND u.id = ?";
    params.push(id);
  }

  if (nombre) {
    sql += " AND (u.nombre LIKE ? OR u.apellido LIKE ?)";
    params.push(`%${nombre}%`, `%${nombre}%`);
  }

  if (fecha_inicio) {
    sql += " AND i.fecha_inicio >= ?";
    params.push(fecha_inicio);
  }

  if (fecha_fin) {
    sql += " AND i.fecha_fin <= ?";
    params.push(fecha_fin);
  }

  db.query(sql, params, (err, results) => {
    if (err) return res.status(500).json(err);
    res.json(results);
  });
});

/* ==========================
   USUARIOS + ESTADO MEMBRESÍA
========================== */
//PROTEGIDO
app.get(
  "/usuarios-con-membresia",
  verifyToken,
  requireRole(["admin", "recepcionista"]),
  (req, res) => {
  const sql = `
    SELECT 
      u.id,
      u.nombre,
      u.apellido,
      u.telefono,
      u.email,
      i.fecha_fin,
      CASE 
        WHEN i.fecha_fin IS NULL THEN 'INACTIVO'
        WHEN i.fecha_fin >= CURDATE() THEN 'ACTIVO'
        ELSE 'INACTIVO'
      END AS estado
    FROM usuarios u
    LEFT JOIN (
      SELECT usuario_id, MAX(fecha_fin) AS fecha_fin
      FROM inscripciones
      GROUP BY usuario_id
    ) i ON u.id = i.usuario_id
  `;

  db.query(sql, (err, results) => {
    if (err) return res.status(500).json(err);
    res.json(results);
  });
});


/* ==========================
   VER USUARIOS
========================== */

// todos
app.get(
  "/usuarios",
  verifyToken,
  requireRole(["admin", "recepcionista"]),
  (req, res) => {
  const sql = "SELECT * FROM usuarios";

  db.query(sql, (err, results) => {
    if (err) {
      return res.status(500).json({ error: "Error en el servidor" });
    }
    res.json(results);
  });
});

// por id
app.get(
  "/usuarios/:id",
  verifyToken,
  requireRole(["admin", "recepcionista"]),
  (req, res) => {

    const { id } = req.params;

    const sql = `
      SELECT 
        u.id,
        u.nombre,
        u.apellido,
        u.telefono,
        u.email,
        u.foto,
        DATE_FORMAT(u.fecha_registro, '%Y-%m-%d') AS fecha_registro,
        DATE_FORMAT(u.fecha_nacimiento, '%Y-%m-%d') AS fecha_nacimiento,
        DATE_FORMAT(i.fecha_fin, '%Y-%m-%d') AS fecha_fin
      FROM usuarios u
      LEFT JOIN (
        SELECT usuario_id, MAX(fecha_fin) AS fecha_fin
        FROM inscripciones
        GROUP BY usuario_id
      ) i ON u.id = i.usuario_id
      WHERE u.id = ?
    `;
    db.query(sql, [id], (err, results) => {
      if (err) return res.status(500).json(err);
      if (results.length === 0) {
        return res.status(404).json({ message: "Usuario no encontrado" });
      }
      res.json(results[0]);
    });
  }
);

/* ==========================
   PRUEBA DE FUNCION PARA ELIMINAR USUARIO
========================== */
app.delete(
  "/usuarios/:id",
  verifyToken,
  requireRole(["admin"]),
  (req, res) => {
  const { id } = req.params;

  // Primero borramos asistencias
  const sqlAsist = "DELETE FROM asistencia WHERE usuario_id = ?";
  const sqlIns = "DELETE FROM inscripciones WHERE usuario_id = ?";
  const sqlUser = "DELETE FROM usuarios WHERE id = ?";

  db.query(sqlAsist, [id], (err) => {
    if (err) return res.status(500).json(err);

    db.query(sqlIns, [id], (err2) => {
      if (err2) return res.status(500).json(err2);

      db.query(sqlUser, [id], (err3) => {
        if (err3) return res.status(500).json(err3);

        res.json({ message: "Usuario eliminado correctamente" });
      });
    });
  });
});


/* ==========================
   TEST SERVER
========================== */
app.get("/", (req, res) => {
  res.json({ ok: true, message: "API funcionando" });
});


/* ==========================
   INICIAR SERVIDOR
========================== */
const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
});
