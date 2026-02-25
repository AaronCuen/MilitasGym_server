require("dotenv").config();
const jwt = require("jsonwebtoken");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const cloudinary = require("cloudinary").v2;
const db = require("./db");
const verifyToken = require("./middlewares/auth");
const requireAdmin = require('./middlewares/requireAdmin');
const requireRole = require('./middlewares/requireRole');

const app = express();

app.use(cors());
app.use(express.json());

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME || "dqrdrnznk",
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME || "dqrdrnznk";
const dbPromise = db.promise();
let cleanupInProgress = false;

const extractPublicIdFromUrl = (url) => {
  if (!url || typeof url !== "string") return null;
  if (!url.includes("res.cloudinary.com")) return null;
  const cleanUrl = url.split("?")[0].split("#")[0];

  // Matches everything after /upload/ and strips version + extension.
  const match = cleanUrl.match(/\/upload\/(?:v\d+\/)?(.+?)(?:\.[a-zA-Z0-9]+)?$/);
  if (!match || !match[1]) return null;
  return decodeURIComponent(match[1]);
};

const deleteCloudinaryByUrl = async (url) => {
  const publicId = extractPublicIdFromUrl(url);
  if (!publicId) return;

  if (!process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
    console.warn("Cloudinary credentials are missing in .env. Skipping image delete.");
    return;
  }

  try {
    const result = await cloudinary.uploader.destroy(publicId, { resource_type: "image" });
    if (result?.result !== "ok" && result?.result !== "not found") {
      console.warn("Cloudinary destroy unexpected result:", result);
    }
  } catch (error) {
    console.error("Cloudinary delete error:", error.message);
  }
};

const cleanupInactiveUsers = async () => {
  const [rows] = await dbPromise.query(
    `
      SELECT
        u.id,
        u.foto,
        MAX(i.fecha_fin) AS ultima_fecha_fin
      FROM usuarios u
      LEFT JOIN inscripciones i ON i.usuario_id = u.id
      GROUP BY u.id, u.foto, u.fecha_registro
      HAVING
        (
          MAX(i.fecha_fin) IS NOT NULL
          AND MAX(i.fecha_fin) < DATE_SUB(CURDATE(), INTERVAL 2 MONTH)
        )
        OR
        (
          MAX(i.fecha_fin) IS NULL
          AND u.fecha_registro < DATE_SUB(CURDATE(), INTERVAL 2 MONTH)
        )
    `
  );

  if (!rows.length) return 0;

  for (const user of rows) {
    if (user.foto) {
      await deleteCloudinaryByUrl(user.foto);
    }

    // asistencia and inscripciones are deleted by FK cascade.
    await dbPromise.query("DELETE FROM usuarios WHERE id = ?", [user.id]);
  }

  return rows.length;
};

const runInactiveCleanup = async () => {
  if (cleanupInProgress) return;
  cleanupInProgress = true;
  try {
    const removed = await cleanupInactiveUsers();
    if (removed > 0) {
      console.log(`Cleanup: ${removed} usuarios inactivos eliminados`);
    }
  } catch (error) {
    console.error("Cleanup inactive users error:", error.message);
  } finally {
    cleanupInProgress = false;
  }
};

/* ==========================
   EDITAR USUARIO (PROTEGIDO)
========================== */
app.put(
  "/usuarios/:id",
  verifyToken,
  requireRole(["admin", "recepcionista"]),
  (req, res) => {
    const { id } = req.params;

    const {
      nombre,
      apellido,
      telefono,
      email,
      fecha_nacimiento,
      genero,
      foto,
    } = req.body;

    if (!nombre || !apellido || !telefono) {
      return res.status(400).json({
        message: "Nombre, apellido y telefono son obligatorios",
      });
    }

    const sqlOldPhoto = "SELECT foto FROM usuarios WHERE id = ?";
    db.query(sqlOldPhoto, [id], (oldErr, oldResults) => {
      if (oldErr) return res.status(500).json(oldErr);
      if (!oldResults.length) {
        return res.status(404).json({ message: "Usuario no encontrado" });
      }

      const oldPhoto = oldResults[0].foto || null;
      const nuevaFoto = typeof foto === "undefined" ? oldPhoto : (foto || null);

      const sql = `
        UPDATE usuarios
        SET
          nombre = ?,
          apellido = ?,
          telefono = ?,
          email = ?,
          fecha_nacimiento = ?,
          genero = ?,
          foto = ?
        WHERE id = ?
      `;

      db.query(
        sql,
        [
          nombre,
          apellido,
          telefono,
          email || null,
          fecha_nacimiento || null,
          genero || null,
          nuevaFoto,
          id,
        ],
        async (err) => {
          if (err) return res.status(500).json(err);

          const oldPublicId = extractPublicIdFromUrl(oldPhoto);
          const newPublicId = extractPublicIdFromUrl(nuevaFoto);

          // Only delete previous image when it is actually a different Cloudinary asset.
          if (
            oldPhoto &&
            oldPublicId &&
            (!newPublicId || oldPublicId !== newPublicId)
          ) {
            await deleteCloudinaryByUrl(oldPhoto);
          }

          res.json({
            message: "Usuario actualizado correctamente",
          });
        }
      );
    });
  }
);

/* ==========================
   FILTRO USUARIOS + MEMBRESÃA
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

    // ðŸ”Ž Filtro por ID
    if (id && id.trim() !== "") {
      sql += " AND u.id = ?";
      params.push(id);
    }

    // ðŸ”Ž Filtro por nombre
    if (nombre && nombre.trim() !== "") {
      sql += " AND (u.nombre LIKE ? OR u.apellido LIKE ?)";
      params.push(`%${nombre}%`, `%${nombre}%`);
    }

    // ðŸ“… DÃ­a exacto de REGISTRO
    if (fecha_inicio && fecha_inicio.trim() !== "") {
      sql += " AND DATE(u.fecha_registro) = ?";
      params.push(fecha_inicio);
    }

    // ðŸ“… DÃ­a exacto de VENCIMIENTO
    if (fecha_fin && fecha_fin.trim() !== "") {
      sql += " AND DATE(i.fecha_fin) = ?";
      params.push(fecha_fin);
    }

    // ðŸŸ¢ðŸ”´ Filtro por estado
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
      return res.status(401).json({ message: "ContraseÃ±a incorrecta" });

    // ðŸ” AQUÃ se crea el token
    const token = jwt.sign(
      {
        id: recep.id,
        nombre: recep.nombre,
        rol: recep.rol
      },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    // Se envÃ­a el token + datos bÃ¡sicos
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
   REGISTRAR USUARIO + INSCRIPCIÃ“N
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
  fecha_nacimiento,
  fecha_inicio,
  fecha_fin
    } = req.body;

    // ðŸ”¹ ValidaciÃ³n bÃ¡sica
    if (!nombre || !apellido || !telefono || !membresia_id) {
      return res.status(400).json({ message: "Faltan datos obligatorios" });
    }

    // ðŸ”¹ ValidaciÃ³n de fechas si se envÃ­an manualmente
    if (fecha_inicio && fecha_fin) {
      if (new Date(fecha_fin) <= new Date(fecha_inicio)) {
        return res.status(400).json({
          message: "La fecha de vencimiento debe ser mayor a la fecha de inicio"
        });
      }
    }

    if (fecha_nacimiento && isNaN(new Date(fecha_nacimiento))) {
  return res.status(400).json({
    message: "Formato de fecha de nacimiento invÃ¡lido"
  });
}

    const sqlUser = `
      INSERT INTO usuarios (nombre, apellido, telefono, email, fecha_nacimiento, foto)
      VALUES (?, ?, ?, ?, ?, ?)
    `;

    db.query(
      sqlUser,
      [
        nombre,
        apellido,
        telefono,
        email || null,
        fecha_nacimiento || null,
        foto || null
      ],
      (err, result) => {
        if (err) return res.status(500).json(err);

        const usuario_id = result.insertId;

        let sqlIns;
        let params;

        // ðŸ”¹ MODO MANUAL
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

          // ðŸ”¹ MODO AUTOMÃTICO (DÃ­a, Semana, Mes)
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
            message: "Usuario e inscripciÃ³n creada correctamente",
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
    res.json({ message: "InscripciÃ³n creada" });
  });
});

/* ===========================
      RENOVAR MEMBRESÃA
=========================== */
/* ===========================
      RENOVAR MEMBRESÃA
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
       ðŸ”µ CASO MANUAL
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
              message: "Error en inserciÃ³n manual",
              error: err.message
            });
          }

          return res.status(200).json({
            message: "MembresÃ­a personalizada creada correctamente"
          });
        }
      );

      return; // ðŸ”´ IMPORTANTE
    }

    /* =========================
       ðŸ”µ CASO AUTOMÃTICO
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
          message: "Error consultando Ãºltima inscripciÃ³n",
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
              message: "Error en inserciÃ³n automÃ¡tica",
              error: err2.message
            });
          }

          return res.status(200).json({
            message: "MembresÃ­a renovada correctamente"
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
        message: "El usuario no tiene membresia registrada"
      });
    }

    const fechaFin = new Date(results[0].fecha_fin);
    const hoy = new Date();

    hoy.setHours(0, 0, 0, 0);
    fechaFin.setHours(0, 0, 0, 0);

    if (hoy > fechaFin) {
      return res.status(400).json({
        message: "Membresia vencida"
      });
    }

    const sqlAsistencia = `
      INSERT INTO asistencia (usuario_id, fecha_asistencia)
      VALUES (?, NOW())
    `;

    db.query(sqlAsistencia, [usuario_id], (err2) => {
      if (err2) return res.status(500).json(err2);

      res.json({
        message: "Asistencia registrada correctamente"
      });
    });
  });
});


/* ==========================
   CONSULTAR ESTADO DE MEMBRESÃA
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
      return res.status(404).json({ message: "Sin membresÃ­a" });

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
   USUARIOS + ESTADO MEMBRESÃA
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
  async (req, res) => {
    const { id } = req.params;

    try {
      const [users] = await dbPromise.query(
        "SELECT foto FROM usuarios WHERE id = ?",
        [id]
      );

      if (!users.length) {
        return res.status(404).json({ message: "Usuario no encontrado" });
      }

      const foto = users[0].foto;
      if (foto) {
        await deleteCloudinaryByUrl(foto);
      }

      // asistencia + inscripciones se borran por ON DELETE CASCADE.
      await dbPromise.query("DELETE FROM usuarios WHERE id = ?", [id]);

      return res.json({ message: "Usuario eliminado correctamente" });
    } catch (error) {
      return res
        .status(500)
        .json({ message: "Error al eliminar usuario", error: error.message });
    }
  }
);


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
  runInactiveCleanup();
  // Repeat cleanup every 12 hours.
  setInterval(runInactiveCleanup, 12 * 60 * 60 * 1000);
});


