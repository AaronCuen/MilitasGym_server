require("dotenv").config();
process.env.TZ = process.env.TZ || "America/Hermosillo";
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

const isISODateString = (value) =>
  typeof value === "string" && /^\d{4}-\d{2}-\d{2}$/.test(value);

const toISODateLocal = (date) => {
  const yyyy = date.getFullYear();
  const mm = String(date.getMonth() + 1).padStart(2, "0");
  const dd = String(date.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
};

const parseISODateLocal = (isoDate) => {
  if (!isISODateString(isoDate)) return null;
  const [yyyy, mm, dd] = isoDate.split("-").map(Number);
  const parsed = new Date(yyyy, mm - 1, dd);

  if (
    parsed.getFullYear() !== yyyy ||
    parsed.getMonth() !== mm - 1 ||
    parsed.getDate() !== dd
  ) {
    return null;
  }

  return parsed;
};

const resolveDashboardRange = (inicioRaw, finRaw) => {
  const today = new Date();
  const defaultInicio = toISODateLocal(new Date(today.getFullYear(), today.getMonth(), 1));
  const defaultFin = toISODateLocal(new Date(today.getFullYear(), today.getMonth(), today.getDate()));

  const inicio = isISODateString(inicioRaw) ? inicioRaw : defaultInicio;
  const fin = isISODateString(finRaw) ? finRaw : defaultFin;

  const inicioDate = parseISODateLocal(inicio);
  const finDate = parseISODateLocal(fin);

  if (!inicioDate || !finDate) {
    return { ok: false, message: "inicio y fin deben tener formato YYYY-MM-DD" };
  }

  if (inicioDate > finDate) {
    return { ok: false, message: "La fecha inicio no puede ser mayor que fecha fin" };
  }

  return { ok: true, inicio, fin };
};

const isAdmin = (req) => req.user?.rol === "admin";

const parsePositiveInt = (value) => {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) return null;
  return parsed;
};

const getTokenSucursalId = (req) => parsePositiveInt(req.user?.sucursal_id);

const resolveSucursalIdForRead = (req, { allowQuery = false } = {}) => {
  if (isAdmin(req)) {
    if (allowQuery) {
      const requested = parsePositiveInt(req.query?.sucursal_id);
      return requested || null;
    }
    return null; // Admin ve todas por defecto
  }
  return getTokenSucursalId(req);
};

const resolveSucursalIdForWrite = (req) => {
  if (isAdmin(req)) {
    const requested = parsePositiveInt(req.body?.sucursal_id);
    return requested || getTokenSucursalId(req);
  }
  return getTokenSucursalId(req);
};

const requireSucursalForNonAdmin = (req, res) => {
  if (!isAdmin(req) && !getTokenSucursalId(req)) {
    res.status(403).json({ message: "Sucursal no asignada" });
    return false;
  }
  return true;
};

const buildSucursalFilter = (sucursalId, alias = null) => {
  if (!sucursalId) return { clause: "", params: [] };
  const column = alias ? `${alias}.sucursal_id` : "sucursal_id";
  return { clause: ` AND ${column} = ?`, params: [sucursalId] };
};

/* ==========================
   SUCURSALES
========================== */
app.get(
  "/sucursales",
  verifyToken,
  requireRole(["admin", "recepcionista"]),
  async (req, res) => {
    try {
      const sucursalId = getTokenSucursalId(req);
      if (isAdmin(req)) {
        const [rows] = await dbPromise.query(
          `
            SELECT id, nombre, direccion, telefono, activo
            FROM sucursales
            ORDER BY nombre ASC, id ASC
          `
        );
        return res.json(rows);
      }

      if (!sucursalId) {
        return res.status(403).json({ message: "Sucursal no asignada" });
      }

      const [rows] = await dbPromise.query(
        `
          SELECT id, nombre, direccion, telefono, activo
          FROM sucursales
          WHERE id = ?
          LIMIT 1
        `,
        [sucursalId]
      );
      return res.json(rows);
    } catch (error) {
      return res.status(500).json({ message: "Error al cargar sucursales" });
    }
  }
);

app.post(
  "/sucursales",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    const { nombre, direccion, telefono, activo } = req.body || {};
    const nombreLimpio = (nombre || "").trim();
    if (!nombreLimpio) {
      return res.status(400).json({ message: "El nombre es obligatorio" });
    }

    try {
      const [result] = await dbPromise.query(
        `
          INSERT INTO sucursales (nombre, direccion, telefono, activo)
          VALUES (?, ?, ?, ?)
        `,
        [
          nombreLimpio,
          direccion ? String(direccion).trim() : null,
          telefono ? String(telefono).trim() : null,
          typeof activo === "number" ? activo : 1,
        ]
      );

      return res.status(201).json({
        id: result.insertId,
        nombre: nombreLimpio,
        direccion: direccion ? String(direccion).trim() : null,
        telefono: telefono ? String(telefono).trim() : null,
        activo: typeof activo === "number" ? activo : 1,
      });
    } catch (error) {
      if (error?.code === "ER_DUP_ENTRY") {
        return res.status(409).json({ message: "La sucursal ya existe" });
      }
      return res.status(500).json({ message: "Error al crear sucursal" });
    }
  }
);

app.put(
  "/sucursales/:id",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    const sucursalId = parsePositiveInt(req.params.id);
    if (!sucursalId) {
      return res.status(400).json({ message: "Sucursal invalida" });
    }

    const { nombre, direccion, telefono, activo } = req.body || {};
    const updates = [];
    const params = [];

    if (typeof nombre === "string" && nombre.trim()) {
      updates.push("nombre = ?");
      params.push(nombre.trim());
    }
    if (typeof direccion !== "undefined") {
      updates.push("direccion = ?");
      params.push(direccion ? String(direccion).trim() : null);
    }
    if (typeof telefono !== "undefined") {
      updates.push("telefono = ?");
      params.push(telefono ? String(telefono).trim() : null);
    }
    if (typeof activo !== "undefined") {
      updates.push("activo = ?");
      params.push(activo ? 1 : 0);
    }

    if (!updates.length) {
      return res.status(400).json({ message: "No hay cambios para guardar" });
    }

    try {
      params.push(sucursalId);
      await dbPromise.query(
        `
          UPDATE sucursales
          SET ${updates.join(", ")}
          WHERE id = ?
        `,
        params
      );
      return res.json({ message: "Sucursal actualizada" });
    } catch (error) {
      if (error?.code === "ER_DUP_ENTRY") {
        return res.status(409).json({ message: "La sucursal ya existe" });
      }
      return res.status(500).json({ message: "Error al actualizar sucursal" });
    }
  }
);

/* ==========================
   EDITAR USUARIO (PROTEGIDO)
========================== */
app.put(
  "/usuarios/:id",
  verifyToken,
  requireRole(["admin", "recepcionista"]),
  (req, res) => {
    const { id } = req.params;
    if (!requireSucursalForNonAdmin(req, res)) return;
    const sucursalId = resolveSucursalIdForRead(req);

    const {
      nombre,
      apellido,
      telefono,
      email,
      fecha_nacimiento,
      genero,
      foto,
    } = req.body;

    const nombreLimpio = (nombre || "").trim();
    const apellidoLimpio = (apellido || "").trim();
    const telefonoLimpio = (telefono || "").replace(/\D/g, "").slice(0, 10);
    const emailLimpio = (email || "").trim();

    if (!nombreLimpio || !apellidoLimpio) {
      return res.status(400).json({
        message: "Nombre y apellido son obligatorios",
      });
    }

    if (telefonoLimpio && !/^\d{10}$/.test(telefonoLimpio)) {
      return res.status(400).json({
        message: "Si agregas telefono, debe tener exactamente 10 digitos numericos",
      });
    }

    if (emailLimpio && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailLimpio)) {
      return res.status(400).json({
        message: "El correo no tiene un formato valido",
      });
    }

    let sqlOldPhoto = "SELECT foto FROM usuarios WHERE id = ?";
    const oldParams = [id];
    if (sucursalId) {
      sqlOldPhoto += " AND sucursal_id = ?";
      oldParams.push(sucursalId);
    }
    db.query(sqlOldPhoto, oldParams, (oldErr, oldResults) => {
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
        WHERE id = ?${sucursalId ? " AND sucursal_id = ?" : ""}
      `;

      db.query(
        sql,
        [
          nombreLimpio,
          apellidoLimpio,
          telefonoLimpio || "",
          emailLimpio || null,
          fecha_nacimiento || null,
          genero || null,
          nuevaFoto,
          id,
          ...(sucursalId ? [sucursalId] : []),
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
   EDITAR INSCRIPCION DESDE MODAL
========================== */
app.put(
  "/usuarios/:id/inscripcion",
  verifyToken,
  requireRole(["admin", "recepcionista"]),
  async (req, res) => {
    const { id } = req.params;
    if (!requireSucursalForNonAdmin(req, res)) return;
    const sucursalId = resolveSucursalIdForRead(req);
    const { fecha_inicio, fecha_fin, membresia_id } = req.body;

    if (!fecha_inicio || !fecha_fin) {
      return res.status(400).json({
        message: "fecha_inicio y fecha_fin son obligatorias",
      });
    }

    if (new Date(fecha_fin) < new Date(fecha_inicio)) {
      return res.status(400).json({
        message: "La fecha_fin debe ser mayor o igual que fecha_inicio",
      });
    }

    let conn;
    try {
      conn = await dbPromise.getConnection();
      await conn.beginTransaction();

      const userQuery = `SELECT id, sucursal_id FROM usuarios WHERE id = ?${sucursalId ? " AND sucursal_id = ?" : ""}`;
      const [usuarios] = await conn.query(userQuery, [id, ...(sucursalId ? [sucursalId] : [])]);
      if (!usuarios.length) {
        await conn.rollback();
        return res.status(404).json({ message: "Usuario no encontrado" });
      }
      const userSucursalId = Number(usuarios[0].sucursal_id);

      let membresiaFinal = Number(membresia_id);
      const [ultima] = await conn.query(
        `
          SELECT id, membresia_id
          FROM inscripciones
          WHERE usuario_id = ? AND sucursal_id = ?
          ORDER BY fecha_fin DESC, id DESC
          LIMIT 1
        `,
        [id, userSucursalId]
      );

      if (!Number.isFinite(membresiaFinal) || membresiaFinal <= 0) {
        membresiaFinal = ultima.length ? Number(ultima[0].membresia_id) : 4;
      }

      let inscripcionObjetivoId = null;

      if (ultima.length) {
        await conn.query(
          `
            UPDATE inscripciones
            SET membresia_id = ?, fecha_inicio = ?, fecha_fin = ?
            WHERE id = ? AND sucursal_id = ?
          `,
          [membresiaFinal, fecha_inicio, fecha_fin, ultima[0].id, userSucursalId]
        );
        inscripcionObjetivoId = Number(ultima[0].id);
      } else {
        const [insertResult] = await conn.query(
          `
            INSERT INTO inscripciones (usuario_id, membresia_id, fecha_inicio, fecha_fin, sucursal_id)
            VALUES (?, ?, ?, ?, ?)
          `,
          [id, membresiaFinal, fecha_inicio, fecha_fin, userSucursalId]
        );
        inscripcionObjetivoId = Number(insertResult.insertId);
      }

      if (inscripcionObjetivoId) {
        // Keep historical rows before the edited start date, but remove rows
        // from that point forward that would override/interfere the correction.
        await conn.query(
          `
            DELETE FROM inscripciones
            WHERE usuario_id = ?
              AND id <> ?
              AND fecha_fin >= DATE(?)
              AND sucursal_id = ?
          `,
          [id, inscripcionObjetivoId, fecha_inicio, userSucursalId]
        );
      }

      await conn.commit();
      return res.json({ message: "Inscripcion actualizada correctamente" });
    } catch (error) {
      if (conn) await conn.rollback();
      return res.status(500).json({
        message: "Error al actualizar inscripcion",
        error: error.message,
      });
    } finally {
      if (conn) conn.release();
    }
  }
);

/* ==========================
   FILTRO USUARIOS + MEMBRESIA
========================== */

// PROTEGIDO 
app.get(
  "/usuarios/filtrar-con-membresia",
  verifyToken,
  requireRole(["admin", "recepcionista"]),
  (req, res) => {

    const { id, nombre, fecha_inicio, fecha_fin, estado } = req.query;
    if (!requireSucursalForNonAdmin(req, res)) return;
    const sucursalId = resolveSucursalIdForRead(req, { allowQuery: true });

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
    const { clause: userFilter, params: userParams } = buildSucursalFilter(sucursalId, "u");
    if (userFilter) {
      sql += userFilter;
      params.push(...userParams);
    }

    // Filtro por ID
    if (id && id.trim() !== "") {
      sql += " AND u.id = ?";
      params.push(id);
    }

    // Filtro por nombre
    if (nombre && nombre.trim() !== "") {
      sql += " AND (u.nombre LIKE ? OR u.apellido LIKE ?)";
      params.push(`%${nombre}%`, `%${nombre}%`);
    }

    // Dia exacto de REGISTRO
    if (fecha_inicio && fecha_inicio.trim() !== "") {
      sql += " AND DATE(u.fecha_registro) = ?";
      params.push(fecha_inicio);
    }

    // Dia exacto de VENCIMIENTO
    if (fecha_fin && fecha_fin.trim() !== "") {
      sql += " AND DATE(i.fecha_fin) = ?";
      params.push(fecha_fin);
    }

    // Filtro por estado
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
  const sucursalId = resolveSucursalIdForWrite(req);

  if (!nombre || !usuario || !password) {
    return res.status(400).json({ message: "Faltan datos" });
  }
  if (!sucursalId) {
    return res.status(400).json({ message: "sucursal_id es obligatorio" });
  }

  try {
    const [existing] = await dbPromise.query(
      "SELECT id FROM recepcionistas WHERE usuario = ? LIMIT 1",
      [usuario]
    );
    if (existing.length) {
      return res.status(409).json({ message: "El usuario ya existe" });
    }

    const hash = await bcrypt.hash(password, 10);

    const sql = `
      INSERT INTO recepcionistas (nombre, usuario, password, rol, sucursal_id)
      VALUES (?, ?, ?, 'recepcionista', ?)
    `;

    db.query(
      sql,
      [nombre, usuario, hash, sucursalId],
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
          rol: "recepcionista",
          sucursal_id: sucursalId,
        });
      }
    );
  } catch (error) {
    res.status(500).json({ message: "Error interno" });
  }
});

app.get(
  "/recepcionistas",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    try {
      const sucursalId = resolveSucursalIdForRead(req, { allowQuery: true });
      let sql = `
        SELECT r.id, r.nombre, r.usuario, r.rol, r.sucursal_id,
               s.nombre AS sucursal_nombre
        FROM recepcionistas r
        LEFT JOIN sucursales s ON s.id = r.sucursal_id
        WHERE 1=1
      `;
      const params = [];
      if (sucursalId) {
        sql += " AND r.sucursal_id = ?";
        params.push(sucursalId);
      }
      sql += " ORDER BY r.id DESC";

      const [rows] = await dbPromise.query(sql, params);
      return res.json(rows);
    } catch (error) {
      return res.status(500).json({ message: "Error al obtener recepcionistas" });
    }
  }
);

app.put(
  "/recepcionistas/:id",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    const recepId = parsePositiveInt(req.params.id);
    if (!recepId) {
      return res.status(400).json({ message: "ID invalido" });
    }

    const { nombre, usuario, password, rol, sucursal_id } = req.body || {};
    const updates = [];
    const params = [];

    if (typeof nombre === "string" && nombre.trim()) {
      updates.push("nombre = ?");
      params.push(nombre.trim());
    }

    if (typeof usuario === "string" && usuario.trim()) {
      const usuarioLimpio = usuario.trim();
      const [existing] = await dbPromise.query(
        "SELECT id FROM recepcionistas WHERE usuario = ? AND id <> ? LIMIT 1",
        [usuarioLimpio, recepId]
      );
      if (existing.length) {
        return res.status(409).json({ message: "El usuario ya existe" });
      }
      updates.push("usuario = ?");
      params.push(usuarioLimpio);
    }

    if (typeof password === "string" && password) {
      const hash = await bcrypt.hash(password, 10);
      updates.push("password = ?");
      params.push(hash);
    }

    if (typeof rol === "string" && ["admin", "recepcionista"].includes(rol)) {
      updates.push("rol = ?");
      params.push(rol);
    }

    if (typeof sucursal_id !== "undefined") {
      const sucursalId = parsePositiveInt(sucursal_id);
      if (!sucursalId) {
        return res.status(400).json({ message: "sucursal_id invalido" });
      }
      updates.push("sucursal_id = ?");
      params.push(sucursalId);
    }

    if (!updates.length) {
      return res.status(400).json({ message: "No hay cambios para guardar" });
    }

    try {
      params.push(recepId);
      await dbPromise.query(
        `
          UPDATE recepcionistas
          SET ${updates.join(", ")}
          WHERE id = ?
        `,
        params
      );
      return res.json({ message: "Recepcionista actualizada" });
    } catch (error) {
      return res.status(500).json({ message: "Error al actualizar recepcionista" });
    }
  }
);

app.delete(
  "/recepcionistas/:id",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    const recepId = parsePositiveInt(req.params.id);
    if (!recepId) {
      return res.status(400).json({ message: "ID invalido" });
    }

    try {
      const [existing] = await dbPromise.query(
        "SELECT id FROM recepcionistas WHERE id = ? LIMIT 1",
        [recepId]
      );
      if (!existing.length) {
        return res.status(404).json({ message: "Recepcionista no encontrada" });
      }

      await dbPromise.query("DELETE FROM recepcionistas WHERE id = ?", [recepId]);
      return res.json({ message: "Recepcionista eliminada" });
    } catch (error) {
      return res.status(500).json({ message: "Error al eliminar recepcionista" });
    }
  }
);


/* ==========================
   LOGIN RECEPCIONISTA
========================== */

// NO REQUIERE PROTECCION
app.post("/login", (req, res) => {
  const { usuario, password } = req.body;
  const usuarioLimpio = (usuario || "").trim();

  if (!usuarioLimpio || typeof password !== "string" || !password) {
    return res
      .status(400)
      .json({ message: "Usuario y contrasena son obligatorios" });
  }

  const sql = `
    SELECT r.*, s.nombre AS sucursal_nombre
    FROM recepcionistas r
    LEFT JOIN sucursales s ON s.id = r.sucursal_id
    WHERE r.usuario = ?
  `;

  db.query(sql, [usuarioLimpio], async (err, results) => {
    if (err) return res.status(500).json(err);

    if (results.length === 0)
      return res.status(401).json({ message: "Usuario no encontrado" });
    if (results.length > 1) {
      return res.status(409).json({
        message: "Usuario duplicado. Contacta al administrador.",
      });
    }

    try {
      const recep = results[0];
      const ok = await bcrypt.compare(password, recep.password || "");

      if (!ok)
        return res.status(401).json({ message: "Contrasena incorrecta" });

      // Aqui se crea el token
      const token = jwt.sign(
        {
          id: recep.id,
          nombre: recep.nombre,
          rol: recep.rol,
          sucursal_id: recep.sucursal_id,
          sucursal_nombre: recep.sucursal_nombre || null,
        },
        process.env.JWT_SECRET,
        { expiresIn: "8h" }
      );

      // Se envia el token + datos basicos
      res.json({
        token,
        user: {
          id: recep.id,
          nombre: recep.nombre,
          rol: recep.rol,
          sucursal_id: recep.sucursal_id,
          sucursal_nombre: recep.sucursal_nombre || null,
        }
      });
    } catch (error) {
      return res.status(500).json({ message: "Error al validar credenciales" });
    }
  });
});


/* ==========================
   REGISTRAR USUARIO + INSCRIPCION
========================== */

// PROTEGIDO 
app.post(
  "/registrar_usuario",
  verifyToken,
  requireRole(['admin', 'recepcionista']),
  async (req, res) => {

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
    const sucursalId = resolveSucursalIdForWrite(req);

    const nombreLimpio = (nombre || "").trim();
    const apellidoLimpio = (apellido || "").trim();
    const telefonoLimpio = (telefono || "").replace(/\D/g, "").slice(0, 10);
    const emailLimpio = (email || "").trim();
    const membresiaId = Number(membresia_id);

    const esFechaISO = (valor) =>
      typeof valor === "string" && /^\d{4}-\d{2}-\d{2}$/.test(valor);
    const fechaLocalISO = () => {
      const hoy = new Date();
      const yyyy = hoy.getFullYear();
      const mm = String(hoy.getMonth() + 1).padStart(2, "0");
      const dd = String(hoy.getDate()).padStart(2, "0");
      return `${yyyy}-${mm}-${dd}`;
    };

    let fechaInicioManual = fecha_inicio || "";
    const fechaFinManual = fecha_fin || "";
    const esManual = membresiaId === 4;
    const fechaInicioBase = esFechaISO(fecha_inicio) ? fecha_inicio : fechaLocalISO();

    // Validacion basica
    if (!nombreLimpio || !apellidoLimpio || !membresiaId) {
      return res.status(400).json({ message: "Faltan datos obligatorios" });
    }
    if (!sucursalId) {
      return res.status(400).json({ message: "sucursal_id es obligatorio" });
    }

    if (telefonoLimpio && !/^\d{10}$/.test(telefonoLimpio)) {
      return res.status(400).json({
        message: "Si agregas telefono, debe tener exactamente 10 digitos numericos"
      });
    }

    if (emailLimpio && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailLimpio)) {
      return res.status(400).json({
        message: "El correo no tiene un formato valido"
      });
    }

    if (esManual && !fechaInicioManual) {
      const hoy = new Date();
      const yyyy = hoy.getFullYear();
      const mm = String(hoy.getMonth() + 1).padStart(2, "0");
      const dd = String(hoy.getDate()).padStart(2, "0");
      fechaInicioManual = `${yyyy}-${mm}-${dd}`;
    }

    if (esManual && !fechaFinManual) {
      return res.status(400).json({
        message: "Debes seleccionar la fecha de vencimiento"
      });
    }

    // Validacion de fechas manuales (igual permitido)
    if (esManual && fechaInicioManual && fechaFinManual) {
      if (new Date(fechaFinManual) < new Date(fechaInicioManual)) {
        return res.status(400).json({
          message: "La fecha de vencimiento no puede ser menor a la fecha de inicio"
        });
      }
    }

    if (fecha_nacimiento && isNaN(new Date(fecha_nacimiento))) {
      return res.status(400).json({
        message: "Formato de fecha de nacimiento invalido"
      });
    }

    const sqlUser = `
      INSERT INTO usuarios (nombre, apellido, telefono, email, fecha_nacimiento, foto, fecha_registro, sucursal_id)
      VALUES (?, ?, ?, ?, ?, ?, CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '-07:00'), ?)
    `;

    let conn;
    try {
      conn = await dbPromise.getConnection();
      await conn.beginTransaction();

      const [result] = await conn.query(
        sqlUser,
        [
          nombreLimpio,
          apellidoLimpio,
          telefonoLimpio || "",
          emailLimpio || null,
          fecha_nacimiento || null,
          foto || null,
          sucursalId,
        ]
      );

      const usuario_id = result.insertId;

      let sqlIns;
      let params;

      // MODO MANUAL
      if (esManual) {

        sqlIns = `
          INSERT INTO inscripciones
          (usuario_id, membresia_id, fecha_inicio, fecha_fin, sucursal_id)
          VALUES (?, ?, ?, ?, ?)
        `;

        params = [
          usuario_id,
          membresiaId,
          fechaInicioManual,
          fechaFinManual,
          sucursalId,
        ];

      } else {

        // MODO AUTOMATICO (Dia, Semana, Mes)
        sqlIns = `
          INSERT INTO inscripciones
          (usuario_id, membresia_id, fecha_inicio, fecha_fin, sucursal_id)
          VALUES (
            ?, 
            ?, 
            DATE(?),
            CASE
              WHEN ? = 1 THEN DATE(?)
              WHEN ? = 2 THEN DATE_ADD(DATE(?), INTERVAL 7 DAY)
              WHEN ? = 3 THEN DATE_ADD(DATE(?), INTERVAL 1 MONTH)
              ELSE DATE_ADD(DATE(?), INTERVAL 1 MONTH)
            END,
            ?
          )
        `;

        params = [
          usuario_id,
          membresiaId,
          fechaInicioBase,
          membresiaId,
          fechaInicioBase,
          membresiaId,
          fechaInicioBase,
          membresiaId,
          fechaInicioBase,
          fechaInicioBase,
          sucursalId,
        ];
      }

      await conn.query(sqlIns, params);
      await conn.commit();

      res.json({
        message: "Usuario e inscripcion creada correctamente",
        usuario_id,
        membresia_id: membresiaId,
        modo: esManual ? "manual" : "automatico"
      });
    } catch (err) {
      if (conn) {
        await conn.rollback();
      }
      if (err?.code) {
        return res.status(500).json(err);
      }
      return res.status(500).json({
        message: "Error al registrar usuario",
        error: err.message
      });
    } finally {
      if (conn) {
        conn.release();
      }
    }
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
  async (req, res) => {
  const { usuario_id, membresia_id, fecha_inicio, fecha_fin } = req.body;

  const usuarioId = parsePositiveInt(usuario_id);
  const membresiaId = Number(membresia_id);

  if (!usuarioId || !membresiaId || !fecha_inicio || !fecha_fin) {
    return res.status(400).json({ message: "Faltan datos obligatorios" });
  }

  if (!requireSucursalForNonAdmin(req, res)) return;

  try {
    const [usuarios] = await dbPromise.query(
      "SELECT id, sucursal_id FROM usuarios WHERE id = ?",
      [usuarioId]
    );

    if (!usuarios.length) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const userSucursalId = Number(usuarios[0].sucursal_id);
    const tokenSucursalId = getTokenSucursalId(req);
    if (!isAdmin(req) && tokenSucursalId !== userSucursalId) {
      return res.status(403).json({ message: "Acceso denegado" });
    }

    const sql = `
      INSERT INTO inscripciones (usuario_id, membresia_id, fecha_inicio, fecha_fin, sucursal_id)
      VALUES (?, ?, ?, ?, ?)
    `;

    await dbPromise.query(sql, [
      usuarioId,
      membresiaId,
      fecha_inicio,
      fecha_fin,
      userSucursalId,
    ]);

    res.json({ message: "Inscripcion creada" });
  } catch (err) {
    return res.status(500).json(err);
  }
});

/* ===========================
      RENOVAR MEMBRESIA
=========================== */
/* ===========================
      RENOVAR MEMBRESIA
=========================== */
app.post(
  "/inscripciones/renovar",
  verifyToken,
  requireRole(["admin", "recepcionista"]),
  async (req, res) => {

    const {
      usuario_id,
      membresia_id,
      fecha_inicio_manual,
      fecha_fin_manual
    } = req.body;

    const usuarioId = parsePositiveInt(usuario_id);
    if (!usuarioId || !membresia_id) {
      return res.status(400).json({
        message: "usuario_id y membresia_id son obligatorios"
      });
    }

    const idMembresia = Number(membresia_id);
    if (!requireSucursalForNonAdmin(req, res)) return;

    let userSucursalId = null;
    try {
      const [usuarios] = await dbPromise.query(
        "SELECT id, sucursal_id FROM usuarios WHERE id = ?",
        [usuarioId]
      );
      if (!usuarios.length) {
        return res.status(404).json({ message: "Usuario no encontrado" });
      }
      userSucursalId = Number(usuarios[0].sucursal_id);
      const tokenSucursalId = getTokenSucursalId(req);
      if (!isAdmin(req) && tokenSucursalId !== userSucursalId) {
        return res.status(403).json({ message: "Acceso denegado" });
      }
    } catch (err) {
      return res.status(500).json(err);
    }

    /* =========================
       CASO MANUAL
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
        (usuario_id, membresia_id, fecha_inicio, fecha_fin, sucursal_id)
        VALUES (?, ?, ?, ?, ?)
      `;

      db.query(
        sqlManual,
        [usuarioId, idMembresia, fechaInicioSQL, fechaFinSQL, userSucursalId],
        (err, result) => {

          if (err) {
            console.error("ERROR INSERT MANUAL:", err);
            return res.status(500).json({
              message: "Error en insercion manual",
              error: err.message
            });
          }

          return res.status(200).json({
            message: "Membresia personalizada creada correctamente"
          });
        }
      );

      return; // IMPORTANTE
    }

    /* =========================
       CASO AUTOMATICO
    ========================= */

    const sqlUltima = `
      SELECT fecha_fin
      FROM inscripciones
      WHERE usuario_id = ? AND sucursal_id = ?
      ORDER BY fecha_fin DESC
      LIMIT 1
    `;

    db.query(sqlUltima, [usuarioId, userSucursalId], (err, result) => {

      if (err) {
        console.error("ERROR CONSULTA ULTIMA:", err);
        return res.status(500).json({
          message: "Error consultando ultima inscripcion",
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

      if (idMembresia === 1) {
        nuevaFechaFin = new Date(fechaBase);
      }

      if (idMembresia === 2)
        nuevaFechaFin.setDate(nuevaFechaFin.getDate() + 7);

      if (idMembresia === 3)
        nuevaFechaFin.setMonth(nuevaFechaFin.getMonth() + 1);

      const fechaInicioSQL = fechaBase.toISOString().slice(0, 10);
      const fechaFinSQL = nuevaFechaFin.toISOString().slice(0, 10);

      const sqlInsert = `
        INSERT INTO inscripciones
        (usuario_id, membresia_id, fecha_inicio, fecha_fin, sucursal_id)
        VALUES (?, ?, ?, ?, ?)
      `;

      db.query(
        sqlInsert,
        [usuarioId, idMembresia, fechaInicioSQL, fechaFinSQL, userSucursalId],
        (err2, result2) => {

          if (err2) {
            console.error("ERROR INSERT AUTO:", err2);
            return res.status(500).json({
              message: "Error en insercion automatica",
              error: err2.message
            });
          }

          return res.status(200).json({
            message: "Membresia renovada correctamente"
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
  async (req, res) => {
  const usuarioId = parsePositiveInt(req.params.usuario_id);
  if (!usuarioId) {
    return res.status(400).json({ message: "usuario_id invalido" });
  }
  if (!requireSucursalForNonAdmin(req, res)) return;

  let userSucursalId = null;
  try {
    const [usuarios] = await dbPromise.query(
      "SELECT id, sucursal_id FROM usuarios WHERE id = ?",
      [usuarioId]
    );
    if (!usuarios.length) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }
    userSucursalId = Number(usuarios[0].sucursal_id);
    const tokenSucursalId = getTokenSucursalId(req);
    if (!isAdmin(req) && tokenSucursalId !== userSucursalId) {
      return res.status(403).json({ message: "Acceso denegado" });
    }
  } catch (err) {
    return res.status(500).json(err);
  }

  const sqlInscripcion = `
    SELECT fecha_fin 
    FROM inscripciones
    WHERE usuario_id = ? AND sucursal_id = ?
    ORDER BY fecha_fin DESC
    LIMIT 1
  `;

  db.query(sqlInscripcion, [usuarioId, userSucursalId], (err, results) => {
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
      INSERT INTO asistencia (usuario_id, fecha_asistencia, sucursal_id)
      VALUES (?, CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', '-07:00'), ?)
    `;

    db.query(sqlAsistencia, [usuarioId, userSucursalId], (err2) => {
      if (err2) return res.status(500).json(err2);

      res.json({
        message: "Asistencia registrada correctamente"
      });
    });
  });
});


/* ==========================
   CONSULTAR ESTADO DE MEMBRESIA
========================== */
//PROTEGIDO
app.get(
  "/inscripcion/:usuario_id",
  verifyToken,
  requireRole(["admin", "recepcionista"]),
  async (req, res) => {
  const usuarioId = parsePositiveInt(req.params.usuario_id);
  if (!usuarioId) {
    return res.status(400).json({ message: "usuario_id invalido" });
  }
  if (!requireSucursalForNonAdmin(req, res)) return;

  let userSucursalId = null;
  try {
    const [usuarios] = await dbPromise.query(
      "SELECT id, sucursal_id FROM usuarios WHERE id = ?",
      [usuarioId]
    );
    if (!usuarios.length) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }
    userSucursalId = Number(usuarios[0].sucursal_id);
    const tokenSucursalId = getTokenSucursalId(req);
    if (!isAdmin(req) && tokenSucursalId !== userSucursalId) {
      return res.status(403).json({ message: "Acceso denegado" });
    }
  } catch (err) {
    return res.status(500).json(err);
  }

  const sql = `
    SELECT *
    FROM inscripciones
    WHERE usuario_id = ? AND sucursal_id = ?
    ORDER BY fecha_fin DESC
    LIMIT 1
  `;

  db.query(sql, [usuarioId, userSucursalId], (err, result) => {
    if (err) return res.status(500).json(err);
    if (result.length === 0)
      return res.status(404).json({ message: "Sin membresia" });

    res.json(result[0]);
  });
});

/* ==========================
   DASHBOARD RESUMEN
========================== */
app.get(
  "/dashboard/resumen",
  verifyToken,
  requireRole(["admin", "recepcionista"]),
  async (req, res) => {
    const {
      inicio: inicioRaw,
      fin: finRaw,
      dia: diaRaw,
      usuario_id: usuarioIdRaw,
    } = req.query;
    if (!requireSucursalForNonAdmin(req, res)) return;
    const sucursalId = resolveSucursalIdForRead(req, { allowQuery: true });
    const sucursalFilter = buildSucursalFilter(sucursalId);
    const sucursalFilterUsuarios = buildSucursalFilter(sucursalId, "u");
    const sucursalFilterInscripciones = buildSucursalFilter(sucursalId, "i");
    const sucursalFilterAsistencia = buildSucursalFilter(sucursalId, "a");
    const subquerySucursalWhere = sucursalId ? "WHERE sucursal_id = ?" : "";
    const subquerySucursalParams = sucursalId ? [sucursalId] : [];
    const rango = resolveDashboardRange(inicioRaw, finRaw);

    if (!rango.ok) {
      return res.status(400).json({ message: rango.message });
    }

    const { inicio, fin } = rango;
    const dia = isISODateString(diaRaw) ? diaRaw : fin;

    const usuarioIdParam =
      typeof usuarioIdRaw === "string" && usuarioIdRaw.trim() !== ""
        ? Number(usuarioIdRaw)
        : null;

    if (
      usuarioIdParam !== null &&
      (!Number.isInteger(usuarioIdParam) || usuarioIdParam <= 0)
    ) {
      return res.status(400).json({
        message: "usuario_id debe ser un numero entero positivo",
      });
    }

    try {
      const warnings = [];

      const safeQuery = async (name, sql, params = []) => {
        try {
          const [rows] = await dbPromise.query(sql, params);
          return rows;
        } catch (err) {
          warnings.push({ query: name, error: err.message });
          console.error(`[dashboard/resumen] ${name}:`, err.message);
          return [];
        }
      };

      const [
        asistenciasPeriodoRows,
        registrosRows,
        inscripcionesRows,
        vencimientosRows,
        totalAsistenciasDiaRows,
        totalRegistrosDiaRows,
        totalInscripcionesDiaRows,
        totalVencimientosDiaRows,
        asistenciasDiaRows,
        registrosDiaRows,
        inscripcionesDiaRows,
        vencimientosDiaRows,
        vencimientosProximosRows,
        serieInscripcionesRows,
        serieVencimientosRows,
        usuariosActivosRows,
        usuariosInactivosRows,
      ] = await Promise.all([
        safeQuery(
          "asistencias_periodo",
          `
            SELECT COUNT(*) AS total
            FROM asistencia
            WHERE DATE(fecha_asistencia) BETWEEN ? AND ?${sucursalFilter.clause}
          `,
          [inicio, fin, ...sucursalFilter.params]
        ),
        safeQuery(
          "registros_periodo",
          `
            SELECT COUNT(*) AS total
            FROM usuarios
            WHERE DATE(fecha_registro) BETWEEN ? AND ?${sucursalFilter.clause}
          `,
          [inicio, fin, ...sucursalFilter.params]
        ),
        safeQuery(
          "inscripciones_periodo",
          `
            SELECT COUNT(*) AS total
            FROM inscripciones
            WHERE DATE(fecha_inicio) BETWEEN ? AND ?${sucursalFilter.clause}
          `,
          [inicio, fin, ...sucursalFilter.params]
        ),
        safeQuery(
          "vencimientos_periodo",
          `
            SELECT COUNT(*) AS total
            FROM inscripciones
            WHERE DATE(fecha_fin) BETWEEN ? AND ?${sucursalFilter.clause}
          `,
          [inicio, fin, ...sucursalFilter.params]
        ),
        safeQuery(
          "total_asistencias_dia",
          `
            SELECT COUNT(*) AS total
            FROM asistencia
            WHERE DATE(fecha_asistencia) = ?${sucursalFilter.clause}
          `,
          [dia, ...sucursalFilter.params]
        ),
        safeQuery(
          "total_registros_dia",
          `
            SELECT COUNT(*) AS total
            FROM usuarios
            WHERE DATE(fecha_registro) = ?${sucursalFilter.clause}
          `,
          [dia, ...sucursalFilter.params]
        ),
        safeQuery(
          "total_inscripciones_dia",
          `
            SELECT COUNT(*) AS total
            FROM inscripciones
            WHERE DATE(fecha_inicio) = ?${sucursalFilter.clause}
          `,
          [dia, ...sucursalFilter.params]
        ),
        safeQuery(
          "total_vencimientos_dia",
          `
            SELECT COUNT(*) AS total
            FROM inscripciones
            WHERE DATE(fecha_fin) = ?${sucursalFilter.clause}
          `,
          [dia, ...sucursalFilter.params]
        ),
        safeQuery(
          "detalle_asistencias_dia",
          `
            SELECT
              u.id AS usuario_id,
              u.nombre,
              u.apellido,
              DATE_FORMAT(a.fecha_asistencia, '%Y-%m-%d') AS fecha,
              DATE_FORMAT(a.fecha_asistencia, '%h:%i:%s %p') AS hora_am_pm
            FROM asistencia a
            INNER JOIN usuarios u ON u.id = a.usuario_id
            WHERE DATE(a.fecha_asistencia) = ?${sucursalFilterAsistencia.clause}
            ORDER BY a.fecha_asistencia DESC
          `,
          [dia, ...sucursalFilterAsistencia.params]
        ),
        safeQuery(
          "detalle_registros_dia",
          `
            SELECT
              u.id AS usuario_id,
              u.nombre,
              u.apellido,
              DATE_FORMAT(u.fecha_registro, '%Y-%m-%d') AS fecha_registro,
              DATE_FORMAT(u.fecha_registro, '%h:%i:%s %p') AS hora_registro_am_pm
            FROM usuarios u
            WHERE DATE(u.fecha_registro) = ?${sucursalFilterUsuarios.clause}
            ORDER BY u.fecha_registro DESC
          `,
          [dia, ...sucursalFilterUsuarios.params]
        ),
        safeQuery(
          "detalle_inscripciones_dia",
          `
            SELECT
              i.id AS inscripcion_id,
              u.id AS usuario_id,
              u.nombre,
              u.apellido,
              CASE
                WHEN i.membresia_id = 1 THEN 'Dia'
                WHEN i.membresia_id = 2 THEN 'Semanal'
                WHEN i.membresia_id = 3 THEN 'Mensual'
                WHEN i.membresia_id = 4 THEN 'Otro'
                ELSE CONCAT('Membresia ', i.membresia_id)
              END AS membresia_nombre,
              DATE_FORMAT(i.fecha_inicio, '%Y-%m-%d') AS fecha_inicio,
              DATE_FORMAT(i.fecha_fin, '%Y-%m-%d') AS fecha_fin
            FROM inscripciones i
            INNER JOIN usuarios u ON u.id = i.usuario_id
            WHERE DATE(i.fecha_inicio) = ?${sucursalFilterInscripciones.clause}
            ORDER BY i.fecha_inicio DESC, i.id DESC
          `,
          [dia, ...sucursalFilterInscripciones.params]
        ),
        safeQuery(
          "detalle_vencimientos_dia",
          `
            SELECT
              i.id AS inscripcion_id,
              u.id AS usuario_id,
              u.nombre,
              u.apellido,
              CASE
                WHEN i.membresia_id = 1 THEN 'Dia'
                WHEN i.membresia_id = 2 THEN 'Semanal'
                WHEN i.membresia_id = 3 THEN 'Mensual'
                WHEN i.membresia_id = 4 THEN 'Otro'
                ELSE CONCAT('Membresia ', i.membresia_id)
              END AS membresia_nombre,
              DATE_FORMAT(i.fecha_inicio, '%Y-%m-%d') AS fecha_inicio,
              DATE_FORMAT(i.fecha_fin, '%Y-%m-%d') AS fecha_fin
            FROM inscripciones i
            INNER JOIN usuarios u ON u.id = i.usuario_id
            WHERE DATE(i.fecha_fin) = ?${sucursalFilterInscripciones.clause}
            ORDER BY i.fecha_fin ASC, i.id ASC
          `,
          [dia, ...sucursalFilterInscripciones.params]
        ),
        safeQuery(
          "detalle_vencimientos_proximos_7_dias",
          `
            SELECT
              i.id AS inscripcion_id,
              u.id AS usuario_id,
              u.nombre,
              u.apellido,
              i.membresia_id,
              CASE
                WHEN i.membresia_id = 1 THEN 'Dia'
                WHEN i.membresia_id = 2 THEN 'Semanal'
                WHEN i.membresia_id = 3 THEN 'Mensual'
                WHEN i.membresia_id = 4 THEN 'Otro'
                ELSE CONCAT('Membresia ', i.membresia_id)
              END AS membresia_nombre,
              DATE_FORMAT(i.fecha_inicio, '%Y-%m-%d') AS fecha_inicio,
              DATE_FORMAT(i.fecha_fin, '%Y-%m-%d') AS fecha_fin,
              DATEDIFF(i.fecha_fin, CURDATE()) AS dias_restantes
            FROM inscripciones i
            INNER JOIN usuarios u ON u.id = i.usuario_id
            INNER JOIN (
              SELECT usuario_id, MAX(fecha_fin) AS ultima_fecha_fin
              FROM inscripciones
              ${subquerySucursalWhere}
              GROUP BY usuario_id
            ) ult ON ult.usuario_id = i.usuario_id AND ult.ultima_fecha_fin = i.fecha_fin
            WHERE DATE(i.fecha_fin) BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 7 DAY)${sucursalFilterInscripciones.clause}
            ORDER BY i.fecha_fin ASC, u.id ASC
            LIMIT 300
          `,
          [...subquerySucursalParams, ...sucursalFilterInscripciones.params]
        ),
        safeQuery(
          "serie_inscripciones",
          `
            SELECT
              DATE_FORMAT(fecha_base, '%Y-%m-%d') AS fecha,
              total
            FROM (
              SELECT DATE(fecha_inicio) AS fecha_base, COUNT(*) AS total
              FROM inscripciones
              WHERE DATE(fecha_inicio) BETWEEN ? AND ?${sucursalFilter.clause}
              GROUP BY DATE(fecha_inicio)
            ) t
            ORDER BY fecha_base ASC
          `,
          [inicio, fin, ...sucursalFilter.params]
        ),
        safeQuery(
          "serie_vencimientos",
          `
            SELECT
              DATE_FORMAT(fecha_base, '%Y-%m-%d') AS fecha,
              total
            FROM (
              SELECT DATE(fecha_fin) AS fecha_base, COUNT(*) AS total
              FROM inscripciones
              WHERE DATE(fecha_fin) BETWEEN ? AND ?${sucursalFilter.clause}
              GROUP BY DATE(fecha_fin)
            ) t
            ORDER BY fecha_base ASC
          `,
          [inicio, fin, ...sucursalFilter.params]
        ),
        safeQuery(
          "total_usuarios_activos",
          `
            SELECT COUNT(*) AS total
            FROM usuarios u
            LEFT JOIN (
              SELECT usuario_id, MAX(fecha_fin) AS fecha_fin
              FROM inscripciones
              ${subquerySucursalWhere}
              GROUP BY usuario_id
            ) ult ON ult.usuario_id = u.id
            WHERE ult.fecha_fin IS NOT NULL
              AND DATE(ult.fecha_fin) >= CURDATE()${sucursalFilterUsuarios.clause}
          `,
          [...subquerySucursalParams, ...sucursalFilterUsuarios.params]
        ),
        safeQuery(
          "total_usuarios_inactivos",
          `
            SELECT COUNT(*) AS total
            FROM usuarios u
            LEFT JOIN (
              SELECT usuario_id, MAX(fecha_fin) AS fecha_fin
              FROM inscripciones
              ${subquerySucursalWhere}
              GROUP BY usuario_id
            ) ult ON ult.usuario_id = u.id
            WHERE (ult.fecha_fin IS NULL
              OR DATE(ult.fecha_fin) < CURDATE())${sucursalFilterUsuarios.clause}
          `,
          [...subquerySucursalParams, ...sucursalFilterUsuarios.params]
        ),
      ]);

      let asistenciaUsuario = {
        usuario: null,
        asistencias: [],
      };
      let inscripcionesUsuario = {
        usuario: null,
        inscripciones: [],
      };

      if (usuarioIdParam !== null) {
        const [usuarioRows, asistenciaUsuarioRows, inscripcionesUsuarioRows] = await Promise.all([
          safeQuery(
            "usuario_busqueda",
            `
              SELECT id, nombre, apellido
              FROM usuarios
              WHERE id = ?${sucursalFilterUsuarios.clause}
              LIMIT 1
            `,
            [usuarioIdParam, ...sucursalFilterUsuarios.params]
          ),
          safeQuery(
            "asistencia_usuario_busqueda",
            `
              SELECT
                DATE_FORMAT(a.fecha_asistencia, '%Y-%m-%d') AS fecha,
                DATE_FORMAT(a.fecha_asistencia, '%h:%i:%s %p') AS hora_am_pm
              FROM asistencia a
              WHERE a.usuario_id = ?${sucursalFilterAsistencia.clause}
              ORDER BY a.fecha_asistencia DESC
              LIMIT 500
            `,
            [usuarioIdParam, ...sucursalFilterAsistencia.params]
          ),
          safeQuery(
            "inscripciones_usuario_busqueda",
            `
              SELECT
                i.id AS inscripcion_id,
                CASE
                  WHEN i.membresia_id = 1 THEN 'Dia'
                  WHEN i.membresia_id = 2 THEN 'Semanal'
                  WHEN i.membresia_id = 3 THEN 'Mensual'
                  WHEN i.membresia_id = 4 THEN 'Otro'
                  ELSE CONCAT('Membresia ', i.membresia_id)
                END AS membresia_nombre,
                DATE_FORMAT(i.fecha_inicio, '%Y-%m-%d') AS fecha_inicio,
                DATE_FORMAT(i.fecha_fin, '%Y-%m-%d') AS fecha_fin
              FROM inscripciones i
              WHERE i.usuario_id = ?${sucursalFilterInscripciones.clause}
              ORDER BY i.fecha_inicio DESC, i.id DESC
              LIMIT 500
            `,
            [usuarioIdParam, ...sucursalFilterInscripciones.params]
          ),
        ]);

        asistenciaUsuario = {
          usuario: usuarioRows[0] || null,
          asistencias: asistenciaUsuarioRows || [],
        };
        inscripcionesUsuario = {
          usuario: usuarioRows[0] || null,
          inscripciones: inscripcionesUsuarioRows || [],
        };
      }

      return res.json({
        rango: { inicio, fin, dia },
        tarjetas: {
          asistencias_periodo: Number(asistenciasPeriodoRows[0]?.total || 0),
          registros_nuevos_periodo: Number(registrosRows[0]?.total || 0),
          inscripciones_periodo: Number(inscripcionesRows[0]?.total || 0),
          vencimientos_periodo: Number(vencimientosRows[0]?.total || 0),
          usuarios_activos_total: Number(usuariosActivosRows[0]?.total || 0),
          usuarios_inactivos_total: Number(usuariosInactivosRows[0]?.total || 0),
        },
        totales_dia: {
          asistencias: Number(totalAsistenciasDiaRows[0]?.total || 0),
          registros: Number(totalRegistrosDiaRows[0]?.total || 0),
          inscripciones: Number(totalInscripcionesDiaRows[0]?.total || 0),
          vencimientos: Number(totalVencimientosDiaRows[0]?.total || 0),
        },
        series: {
          inscripciones_por_dia: serieInscripcionesRows || [],
          vencimientos_por_dia: serieVencimientosRows || [],
        },
        detalle: {
          asistencias_dia: asistenciasDiaRows || [],
          registros_dia: registrosDiaRows || [],
          inscripciones_dia: inscripcionesDiaRows || [],
          vencimientos_dia: vencimientosDiaRows || [],
          vencimientos_proximos_7_dias: vencimientosProximosRows || [],
          asistencia_usuario: asistenciaUsuario,
          inscripciones_usuario: inscripcionesUsuario,
        },
        warnings,
      });
    } catch (error) {
      return res.status(500).json({
        message: "Error al generar resumen de dashboard",
        error: error.message,
      });
    }
  }
);


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
  if (!requireSucursalForNonAdmin(req, res)) return;
  const sucursalId = resolveSucursalIdForRead(req, { allowQuery: true });

  let sql = `
    SELECT DISTINCT u.*
    FROM usuarios u
    LEFT JOIN inscripciones i ON u.id = i.usuario_id
    WHERE 1=1
  `;

  const params = [];
  const { clause: userFilter, params: userParams } = buildSucursalFilter(sucursalId, "u");
  if (userFilter) {
    sql += userFilter;
    params.push(...userParams);
  }

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
   USUARIOS + ESTADO MEMBRESIA
========================== */
//PROTEGIDO
app.get(
  "/usuarios-con-membresia",
  verifyToken,
  requireRole(["admin", "recepcionista"]),
  (req, res) => {
  if (!requireSucursalForNonAdmin(req, res)) return;
  const sucursalId = resolveSucursalIdForRead(req, { allowQuery: true });
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
  `;
  const params = [];
  const { clause: userFilter, params: userParams } = buildSucursalFilter(sucursalId, "u");
  if (userFilter) {
    sql += ` WHERE 1=1${userFilter}`;
    params.push(...userParams);
  }

  db.query(sql, params, (err, results) => {
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
  if (!requireSucursalForNonAdmin(req, res)) return;
  const sucursalId = resolveSucursalIdForRead(req, { allowQuery: true });

  let sql = "SELECT * FROM usuarios";
  const params = [];
  const { clause: userFilter, params: userParams } = buildSucursalFilter(sucursalId);
  if (userFilter) {
    sql += ` WHERE 1=1${userFilter}`;
    params.push(...userParams);
  }

  db.query(sql, params, (err, results) => {
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
    if (!requireSucursalForNonAdmin(req, res)) return;
    const sucursalId = resolveSucursalIdForRead(req, { allowQuery: true });

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
      WHERE u.id = ?${sucursalId ? " AND u.sucursal_id = ?" : ""}
    `;
    db.query(sql, [id, ...(sucursalId ? [sucursalId] : [])], (err, results) => {
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
