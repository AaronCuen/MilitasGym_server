require("dotenv").config();
const jwt = require("jsonwebtoken");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const db = require("./db");
const verifyToken = require("./middlewares/auth");
const requireAdmin = require("./middlewares/requireAdmin");
const requireRole = require("./middlewares/requireRole");

const app = express();
app.use(cors());
app.use(express.json());

/* ==========================
   FILTRO USUARIOS + MEMBRESÍA
========================== */
app.get("/usuarios/filtrar-con-membresia",
verifyToken,
requireRole(["admin", "recepcionista"]),
async (req, res) => {
  try {
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

    if (id) {
      sql += " AND u.id = ?";
      params.push(id);
    }

    if (nombre) {
      sql += " AND (u.nombre LIKE ? OR u.apellido LIKE ?)";
      params.push(`%${nombre}%`, `%${nombre}%`);
    }

    if (fecha_inicio) {
      sql += " AND DATE(u.fecha_registro) = ?";
      params.push(fecha_inicio);
    }

    if (fecha_fin) {
      sql += " AND DATE(i.fecha_fin) = ?";
      params.push(fecha_fin);
    }

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

    const [rows] = await db.query(sql, params);
    res.json(rows);

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error interno" });
  }
});

/* ==========================
   LOGIN
========================== */
app.post("/login", async (req, res) => {
  try {
    const { usuario, password } = req.body;

    const [rows] = await db.query(
      "SELECT * FROM recepcionistas WHERE usuario = ?",
      [usuario]
    );

    if (rows.length === 0)
      return res.status(401).json({ message: "Usuario no encontrado" });

    const recep = rows[0];
    const ok = await bcrypt.compare(password, recep.password);

    if (!ok)
      return res.status(401).json({ message: "Contraseña incorrecta" });

    const token = jwt.sign(
      { id: recep.id, nombre: recep.nombre, rol: recep.rol },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    res.json({
      token,
      user: {
        id: recep.id,
        nombre: recep.nombre,
        rol: recep.rol
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error interno" });
  }
});

/* ==========================
   CREAR RECEPCIONISTA
========================== */
app.post("/recepcionistas",
verifyToken,
requireAdmin,
async (req, res) => {
  try {
    const { nombre, usuario, password } = req.body;

    if (!nombre || !usuario || !password)
      return res.status(400).json({ message: "Faltan datos" });

    const hash = await bcrypt.hash(password, 10);

    const [result] = await db.query(
      `INSERT INTO recepcionistas (nombre, usuario, password, rol)
       VALUES (?, ?, ?, 'recepcionista')`,
      [nombre, usuario, hash]
    );

    res.status(201).json({
      message: "Recepcionista registrado",
      id: result.insertId
    });

  } catch (error) {
    if (error.code === "ER_DUP_ENTRY")
      return res.status(409).json({ message: "El usuario ya existe" });

    console.error(error);
    res.status(500).json({ message: "Error interno" });
  }
});

/* ==========================
   REGISTRAR USUARIO + INSCRIPCIÓN
========================== */
app.post("/registrar_usuario",
verifyToken,
requireRole(["admin", "recepcionista"]),
async (req, res) => {
  try {
    const {
      nombre, apellido, telefono,
      email, membresia_id, foto,
      fecha_inicio, fecha_fin
    } = req.body;

    if (!nombre || !apellido || !telefono || !membresia_id)
      return res.status(400).json({ message: "Faltan datos obligatorios" });

    const [userResult] = await db.query(
      `INSERT INTO usuarios (nombre, apellido, telefono, email, foto)
       VALUES (?, ?, ?, ?, ?)`,
      [nombre, apellido, telefono, email || null, foto || null]
    );

    const usuario_id = userResult.insertId;

    if (fecha_inicio && fecha_fin) {
      await db.query(
        `INSERT INTO inscripciones (usuario_id, membresia_id, fecha_inicio, fecha_fin)
         VALUES (?, ?, ?, ?)`,
        [usuario_id, membresia_id, fecha_inicio, fecha_fin]
      );
    } else {
      await db.query(
        `INSERT INTO inscripciones (usuario_id, membresia_id, fecha_inicio, fecha_fin)
         VALUES (?, ?, CURDATE(),
          CASE
            WHEN ? = 1 THEN DATE_ADD(CURDATE(), INTERVAL 1 DAY)
            WHEN ? = 2 THEN DATE_ADD(CURDATE(), INTERVAL 7 DAY)
            WHEN ? = 3 THEN DATE_ADD(CURDATE(), INTERVAL 1 MONTH)
            ELSE DATE_ADD(CURDATE(), INTERVAL 1 MONTH)
          END)`,
        [usuario_id, membresia_id, membresia_id, membresia_id, membresia_id]
      );
    }

    res.json({ message: "Usuario e inscripción creada correctamente" });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error interno" });
  }
});

/* ==========================
   RENOVAR MEMBRESÍA
========================== */
app.post("/inscripciones/renovar",
verifyToken,
requireRole(["admin", "recepcionista"]),
async (req, res) => {
  try {
    const { usuario_id, membresia_id, fecha_inicio_manual, fecha_fin_manual } = req.body;

    if (!usuario_id || !membresia_id)
      return res.status(400).json({ message: "Faltan datos" });

    if (Number(membresia_id) === 4) {
      await db.query(
        `INSERT INTO inscripciones (usuario_id, membresia_id, fecha_inicio, fecha_fin)
         VALUES (?, ?, ?, ?)`,
        [usuario_id, membresia_id, fecha_inicio_manual, fecha_fin_manual]
      );
      return res.json({ message: "Membresía personalizada creada correctamente" });
    }

    const [rows] = await db.query(
      `SELECT fecha_fin FROM inscripciones
       WHERE usuario_id = ?
       ORDER BY fecha_fin DESC
       LIMIT 1`,
      [usuario_id]
    );

    let fechaBase = new Date();
    const hoy = new Date();
    hoy.setHours(0,0,0,0);

    if (rows.length > 0) {
      const ultima = new Date(rows[0].fecha_fin);
      ultima.setHours(0,0,0,0);
      fechaBase = ultima >= hoy ? ultima : hoy;
    } else {
      fechaBase = hoy;
    }

    let nueva = new Date(fechaBase);

    if (Number(membresia_id) === 1) nueva.setDate(nueva.getDate()+1);
    if (Number(membresia_id) === 2) nueva.setDate(nueva.getDate()+7);
    if (Number(membresia_id) === 3) nueva.setMonth(nueva.getMonth()+1);

    const inicio = fechaBase.toISOString().slice(0,10);
    const fin = nueva.toISOString().slice(0,10);

    await db.query(
      `INSERT INTO inscripciones (usuario_id, membresia_id, fecha_inicio, fecha_fin)
       VALUES (?, ?, ?, ?)`,
      [usuario_id, membresia_id, inicio, fin]
    );

    res.json({ message: "Membresía renovada correctamente" });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error interno" });
  }
});

/* ==========================
   REGISTRAR ASISTENCIA
========================== */
app.post("/asistencia/:usuario_id",
verifyToken,
requireRole(["admin","recepcionista"]),
async (req,res)=>{
  try{
    const {usuario_id}=req.params;

    const [rows]=await db.query(
      `SELECT fecha_fin FROM inscripciones
       WHERE usuario_id=? ORDER BY fecha_fin DESC LIMIT 1`,
      [usuario_id]
    );

    if(rows.length===0)
      return res.status(400).json({message:"Sin membresía"});

    const fechaFin=new Date(rows[0].fecha_fin);
    const hoy=new Date();
    hoy.setHours(0,0,0,0);
    fechaFin.setHours(0,0,0,0);

    if(hoy>fechaFin)
      return res.status(400).json({message:"Membresía vencida"});

    await db.query(
      `INSERT INTO asistencia (usuario_id,fecha_asistencia)
       VALUES (?,NOW())`,
      [usuario_id]
    );

    res.json({message:"Asistencia registrada correctamente"});

  }catch(error){
    console.error(error);
    res.status(500).json({message:"Error interno"});
  }
});

/* ==========================
   CONSULTAR INSCRIPCIÓN
========================== */
app.get("/inscripcion/:usuario_id",
verifyToken,
requireRole(["admin","recepcionista"]),
async (req,res)=>{
  try{
    const {usuario_id}=req.params;

    const [rows]=await db.query(
      `SELECT * FROM inscripciones
       WHERE usuario_id=? ORDER BY fecha_fin DESC LIMIT 1`,
      [usuario_id]
    );

    if(rows.length===0)
      return res.status(404).json({message:"Sin membresía"});

    res.json(rows[0]);

  }catch(error){
    console.error(error);
    res.status(500).json({message:"Error interno"});
  }
});

/* ==========================
   VER USUARIOS
========================== */
app.get("/usuarios",
verifyToken,
requireRole(["admin","recepcionista"]),
async (req,res)=>{
  try{
    const [rows]=await db.query("SELECT * FROM usuarios");
    res.json(rows);
  }catch(error){
    res.status(500).json({message:"Error interno"});
  }
});

/* ==========================
   ELIMINAR USUARIO
========================== */
app.delete("/usuarios/:id",
verifyToken,
requireRole(["admin"]),
async (req,res)=>{
  try{
    const {id}=req.params;
    await db.query("DELETE FROM asistencia WHERE usuario_id=?", [id]);
    await db.query("DELETE FROM inscripciones WHERE usuario_id=?", [id]);
    await db.query("DELETE FROM usuarios WHERE id=?", [id]);
    res.json({message:"Usuario eliminado correctamente"});
  }catch(error){
    console.error(error);
    res.status(500).json({message:"Error interno"});
  }
});

/* ==========================
   TEST
========================== */
app.get("/", (req,res)=>{
  res.json({ok:true,message:"API funcionando"});
});

const PORT=process.env.PORT||4000;
app.listen(PORT,()=>console.log("Servidor corriendo en puerto "+PORT));