const express = require("express")
const sqlite3 = require("sqlite3").verbose()
const session = require("express-session")
const bcrypt = require("bcryptjs")
const bodyParser = require("body-parser")
const path = require("path")
const multer = require("multer")
const http = require("http")
const { Server } = require("socket.io")
const nodemailer = require("nodemailer")
const crypto = require("crypto")

// Importar el módulo de publicaciones
const publicacionModule = require("./publicacion")

// Configuración de `multer` (almacenar en memoria para insertar en SQLite)
const storage = multer.memoryStorage()
const upload = multer({ storage: storage })
const app = express()
const db = new sqlite3.Database("./database.db")
const server = http.createServer(app)
const io = new Server(server)

// Pasar la instancia de io al módulo de publicaciones
publicacionModule.setSocketIO(io)

// Configurar EJS
app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "views"))

// Middleware
app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.json()) // Para manejar JSON en las peticiones
app.use(express.static("public"))
app.use(
  session({
    secret: "secreto123",
    resave: false,
    saveUninitialized: true,
  }),
)

// Crear tabla usuarios
db.run(
  `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    profile_picture TEXT,
    banner BLOB,
    description TEXT,
	verification_code TEXT,
    verification_expiration DATETIME
  )`,
)

db.run(
  `CREATE TABLE IF NOT EXISTS clans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    photo BLOB NOT NULL,
    banner BLOB NOT NULL,
    owner_id INTEGER,
    invite_link TEXT,
    FOREIGN KEY(owner_id) REFERENCES users(id)
  )`,
)

// Tabla intermedia para la relación usuarios-clanes
db.run(
  `CREATE TABLE IF NOT EXISTS clan_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    clan_id INTEGER,
    user_id INTEGER,
    joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(clan_id) REFERENCES clans(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    UNIQUE(clan_id, user_id)
  )`,
)

db.run(
  `CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    clan_id INTEGER,
    user_id INTEGER,
    message TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(clan_id) REFERENCES clans(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`,
)
db.run(
  `CREATE TABLE IF NOT EXISTS clan_bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    clan_id INTEGER,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(clan_id, user_id),
    FOREIGN KEY(clan_id) REFERENCES clans(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`,
)

// Configuración del transportador de nodemailer
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "correo electronico.com", // Tu correo de Gmail
    pass: "myzceuujbgfmzrxy"
  },
})

app.get("/", (req, res) => {
  res.render("auth", { error: null })
})

// REGISTRO - Envío de código de verificación
app.post("/register", async (req, res) => {
  const { name, email, password, confirmPassword } = req.body

  if (!name || !email || !password || password !== confirmPassword) {
    return res.render("auth", { error: "Datos inválidos o contraseñas no coinciden." })
  }

  const hashedPassword = await bcrypt.hash(password, 10)
  const verificationCode = crypto.randomBytes(3).toString("hex")

  req.session.pendingUser = {
    name,
    email,
    password: hashedPassword,
    verificationCode,
    codeSentAt: Date.now(),
    resendCount: 0,
  }

  // Enviar código de verificación en un correo decorado
  await transporter.sendMail({
    from: "correo electronico.com",
    to: email,
    subject: "Código de verificación",
    html: `
      <html>
        <body style="font-family: 'Arial', sans-serif; padding: 20px; background-color: #f4f9fc; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; background-color: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); border-top: 4px solid #1e88e5;">
            <h2 style="color: #1e88e5; font-size: 26px; margin-bottom: 20px; font-weight: 600; text-align: center;">Bienvenido a Stelar Studio</h2>
            <p style="font-size: 18px; color: #555;">Hola <strong style="color: #1e88e5;">${name}</strong>,</p>
            <p style="font-size: 16px; color: #555;">Gracias por registrarte. Para completar tu registro, ingresa el siguiente código de verificación:</p>
            <div style="background-color: #e0f7fa; padding: 20px; text-align: center; font-size: 24px; font-weight: bold; color: #00796b; border-radius: 6px; margin: 20px 0;">
              <strong>${verificationCode}</strong>
            </div>
            <p style="font-size: 16px; color: #555;">Si no realizaste esta solicitud, por favor ignora este correo.</p>
            <p style="font-size: 16px; color: #555;">¡Gracias por ser parte de nuestra comunidad!</p>
            <p style="font-size: 0.9em; color: #777; text-align: center;">Este correo fue enviado automáticamente, no respondas a esta dirección.</p>
            <footer style="margin-top: 30px; font-size: 12px; color: #999; text-align: center;">
              <p>Stelar Studio &copy; 2025</p>
            </footer>
          </div>
        </body>
      </html>
    `,
  })

  res.render("verify", { error: null, pendingUser: req.session.pendingUser })
})

// VERIFICACIÓN
app.post("/verify", (req, res) => {
  const { code } = req.body
  const user = req.session.pendingUser
  if (!user) return res.redirect("/")

  const expirado = Date.now() - user.codeSentAt > 10 * 60 * 1000
  if (expirado) {
    return res.render("verify", { error: "El código ha expirado. Reenvíalo.", pendingUser: user })
  }

  if (code !== user.verificationCode) {
    return res.render("verify", { error: "Código incorrecto.", pendingUser: user })
  }

  db.run(
    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
    [user.name, user.email, user.password],
    (err) => {
      if (err) return res.render("auth", { error: "Correo ya registrado." })
      req.session.pendingUser = null
      res.redirect("/")
    },
  )
})

// REENVÍO DEL CÓDIGO
app.get("/resend-code", async (req, res) => {
  const user = req.session.pendingUser
  if (!user) return res.redirect("/")

  const now = Date.now()

  // Si alcanzó el límite antes
  if (user.resendCount >= 3) {
    if (!user.resendBlockedAt) {
      user.resendBlockedAt = now
    }

    const minutesPassed = (now - user.resendBlockedAt) / (60 * 1000)

    if (minutesPassed >= 30) {
      user.resendCount = 0
      user.resendBlockedAt = null
    } else {
      const minutosFaltantes = Math.ceil(30 - minutesPassed)
      return res.render("verify", {
        error: `Límite de reenvíos alcanzado. Intenta en ${minutosFaltantes} minutos.`,
        pendingUser: user,
      })
    }
  }

  // Nuevo código
  const newCode = crypto.randomBytes(3).toString("hex")
  user.verificationCode = newCode
  user.codeSentAt = now
  user.resendCount += 1

  await transporter.sendMail({
    from: "correo electronico.com",
    to: user.email,
    subject: "Nuevo código de verificación",
    html: `
      <html>
        <body style="font-family: 'Arial', sans-serif; padding: 20px; background-color: #f4f9fc; color: #333;">
          <div style="max-width: 600px; margin: 0 auto; background-color: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1); border-top: 4px solid #1e88e5;">
            <h2 style="color: #1e88e5; font-size: 26px; margin-bottom: 20px; font-weight: 600; text-align: center;">Tu nuevo código de verificación</h2>
            <p style="font-size: 18px; color: #555;">Hola <strong style="color: #1e88e5;">${user.name}</strong>,</p>
            <p style="font-size: 16px; color: #555;">Hemos enviado un nuevo código de verificación. Usa el siguiente código para completar tu registro:</p>
            <div style="background-color: #e0f7fa; padding: 20px; text-align: center; font-size: 24px; font-weight: bold; color: #00796b; border-radius: 6px; margin: 20px 0;">
              <strong>${newCode}</strong>
            </div>
            <p style="font-size: 16px; color: #555;">Si no realizaste esta solicitud, por favor ignora este correo.</p>
            <p style="font-size: 16px; color: #555;">¡Gracias por ser parte de nuestra comunidad!</p>
            <p style="font-size: 0.9em; color: #777; text-align: center;">Este correo fue enviado automáticamente, no respondas a esta dirección.</p>
            <footer style="margin-top: 30px; font-size: 12px; color: #999; text-align: center;">
              <p>Stelar Studio &copy; 2025</p>
            </footer>
          </div>
        </body>
      </html>
    `,
  })

  res.render("verify", { error: "Nuevo código enviado.", pendingUser: user })
})

// LOGIN
app.post("/login", (req, res) => {
  const { email, password } = req.body

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err || !user || !(await bcrypt.compare(password, user.password))) {
      return res.render("auth", { error: "Correo o contraseña incorrectos." })
    }

    req.session.user = user
    res.redirect("/dashboard")
  })
})


// LOGIN
app.post("/login", (req, res) => {
  const { email, password } = req.body

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (err || !user || !(await bcrypt.compare(password, user.password))) {
      return res.render("auth", { error: "Correo o contraseña incorrectos." })
    }

    req.session.user = user
    res.redirect("/dashboard")
  })
})

// 🔹 MOSTRAR PERFIL DEL USUARIO
app.get("/perfil", (req, res) => {
  if (!req.session.user) return res.redirect("/")
  db.get("SELECT * FROM users WHERE id = ?", [req.session.user.id], (err, user) => {
    if (err) return res.send("Error cargando perfil.")
    res.render("perfil", { user })
  })
})

// 🔹 ACTUALIZAR PERFIL (IMÁGENES Y DESCRIPCIÓN)
app.post("/perfil", upload.fields([{ name: "profile_picture" }, { name: "banner" }]), (req, res) => {
  if (!req.session.user) return res.redirect("/")

  const profilePicture = req.files["profile_picture"] ? req.files["profile_picture"][0].buffer.toString("base64") : null
  const banner = req.files["banner"] ? req.files["banner"][0].buffer.toString("base64") : null
  const description = req.body.description || ""

  db.run(
    "UPDATE users SET profile_picture = COALESCE(?, profile_picture), banner = COALESCE(?, banner), description = ? WHERE id = ?",
    [profilePicture, banner, description, req.session.user.id],
    (err) => {
      if (err) {
        console.error("Error al actualizar perfil:", err)
        return res.send("Error al actualizar el perfil.")
      }

      // Actualizar la sesión con los nuevos datos
      db.get("SELECT * FROM users WHERE id = ?", [req.session.user.id], (err, user) => {
        if (!err && user) {
          req.session.user = user
        }
        res.redirect("/perfil")
      })
    },
  )
})

// Función auxiliar para verificar el número de clanes de un usuario
function getUserClanCount(userId, callback) {
  db.get(
    `
    SELECT COUNT(*) as count 
    FROM (
      SELECT id FROM clans WHERE owner_id = ?
      UNION
      SELECT clan_id FROM clan_members WHERE user_id = ?
    )`,
    [userId, userId],
    (err, row) => {
      if (err) {
        console.error(err)
        callback(err)
        return
      }
      callback(null, row.count)
    },
  )
}

// Página para Crear Clan
app.get("/crear", (req, res) => {
  if (!req.session.user) return res.redirect("/")

  // Verificar el número de clanes del usuario
  getUserClanCount(req.session.user.id, (err, count) => {
    if (err) return res.send("Error al verificar clanes.")
    if (count >= 100) {
      return res.send("Ya has alcanzado el límite de 100 clanes. Debes salir de alguno antes de crear uno nuevo.")
    }
    res.render("crear")
  })
})

// Procesar Creación del Clan
app.post("/crear", upload.fields([{ name: "photo" }, { name: "banner" }]), (req, res) => {
  if (!req.session.user) return res.redirect("/")

  // Verificar el número de clanes del usuario
  getUserClanCount(req.session.user.id, (err, count) => {
    if (err) return res.send("Error al verificar clanes.")
    if (count >= 100) {
      return res.send("Ya has alcanzado el límite de 100 clanes. Debes salir de alguno antes de crear uno nuevo.")
    }

    const { title, description } = req.body
    const photo = req.files["photo"][0].buffer
    const banner = req.files["banner"][0].buffer
    const user_id = req.session.user.id

    db.run(
      "INSERT INTO clans (title, description, photo, banner, owner_id) VALUES (?, ?, ?, ?, ?)",
      [title, description, photo, banner, user_id],
      (err) => {
        if (err) {
          console.error(err)
          return res.send("Error al crear el clan.")
        }
        res.redirect("/dashboard")
      },
    )
  })
})

function getUnreadPublicationsCount(userId, clans, callback) {
  if (!clans || clans.length === 0) {
    return callback(null, {})
  }

  const clanIds = clans.map((clan) => clan.id)
  const placeholders = clanIds.map(() => "?").join(",")

  db.all(
    `SELECT p.clan_id, COUNT(*) as count 
     FROM publications p 
     WHERE p.clan_id IN (${placeholders}) 
     AND NOT EXISTS (
       SELECT 1 FROM publication_views v 
       WHERE v.publication_id = p.id AND v.user_id = ?
     )
     GROUP BY p.clan_id`,
    [...clanIds, userId],
    (err, results) => {
      if (err) {
        console.error("Error getting unread counts:", err)
        return callback(err)
      }

      const counts = {}
      results.forEach((result) => {
        counts[result.clan_id] = result.count
      })

      callback(null, counts)
    },
  )
}

// creo que necesito ayuda
// https://fxy-fox.netlify.app/

app.get("/dashboard", (req, res) => {
  if (!req.session.user) return res.redirect("/")

  // Consulta de clanes en los que el usuario es el propietario
  db.all("SELECT * FROM clans WHERE owner_id = ?", [req.session.user.id], (err, ownClans) => {
    if (err) return res.send("Error al cargar clanes.")

    // Consulta de clanes en los que el usuario es miembro (excluyendo los que creó)
    db.all(
      "SELECT c.* FROM clans c JOIN clan_members cm ON c.id = cm.clan_id WHERE cm.user_id = ? AND c.owner_id != ?",
      [req.session.user.id, req.session.user.id],
      (err, memberClans) => {
        if (err) return res.send("Error al cargar clanes.")

        // Get unread publications count for all clans
        const allClans = [...ownClans, ...memberClans]
        getUnreadPublicationsCount(req.session.user.id, allClans, (err, unreadCounts) => {
          if (err) {
            console.error("Error getting unread counts:", err)
            unreadCounts = {}
          }

          res.render("dashboard", {
            user: req.session.user,
            ownClans,
            memberClans,
            unreadCounts,
          })
        })
      },
    )
  })
})
app.get("/clan/:id/ajustes", (req, res) => {
  if (!req.session.user) return res.redirect("/")
  const clanId = req.params.id

  db.get("SELECT * FROM clans WHERE id = ?", [clanId], (err, clan) => {
    if (err || !clan) return res.send("Clan no encontrado.")
    // Verificar que el usuario sea el propietario del clan
    if (req.session.user.id !== clan.owner_id) {
      return res.send("No tienes permiso para acceder a los ajustes de este clan.")
    }
    res.render("ajustes", { clan })
  })
})
app.post("/clan/:id/ajustes", upload.fields([{ name: "photo" }, { name: "banner" }]), (req, res) => {
  if (!req.session.user) return res.redirect("/")
  const clanId = req.params.id

  // Primero, obtenemos el clan para verificar la propiedad
  db.get("SELECT * FROM clans WHERE id = ?", [clanId], (err, clan) => {
    if (err || !clan) return res.send("Clan no encontrado.")
    if (req.session.user.id !== clan.owner_id) {
      return res.send("No tienes permiso para modificar este clan.")
    }

    // Extraer datos del formulario
    const { title, description } = req.body
    const photo = req.files["photo"] ? req.files["photo"][0].buffer : null
    const banner = req.files["banner"] ? req.files["banner"][0].buffer : null

    // Actualizar el clan: solo se actualizan los campos que tengan valor (si el campo está vacío, se conserva el anterior)
    const query = `
      UPDATE clans 
      SET 
        title = COALESCE(?, title),
        description = COALESCE(?, description),
        photo = COALESCE(?, photo),
        banner = COALESCE(?, banner)
      WHERE id = ?
    `
    db.run(query, [title || null, description || null, photo, banner, clanId], (err) => {
      if (err) {
        console.error(err)
        return res.send("Error al actualizar los ajustes del clan.")
      }
      res.redirect(`/clan/${clanId}`)
    })
  })
})

// Servir Imágenes desde SQLite
app.get("/imagen/:id/:tipo", (req, res) => {
  const { id, tipo } = req.params
  const columna = tipo === "banner" ? "banner" : "photo"

  db.get(`SELECT ${columna} FROM clans WHERE id = ?`, [id], (err, row) => {
    if (err || !row) return res.send("Imagen no encontrada")
    res.writeHead(200, { "Content-Type": "image/png" })
    res.end(row[columna])
  })
})

// API para obtener mensajes paginados (para scroll infinito)
app.get("/api/clan/:id/messages", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "No autorizado" })

  const clanId = req.params.id
  const page = Number.parseInt(req.query.page) || 1
  const limit = 10
  const offset = (page - 1) * limit

  // Verificar si el usuario es miembro o propietario del clan
  db.get("SELECT * FROM clans WHERE id = ?", [clanId], (err, clan) => {
    if (err || !clan) return res.status(404).json({ error: "Clan no encontrado" })

    const isOwner = req.session.user.id === clan.owner_id

    if (!isOwner) {
      db.get(
        "SELECT * FROM clan_members WHERE clan_id = ? AND user_id = ?",
        [clanId, req.session.user.id],
        (err, membership) => {
          if (err || !membership) {
            return res.status(403).json({ error: "No eres miembro de este clan" })
          }

          // Verificar si el usuario está baneado
          db.get(
            "SELECT * FROM clan_bans WHERE clan_id = ? AND user_id = ?",
            [clanId, req.session.user.id],
            (err, ban) => {
              if (ban) {
                return res.status(403).json({ error: "Has sido baneado de este clan" })
              }

              fetchMessages()
            },
          )
        },
      )
    } else {
      fetchMessages()
    }

    function fetchMessages() {
      // Obtener el total de mensajes
      db.get("SELECT COUNT(*) as total FROM messages WHERE clan_id = ?", [clanId], (err, countResult) => {
        if (err) return res.status(500).json({ error: "Error al contar mensajes" })

        const totalMessages = countResult.total
        const totalPages = Math.ceil(totalMessages / limit)

        // Obtener mensajes paginados
        db.all(
          `SELECT m.*, u.name, u.profile_picture 
           FROM messages m 
           JOIN users u ON m.user_id = u.id 
           WHERE m.clan_id = ? 
           ORDER BY m.timestamp DESC
           LIMIT ? OFFSET ?`,
          [clanId, limit, offset],
          (err, messages) => {
            if (err) return res.status(500).json({ error: "Error al cargar mensajes" })

            res.json({
              messages,
              currentPage: page,
              totalPages,
              hasMore: page < totalPages,
            })
          },
        )
      })
    }
  })
})

app.get("/clan/:id", (req, res) => {
  // Si el usuario no está autenticado, redirigir al inicio
  if (!req.session.user) {
    return res.redirect("/")
  }

  const clanId = req.params.id
  const page = Number.parseInt(req.query.page) || 1
  const limit = 10
  const offset = (page - 1) * limit

  db.get("SELECT * FROM clans WHERE id = ?", [clanId], (err, clan) => {
    if (err || !clan) return res.send("Clan no encontrado.")

    const isOwner = req.session.user.id === clan.owner_id

    // Obtener miembros del clan (incluyendo al propietario)
    db.all(
      `
      SELECT u.* FROM users u 
      WHERE u.id = ? OR u.id IN (
        SELECT user_id FROM clan_members WHERE clan_id = ?
      )
    `,
      [clan.owner_id, clanId],
      (err, members) => {
        if (err) return res.send("Error al cargar miembros.")

        // Verificar si el usuario es miembro (propietario o miembro regular)
        db.get(
          "SELECT * FROM clan_members WHERE clan_id = ? AND user_id = ?",
          [clanId, req.session.user.id],
          (err, membership) => {
            const isMember = isOwner || !!membership

            // Verificar si el usuario está baneado
            db.get(
              "SELECT * FROM clan_bans WHERE clan_id = ? AND user_id = ?",
              [clanId, req.session.user.id],
              (err, ban) => {
                const banned = !!ban

                // Obtener usuarios baneados
                db.all(
                  "SELECT u.* FROM users u JOIN clan_bans b ON u.id = b.user_id WHERE b.clan_id = ?",
                  [clanId],
                  (err, bannedUsers) => {
                    if (err) bannedUsers = []

                    // Obtener el total de mensajes
                    db.get("SELECT COUNT(*) as total FROM messages WHERE clan_id = ?", [clanId], (err, countResult) => {
                      if (err) return res.send("Error al cargar mensajes.")
                      const totalMessages = countResult.total
                      const totalPages = Math.ceil(totalMessages / limit)

                      // Obtener mensajes paginados
                      db.all(
                        `SELECT m.*, u.name, u.profile_picture 
                 FROM messages m 
                 JOIN users u ON m.user_id = u.id 
                 WHERE m.clan_id = ? 
                 ORDER BY m.timestamp DESC
                 LIMIT ? OFFSET ?`,
                        [clanId, limit, offset],
                        (err, messages) => {
                          if (err) return res.send("Error al cargar mensajes.")
                          // Invertir el orden de los mensajes para mostrarlos cronológicamente
                          messages.reverse()
                          res.render("clan", {
                            clan,
                            members,
                            isOwner,
                            messages,
                            user: req.session.user,
                            isMember,
                            banned,
                            bannedUsers,
                            totalMessages,
                            currentPage: page,
                            totalPages,
                            hasMore: page < totalPages,
                          })
                        },
                      )
                    })
                  },
                )
              },
            )
          },
        )
      },
    )
  })
})

// Generar código de invitación (solo una vez)
app.post("/clan/:id/generar-invitacion", (req, res) => {
  const clanId = req.params.id

  db.get("SELECT invite_link FROM clans WHERE id = ?", [clanId], (err, clan) => {
    if (err || !clan) return res.send({ error: "Clan no encontrado" })

    // Si ya existe un código, retornarlo
    if (clan.invite_link) {
      return res.send({ code: clan.invite_link })
    }

    // Generar un código de 8 caracteres sin el prefijo "http://"
    const code = Math.random().toString(36).substr(2, 8).toUpperCase()

    db.run("UPDATE clans SET invite_link = ? WHERE id = ?", [code, clanId], () => {
      res.send({ code })
    })
  })
})
app.post("/unirse", (req, res) => {
  if (!req.session.user) return res.redirect("/")

  const { invite_code } = req.body

  // Verificar el número de clanes del usuario
  getUserClanCount(req.session.user.id, (err, count) => {
    if (err) return res.send("Error al verificar clanes.")
    if (count >= 100) {
      return res.send("Ya has alcanzado el límite de 100 clanes. Debes salir de alguno antes de unirte a otro.")
    }

    // Buscar un clan con el código de invitación
    db.get("SELECT * FROM clans WHERE invite_link = ?", [invite_code], (err, clan) => {
      if (err || !clan) {
        return res.send("Código de invitación inválido.")
      }

      // Evitar que el propietario se una como miembro
      if (clan.owner_id === req.session.user.id) {
        return res.send("Eres el creador del clan, no puedes unirte como miembro.")
      }

      // Verificar si el usuario está baneado del clan
      db.get(
        "SELECT * FROM clan_bans WHERE clan_id = ? AND user_id = ?",
        [clan.id, req.session.user.id],
        (err, ban) => {
          if (err) {
            console.error(err)
            return res.send("Error al verificar baneos.")
          }
          if (ban) {
            return res.send("No puedes unirte a este clan, has sido baneado.")
          }

          // Verificar si el usuario ya es miembro del clan
          db.get(
            "SELECT * FROM clan_members WHERE clan_id = ? AND user_id = ?",
            [clan.id, req.session.user.id],
            (err, membership) => {
              if (membership) {
                return res.send("Ya estás unido a este clan.")
              }

              // Insertar al usuario en el clan
              db.run(
                "INSERT INTO clan_members (clan_id, user_id) VALUES (?, ?)",
                [clan.id, req.session.user.id],
                (err) => {
                  if (err) {
                    return res.send("Error al unirse al clan.")
                  }
                  res.redirect(`/clan-joined/${clan.id}`)
                },
              )
            },
          )
        },
      )
    })
  })
})

app.get("/unirse/:clanId/:code", (req, res) => {
  const { clanId, code } = req.params
  const currentUser = req.session.user

  if (!currentUser) {
    return res.send("Debes iniciar sesión para unirte al clan.")
  }

  // Verificar el número de clanes del usuario
  getUserClanCount(currentUser.id, (err, count) => {
    if (err) return res.send("Error al verificar clanes.")
    if (count >= 100) {
      return res.send("Ya has alcanzado el límite de 100 clanes. Debes salir de alguno antes de unirte a otro.")
    }

    console.log("Intentando unirse: usuario", currentUser.id, "al clan", clanId)

    // Buscar el clan por id y verificar el código de invitación
    db.get("SELECT * FROM clans WHERE id = ? AND invite_link LIKE ?", [clanId, `%${code}`], (err, clan) => {
      if (err) {
        console.error(err)
        return res.send("Error en la base de datos.")
      }
      if (!clan) {
        return res.send("Enlace inválido o expirado.")
      }

      // Verificar si el usuario está baneado del clan
      db.get("SELECT * FROM clan_bans WHERE clan_id = ? AND user_id = ?", [clanId, currentUser.id], (err, ban) => {
        if (err) {
          console.error(err)
          return res.send("Error al verificar baneos.")
        }
        if (ban) {
          console.log("Usuario baneado:", currentUser.id)
          return res.send("No puedes unirte a este clan, has sido baneado.")
        }

        // Verificar si el usuario ya es miembro del clan
        db.get(
          "SELECT * FROM clan_members WHERE clan_id = ? AND user_id = ?",
          [clanId, currentUser.id],
          (err, membership) => {
            if (err) {
              console.error(err)
              return res.send("Error al verificar membresía.")
            }
            if (membership) {
              return res.send("Ya eres miembro de este clan.")
            }

            // Insertar al usuario en el clan
            db.run("INSERT INTO clan_members (clan_id, user_id) VALUES (?, ?)", [clanId, currentUser.id], (err) => {
              if (err) {
                console.error(err)
                return res.send("Error al unirse al clan.")
              }
              console.log("Usuario", currentUser.id, "se unió al clan", clanId)
              res.redirect(`/clan-joined/${clanId}`)
            })
          },
        )
      })
    })
  })
})

// Ruta para mostrar la página de unión exitosa a un clan
app.get("/clan-joined/:id", (req, res) => {
  if (!req.session.user) return res.redirect("/")

  const clanId = req.params.id

  // Verificar que el clan exista
  db.get("SELECT * FROM clans WHERE id = ?", [clanId], (err, clan) => {
    if (err || !clan) return res.send("Clan no encontrado.")

    // Verificar que el usuario sea miembro del clan
    const isOwner = req.session.user.id === clan.owner_id

    if (!isOwner) {
      db.get(
        "SELECT * FROM clan_members WHERE clan_id = ? AND user_id = ?",
        [clanId, req.session.user.id],
        (err, membership) => {
          if (err || !membership) {
            return res.redirect("/dashboard")
          }

          // Renderizar la página de unión exitosa
          res.render("clan-joined", { clan, user: req.session.user })
        },
      )
    } else {
      // Si es el propietario, también mostrar la página
      res.render("clan-joined", { clan, user: req.session.user })
    }
  })
})

// Banear miembro
app.post("/clan/:clanId/ban/:userId", (req, res) => {
  if (!req.session.user) return res.redirect("/")
  const { clanId, userId } = req.params

  // Verificar que el clan exista y que el usuario actual sea el owner
  db.get("SELECT * FROM clans WHERE id = ?", [clanId], (err, clan) => {
    if (err || !clan) return res.send("Clan no encontrado.")
    if (req.session.user.id !== clan.owner_id) return res.send("No tienes permiso.")

    // Obtener el nombre del usuario que será baneado
    db.get("SELECT name FROM users WHERE id = ?", [userId], (err, user) => {
      if (err || !user) return res.send("Usuario no encontrado.")

      // Insertar en clan_bans y eliminar de clan_members
      db.run("INSERT OR IGNORE INTO clan_bans (clan_id, user_id) VALUES (?, ?)", [clanId, userId], (err) => {
        if (err) return res.send("Error al banear al miembro.")
        db.run("DELETE FROM clan_members WHERE clan_id = ? AND user_id = ?", [clanId, userId], (err) => {
          if (err) return res.send("Error al expulsar al miembro.")

          // Emitir evento de baneo a través de Socket.IO
          io.to(`user_${userId}`).emit("userBanned", {
            clan_id: clanId,
            clan_title: clan.title,
            message: "Has sido baneado del clan. Ya no podrás acceder al chat ni volver a unirte.",
          })

          // Notificar a todos los miembros del clan
          io.to(`clan_${clanId}`).emit("memberBanned", {
            user_id: userId,
            user_name: user.name,
          })

          res.send("Miembro baneado.")
        })
      })
    })
  })
})

// Expulsar miembro (acción temporal: se permite volver a unirse)
app.post("/clan/:clanId/expel/:userId", (req, res) => {
  if (!req.session.user) return res.redirect("/")
  const { clanId, userId } = req.params

  db.get("SELECT * FROM clans WHERE id = ?", [clanId], (err, clan) => {
    if (err || !clan) return res.send("Clan no encontrado.")
    if (req.session.user.id !== clan.owner_id) return res.send("No tienes permiso.")

    // Obtener el nombre del usuario que será expulsado
    db.get("SELECT name FROM users WHERE id = ?", [userId], (err, user) => {
      if (err || !user) return res.send("Usuario no encontrado.")

      // Eliminar al usuario de clan_members
      db.run("DELETE FROM clan_members WHERE clan_id = ? AND user_id = ?", [clanId, userId], (err) => {
        if (err) return res.send("Error al expulsar al miembro.")

        // Además, remover cualquier baneo previo para permitir que pueda volver a unirse
        db.run("DELETE FROM clan_bans WHERE clan_id = ? AND user_id = ?", [clanId, userId], (err) => {
          if (err) console.error("Error al remover baneo, pero expulsión completada.")

          // Emitir evento de expulsión a través de Socket.IO
          io.to(`user_${userId}`).emit("userExpelled", {
            clan_id: clanId,
            clan_title: clan.title,
            message: "Has sido expulsado del clan. Puedes volver a unirte con una invitación.",
          })

          // Notificar a todos los miembros del clan
          io.to(`clan_${clanId}`).emit("memberExpelled", {
            user_id: userId,
            user_name: user.name,
          })

          res.send("Miembro expulsado.")
        })
      })
    })
  })
})

// Ruta para desbanear a un usuario (solo owner)
app.post("/clan/:clanId/unban/:userId", (req, res) => {
  if (!req.session.user) return res.redirect("/")
  const { clanId, userId } = req.params

  db.get("SELECT * FROM clans WHERE id = ?", [clanId], (err, clan) => {
    if (err || !clan) return res.send("Clan no encontrado.")
    if (req.session.user.id !== clan.owner_id) return res.send("No tienes permiso.")

    db.run("DELETE FROM clan_bans WHERE clan_id = ? AND user_id = ?", [clanId, userId], (err) => {
      if (err) return res.send("Error al desbanear al miembro.")

      // Notificar al usuario que ha sido desbaneado
      io.to(`user_${userId}`).emit("userUnbanned", {
        clan_id: clanId,
        clan_title: clan.title,
        message: "Has sido desbaneado del clan. Ahora puedes volver a unirte.",
      })

      res.send("Miembro desbaneado.")
    })
  })
})

// Ruta para salir del clan
app.post("/clan/:clanId/salir", (req, res) => {
  if (!req.session.user) return res.redirect("/")
  const clanId = req.params.clanId

  // Verificar que el clan exista
  db.get("SELECT * FROM clans WHERE id = ?", [clanId], (err, clan) => {
    if (err || !clan) return res.send("Clan no encontrado.")

    // Verificar que el usuario no sea el propietario
    if (req.session.user.id === clan.owner_id) {
      return res.send("No puedes salir del clan si eres el propietario. Debes eliminarlo o transferir la propiedad.")
    }

    // Verificar que el usuario sea miembro del clan
    db.get(
      "SELECT * FROM clan_members WHERE clan_id = ? AND user_id = ?",
      [clanId, req.session.user.id],
      (err, membership) => {
        if (err || !membership) {
          return res.send("No eres miembro de este clan.")
        }

        // Eliminar al usuario del clan
        db.run("DELETE FROM clan_members WHERE clan_id = ? AND user_id = ?", [clanId, req.session.user.id], (err) => {
          if (err) return res.send("Error al salir del clan.")

          // Notificar a todos los miembros del clan que el usuario ha salido
          io.to(`clan_${clanId}`).emit("memberLeft", {
            user_id: req.session.user.id,
            user_name: req.session.user.name,
          })

          res.redirect("/dashboard")
        })
      },
    )
  })
})

app.post("/clan/:id/eliminar", (req, res) => {
  const clanId = req.params.id
  const userId = req.session.user.id

  // Verificar que el usuario sea el propietario del clan
  db.get("SELECT owner_id FROM clans WHERE id = ?", [clanId], (err, clan) => {
    if (err) {
      console.error("Error al verificar propietario:", err)
      return res.status(500).send("Error al eliminar el clan")
    }

    if (!clan || clan.owner_id !== userId) {
      return res.status(403).send("No tienes permiso para eliminar este clan")
    }

    // Iniciar una transacción para eliminar todo relacionado con el clan
    db.serialize(() => {
      db.run("BEGIN TRANSACTION")

      // 1. Eliminar todos los likes de las publicaciones del clan
      db.run(
        `DELETE FROM likes WHERE publication_id IN 
              (SELECT id FROM publications WHERE clan_id = ?)`,
        [clanId],
        (err) => {
          if (err) {
            console.error("Error al eliminar likes:", err)
            db.run("ROLLBACK")
            return res.status(500).send("Error al eliminar el clan")
          }

          // 2. Eliminar todos los comentarios de las publicaciones del clan
          db.run(
            `DELETE FROM comments WHERE publication_id IN 
                (SELECT id FROM publications WHERE clan_id = ?)`,
            [clanId],
            (err) => {
              if (err) {
                console.error("Error al eliminar comentarios:", err)
                db.run("ROLLBACK")
                return res.status(500).send("Error al eliminar el clan")
              }

              // 3. Eliminar todas las vistas de publicaciones
              db.run(
                `DELETE FROM publication_views WHERE publication_id IN 
                  (SELECT id FROM publications WHERE clan_id = ?)`,
                [clanId],
                (err) => {
                  if (err) {
                    console.error("Error al eliminar vistas de publicaciones:", err)
                    db.run("ROLLBACK")
                    return res.status(500).send("Error al eliminar el clan")
                  }

                  // 4. Eliminar todas las publicaciones del clan
                  db.run("DELETE FROM publications WHERE clan_id = ?", [clanId], (err) => {
                    if (err) {
                      console.error("Error al eliminar publicaciones:", err)
                      db.run("ROLLBACK")
                      return res.status(500).send("Error al eliminar el clan")
                    }

                    // 5. Eliminar todos los mensajes del clan
                    db.run("DELETE FROM messages WHERE clan_id = ?", [clanId], (err) => {
                      if (err) {
                        console.error("Error al eliminar mensajes:", err)
                        db.run("ROLLBACK")
                        return res.status(500).send("Error al eliminar el clan")
                      }

                      // 6. Eliminar todos los baneos del clan
                      db.run("DELETE FROM clan_bans WHERE clan_id = ?", [clanId], (err) => {
                        if (err) {
                          console.error("Error al eliminar baneos:", err)
                          db.run("ROLLBACK")
                          return res.status(500).send("Error al eliminar el clan")
                        }

                        // 7. Eliminar todos los miembros del clan
                        db.run("DELETE FROM clan_members WHERE clan_id = ?", [clanId], (err) => {
                          if (err) {
                            console.error("Error al eliminar miembros:", err)
                            db.run("ROLLBACK")
                            return res.status(500).send("Error al eliminar el clan")
                          }

                          // 8. Finalmente, eliminar el clan
                          db.run("DELETE FROM clans WHERE id = ?", [clanId], (err) => {
                            if (err) {
                              console.error("Error al eliminar clan:", err)
                              db.run("ROLLBACK")
                              return res.status(500).send("Error al eliminar el clan")
                            }

                            // Confirmar la transacción
                            db.run("COMMIT")

                            // Notificar a todos los clientes conectados que el clan ha sido eliminado
                            if (io) {
                              io.emit("clanDeleted", { clanId })
                            }

                            // Redirigir al dashboard
                            res.redirect("/dashboard")
                          })
                        })
                      })
                    })
                  })
                },
              )
            },
          )
        },
      )
    })
  })
})

// alguien le estas cosas?

// Al inicio de tu archivo de servidor:
const onlineUsers = {}

// En el bloque de conexión de Socket.IO:
io.on("connection", (socket) => {
  // Asegurarse de que el ID de usuario se guarde correctamente en el objeto socket
  socket.on("registerUser", (userId) => {
    // Convertir el userId a número para asegurar que la comparación sea correcta
    socket.userId = Number.parseInt(userId, 10)
    onlineUsers[userId] = (onlineUsers[userId] || 0) + 1
    io.emit("userStatusUpdate", onlineUsers)
    console.log("Usuario registrado en socket:", socket.userId)

    // Unir al usuario a su sala personal para notificaciones directas
    socket.join(`user_${userId}`)
  })

  socket.on("disconnect", () => {
    if (socket.userId) {
      onlineUsers[socket.userId]--
      if (onlineUsers[socket.userId] <= 0) {
        delete onlineUsers[socket.userId]
      }
      io.emit("userStatusUpdate", onlineUsers)
    }
  })

  socket.on("joinClan", (clan_id) => {
    const room = `clan_${clan_id}`
    socket.join(room)
    // Emitir la cantidad actual de miembros en la sala
    const membersCount = io.sockets.adapter.rooms.get(room)?.size || 0
    io.to(room).emit("updateMembersCount", { count: membersCount })
  })

  // Manejar el estado de "escribiendo"
  socket.on("typing", (data) => {
    const { clan_id, user_id, isTyping } = data
    const room = `clan_${clan_id}`

    // Emitir el estado de escritura a todos los miembros del clan
    io.to(room).emit("userTyping", { user_id, isTyping })
  })

  socket.on("sendMessage", (data) => {
    const { clan_id, user_id, message } = data

    // Verificar si el usuario está baneado antes de enviar el mensaje
    db.get("SELECT * FROM clan_bans WHERE clan_id = ? AND user_id = ?", [clan_id, user_id], (err, ban) => {
      if (ban) {
        // Si está baneado, enviar un mensaje de error solo al usuario
        socket.emit("messageFailed", {
          error: "No puedes enviar mensajes porque has sido baneado del clan.",
        })
        return
      }

      // Verificar si el usuario sigue siendo miembro del clan
      db.get("SELECT * FROM clan_members WHERE clan_id = ? AND user_id = ?", [clan_id, user_id], (err, membership) => {
        // También verificar si es el propietario
        db.get("SELECT * FROM clans WHERE id = ? AND owner_id = ?", [clan_id, user_id], (err, ownership) => {
          if (!membership && !ownership) {
            // Si no es miembro ni propietario, enviar un mensaje de error
            socket.emit("messageFailed", {
              error: "No puedes enviar mensajes porque ya no eres miembro del clan.",
            })
            return
          }

          // Si todo está bien, proceder con el envío del mensaje
          db.get("SELECT name, profile_picture FROM users WHERE id = ?", [user_id], (err, user) => {
            if (err || !user) return

            db.run(
              "INSERT INTO messages (clan_id, user_id, message) VALUES (?, ?, ?)",
              [clan_id, user_id, message],
              function (err) {
                if (!err) {
                  const messageId = this.lastID
                  const timestamp = new Date().toLocaleString("es-ES", {
                    year: "numeric",
                    month: "2-digit",
                    day: "2-digit",
                    hour: "2-digit",
                    minute: "2-digit",
                  })

                  io.to(`clan_${clan_id}`).emit("newMessage", {
                    id: messageId,
                    user_id: user_id,
                    user: user.name,
                    message,
                    profile_picture: user.profile_picture,
                    timestamp: timestamp,
                  })
                }
              },
            )
          })
        })
      })
    })
  })

  // Manejar edición de mensajes
  socket.on("editMessage", (data) => {
    const { clan_id, message_id, new_message } = data

    // Verificar si el usuario está baneado
    db.get("SELECT * FROM clan_bans WHERE clan_id = ? AND user_id = ?", [clan_id, socket.userId], (err, ban) => {
      if (ban) {
        socket.emit("editFailed", {
          error: "No puedes editar mensajes porque has sido baneado del clan.",
        })
        return
      }

      // Convertir message_id a número para asegurar que la comparación sea correcta
      const messageIdNum = Number.parseInt(message_id, 10)

      // Verificar que el mensaje pertenece al usuario
      db.get("SELECT user_id FROM messages WHERE id = ? AND clan_id = ?", [messageIdNum, clan_id], (err, message) => {
        if (err) {
          console.error("Error al verificar mensaje:", err)
          return
        }

        if (!message) {
          console.error("Mensaje no encontrado")
          return
        }

        // Convertir user_id a número para comparar correctamente
        const messageUserId = Number.parseInt(message.user_id, 10)
        const socketUserId = Number.parseInt(socket.userId, 10)

        console.log("Comparando IDs:", messageUserId, socketUserId, messageUserId === socketUserId)

        if (messageUserId !== socketUserId) {
          console.error("El usuario no es propietario del mensaje", messageUserId, socketUserId)
          socket.emit("editFailed", {
            error: "No puedes editar este mensaje porque no eres su propietario.",
          })
          return
        }

        // Actualizar el mensaje
        db.run("UPDATE messages SET message = ? WHERE id = ?", [new_message, messageIdNum], (err) => {
          if (err) {
            console.error("Error al actualizar mensaje:", err)
            socket.emit("editFailed", {
              error: "Error al editar el mensaje.",
            })
            return
          }

          io.to(`clan_${clan_id}`).emit("messageEdited", {
            message_id: messageIdNum,
            new_message,
          })
        })
      })
    })
  })

  // Manejar eliminación de mensajes
  socket.on("deleteMessage", (data) => {
    const { clan_id, message_id } = data

    // Verificar si el usuario está baneado
    db.get("SELECT * FROM clan_bans WHERE clan_id = ? AND user_id = ?", [clan_id, socket.userId], (err, ban) => {
      if (ban) {
        socket.emit("deleteFailed", {
          error: "No puedes eliminar mensajes porque has sido baneado del clan.",
        })
        return
      }

      // Convertir message_id a número para asegurar que la comparación sea correcta
      const messageIdNum = Number.parseInt(message_id, 10)

      // Verificar que el mensaje pertenece al usuario
      db.get("SELECT user_id FROM messages WHERE id = ? AND clan_id = ?", [messageIdNum, clan_id], (err, message) => {
        if (err) {
          console.error("Error al verificar mensaje:", err)
          return
        }

        if (!message) {
          console.error("Mensaje no encontrado")
          return
        }

        // Convertir user_id a número para comparar correctamente
        const messageUserId = Number.parseInt(message.user_id, 10)
        const socketUserId = Number.parseInt(socket.userId, 10)

        console.log("Comparando IDs para eliminar:", messageUserId, socketUserId, messageUserId === socketUserId)

        if (messageUserId !== socketUserId) {
          console.error("El usuario no es propietario del mensaje", messageUserId, socketUserId)
          socket.emit("deleteFailed", {
            error: "No puedes eliminar este mensaje porque no eres su propietario.",
          })
          return
        }

        // Eliminar el mensaje
        db.run("DELETE FROM messages WHERE id = ?", [messageIdNum], (err) => {
          if (err) {
            console.error("Error al eliminar mensaje:", err)
            socket.emit("deleteFailed", {
              error: "Error al eliminar el mensaje.",
            })
            return
          }

          io.to(`clan_${clan_id}`).emit("messageDeleted", {
            message_id: messageIdNum,
          })
        })
      })
    })
  })

  socket.on("disconnect", () => {
    // Recorrer todas las salas a las que pertenecía el socket (excluyendo la sala privada del socket)
    socket.rooms.forEach((room) => {
      if (room.startsWith("clan_")) {
        const count = io.sockets.adapter.rooms.get(room)?.size || 0
        io.to(room).emit("updateMembersCount", { count })
      }
    })
  })
})

// Cerrar sesión
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/")
  })
})

// Ruta para obtener el conteo de clanes del usuario
app.get("/clan-count", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "No autorizado" })

  getUserClanCount(req.session.user.id, (err, count) => {
    if (err) return res.status(500).json({ error: "Error al obtener el conteo" })
    res.json({ count })
  })
})

app.get("/api/user/:id", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "No autorizado" })

  const userId = req.params.id

  db.get(
    "SELECT id, name, email, profile_picture, banner, description FROM users WHERE id = ?",
    [userId],
    (err, user) => {
      if (err) return res.status(500).json({ error: "Error al obtener datos del usuario" })
      if (!user) return res.status(404).json({ error: "Usuario no encontrado" })

      // Enviar los datos del usuario
      res.json({
        id: user.id,
        name: user.name,
        email: user.email,
        profile_picture: user.profile_picture,
        banner: user.banner,
        description: user.description || "Este usuario no ha añadido una descripción.",
      })
    },
  )
})

// Añadir después de las otras rutas, antes de iniciar el servidor
app.use("/publicacion", publicacionModule.router)

// 🔹 INICIAR SERVIDOR
server.listen(20943, () => console.log("Servidor corriendo en http://localhost:20943"))

