const express = require("express")
const sqlite3 = require("sqlite3").verbose()
const multer = require("multer")
const path = require("path")
const fs = require("fs")

// Configuración de multer para almacenar imágenes
const storage = multer.memoryStorage()
const upload = multer({ storage: storage })

// Inicializar router
const router = express.Router()
const db = new sqlite3.Database("./database.db")

// Variable para almacenar la referencia a io (se establecerá desde index.js)
let io

// Función para configurar Socket.IO (llamada desde index.js)
function setSocketIO(socketIO) {
  io = socketIO
}

// Crear tablas necesarias si no existen
db.serialize(() => {
  // Tabla de publicaciones
  db.run(`
    CREATE TABLE IF NOT EXISTS publications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      clan_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      description TEXT,
      image BLOB,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(clan_id) REFERENCES clans(id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `)

  // Tabla de comentarios
  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      publication_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      comment TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(publication_id) REFERENCES publications(id),
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `)

  // Tabla de likes
  db.run(`
    CREATE TABLE IF NOT EXISTS likes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      publication_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(publication_id) REFERENCES publications(id),
      FOREIGN KEY(user_id) REFERENCES users(id),
      UNIQUE(publication_id, user_id)
    )
  `)

  db.run(`
  CREATE TABLE IF NOT EXISTS publication_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    publication_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    viewed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(publication_id) REFERENCES publications(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    UNIQUE(publication_id, user_id)
  )
`)
})

// Middleware para verificar si el usuario está autenticado
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next()
  }
  res.redirect("/")
}

// Middleware para verificar si el usuario es el propietario del clan
function isOwner(req, res, next) {
  const clanId = req.params.clanId

  db.get("SELECT owner_id FROM clans WHERE id = ?", [clanId], (err, clan) => {
    if (err || !clan) {
      return res.status(404).send("Clan no encontrado")
    }

    if (clan.owner_id !== req.session.user.id) {
      return res.status(403).send("No tienes permiso para realizar esta acción")
    }

    next()
  })
}

// Middleware para verificar si el usuario es miembro del clan
function isMember(req, res, next) {
  const clanId = req.params.clanId
  const userId = req.session.user.id

  // Verificar si es propietario
  db.get("SELECT owner_id FROM clans WHERE id = ?", [clanId], (err, clan) => {
    if (err || !clan) {
      return res.status(404).send("Clan no encontrado")
    }

    if (clan.owner_id === userId) {
      return next()
    }

    // Verificar si es miembro
    db.get("SELECT * FROM clan_members WHERE clan_id = ? AND user_id = ?", [clanId, userId], (err, member) => {
      if (err || !member) {
        return res.status(403).send("No eres miembro de este clan")
      }

      // Verificar si está baneado
      db.get("SELECT * FROM clan_bans WHERE clan_id = ? AND user_id = ?", [clanId, userId], (err, ban) => {
        if (ban) {
          return res.status(403).send("Has sido baneado de este clan")
        }

        next()
      })
    })
  })
}

// Ruta para mostrar las publicaciones del clan
router.get("/:clanId", isAuthenticated, isMember, (req, res) => {
  const clanId = req.params.clanId
  const userId = req.session.user.id

  // Obtener información del clan
  db.get("SELECT * FROM clans WHERE id = ?", [clanId], (err, clan) => {
    if (err || !clan) {
      return res.status(404).send("Clan no encontrado")
    }

    const isOwner = clan.owner_id === userId

    // Obtener publicaciones del clan
    db.all(
      `SELECT p.*, u.name, u.profile_picture 
       FROM publications p 
       JOIN users u ON p.user_id = u.id 
       WHERE p.clan_id = ? 
       ORDER BY p.created_at DESC`,
      [clanId],
      (err, publications) => {
        if (err) {
          return res.status(500).send("Error al cargar publicaciones")
        }

        // Para cada publicación, obtener comentarios y likes
        const promises = publications.map((publication) => {
          return new Promise((resolve, reject) => {
            // Obtener comentarios
            db.all(
              `SELECT c.*, u.name, u.profile_picture 
               FROM comments c 
               JOIN users u ON c.user_id = u.id 
               WHERE c.publication_id = ? 
               ORDER BY c.created_at ASC`,
              [publication.id],
              (err, comments) => {
                if (err) {
                  reject(err)
                  return
                }

                publication.comments = comments

                // Obtener likes
                db.all("SELECT user_id FROM likes WHERE publication_id = ?", [publication.id], (err, likes) => {
                  if (err) {
                    reject(err)
                    return
                  }

                  publication.likes = likes.map((like) => like.user_id)
                  publication.likesCount = likes.length
                  publication.userLiked = likes.some((like) => like.user_id === userId)

                  resolve()
                })
              },
            )
          })
        })

        Promise.all(promises)
          .then(() => {
            res.render("publicacion", {
              clan,
              publications,
              user: req.session.user,
              isOwner,
            })
          })
          .catch((error) => {
            console.error("Error:", error)
            res.status(500).send("Error al cargar datos")
          })
      },
    )
  })
})

// Ruta para crear una nueva publicación (solo propietario)
router.post("/:clanId/crear", isAuthenticated, isOwner, upload.single("image"), (req, res) => {
  const clanId = req.params.clanId
  const userId = req.session.user.id
  const { description } = req.body
  const image = req.file ? req.file.buffer : null

  // Validar que haya al menos descripción o imagen
  if (!description && !image) {
    return res.status(400).send("La publicación debe tener al menos una descripción o una imagen")
  }

  // Insertar la publicación
  db.run(
    "INSERT INTO publications (clan_id, user_id, description, image) VALUES (?, ?, ?, ?)",
    [clanId, userId, description, image],
    function (err) {
      if (err) {
        console.error("Error al crear publicación:", err)
        return res.status(500).send("Error al crear la publicación")
      }

      const publicationId = this.lastID

      // Mark the publication as read for the creator
      db.run(
        "INSERT INTO publication_views (publication_id, user_id) VALUES (?, ?)",
        [publicationId, userId],
        (err) => {
          if (err) {
            console.error("Error marking publication as read for creator:", err)
          }
        },
      )

      // Obtener los datos completos de la publicación para emitir el evento
      db.get(
        `SELECT p.*, u.name, u.profile_picture 
         FROM publications p 
         JOIN users u ON p.user_id = u.id 
         WHERE p.id = ?`,
        [publicationId],
        (err, publication) => {
          if (!err && publication) {
            // Formatear la fecha para mostrarla correctamente
            const formattedDate = new Date(publication.created_at).toLocaleString("es-ES", {
              year: "numeric",
              month: "long",
              day: "numeric",
              hour: "2-digit",
              minute: "2-digit",
            })

            // Emitir evento de nueva publicación
            if (io) {
              io.to(`clan_${clanId}`).emit("newPublication", {
                ...publication,
                formatted_date: formattedDate,
                comments: [],
                likes: [],
                likesCount: 0,
                userLiked: false,
              })
            }
          }
        },
      )

      res.redirect(`/publicacion/${clanId}`)
    },
  )
})

// Ruta para eliminar una publicación (solo propietario)
router.post("/:clanId/eliminar/:publicationId", isAuthenticated, isOwner, (req, res) => {
  const publicationId = req.params.publicationId
  const clanId = req.params.clanId

  // Eliminar likes y comentarios primero
  db.serialize(() => {
    db.run("BEGIN TRANSACTION")

    db.run("DELETE FROM likes WHERE publication_id = ?", [publicationId])
    db.run("DELETE FROM comments WHERE publication_id = ?", [publicationId])

    // Finalmente eliminar la publicación
    db.run("DELETE FROM publications WHERE id = ?", [publicationId], (err) => {
      if (err) {
        db.run("ROLLBACK")
        console.error("Error al eliminar publicación:", err)
        return res.status(500).send("Error al eliminar la publicación")
      }

      db.run("COMMIT")

      // Emitir evento de publicación eliminada
      if (io) {
        io.to(`clan_${clanId}`).emit("publicationDeleted", {
          publication_id: publicationId,
        })
      }

      res.redirect(`/publicacion/${clanId}`)
    })
  })
})

// Ruta para añadir un comentario
router.post("/:clanId/comentar/:publicationId", isAuthenticated, isMember, (req, res) => {
  const publicationId = req.params.publicationId
  const clanId = req.params.clanId
  const userId = req.session.user.id
  const { comment } = req.body

  if (!comment || comment.trim() === "") {
    return res.status(400).send("El comentario no puede estar vacío")
  }

  db.run(
    "INSERT INTO comments (publication_id, user_id, comment) VALUES (?, ?, ?)",
    [publicationId, userId, comment],
    function (err) {
      if (err) {
        console.error("Error al añadir comentario:", err)
        return res.status(500).send("Error al añadir el comentario")
      }

      const commentId = this.lastID

      // Obtener los datos completos del comentario para emitir el evento
      db.get(
        `SELECT c.*, u.name, u.profile_picture 
         FROM comments c 
         JOIN users u ON c.user_id = u.id 
         WHERE c.id = ?`,
        [commentId],
        (err, commentData) => {
          if (!err && commentData) {
            // Formatear la fecha para mostrarla correctamente
            const formattedDate = new Date(commentData.created_at).toLocaleString("es-ES", {
              year: "numeric",
              month: "short",
              day: "numeric",
              hour: "2-digit",
              minute: "2-digit",
            })

            // Emitir evento de nuevo comentario
            if (io) {
              io.to(`clan_${clanId}`).emit("newComment", {
                ...commentData,
                formatted_date: formattedDate,
                publication_id: publicationId,
              })
            }
          }
        },
      )

      if (req.headers["x-requested-with"] === "XMLHttpRequest") {
        // Si es una petición AJAX, devolver respuesta JSON
        res.json({ success: true })
      } else {
        // Si es una petición normal, redirigir
        res.redirect(`/publicacion/${clanId}`)
      }
    },
  )
})

// Ruta para dar/quitar like
router.post("/:clanId/like/:publicationId", isAuthenticated, isMember, (req, res) => {
  const publicationId = req.params.publicationId
  const clanId = req.params.clanId
  const userId = req.session.user.id

  // Verificar si ya dio like
  db.get("SELECT * FROM likes WHERE publication_id = ? AND user_id = ?", [publicationId, userId], (err, like) => {
    if (err) {
      console.error("Error al verificar like:", err)
      return res.status(500).send("Error al procesar el like")
    }

    if (like) {
      // Ya dio like, quitar
      db.run("DELETE FROM likes WHERE publication_id = ? AND user_id = ?", [publicationId, userId], (err) => {
        if (err) {
          console.error("Error al quitar like:", err)
          return res.status(500).send("Error al quitar el like")
        }

        // Obtener el nuevo conteo de likes
        db.get("SELECT COUNT(*) as count FROM likes WHERE publication_id = ?", [publicationId], (err, result) => {
          const likesCount = result ? result.count : 0

          // Emitir evento de like eliminado
          if (io) {
            io.to(`clan_${clanId}`).emit("likeUpdated", {
              publication_id: publicationId,
              user_id: userId,
              liked: false,
              likesCount,
            })
          }

          if (req.headers["x-requested-with"] === "XMLHttpRequest") {
            // Si es una petición AJAX, devolver respuesta JSON
            res.json({ success: true, liked: false, likesCount })
          } else {
            // Si es una petición normal, redirigir
            res.redirect(`/publicacion/${clanId}`)
          }
        })
      })
    } else {
      // No ha dado like, añadir
      db.run("INSERT INTO likes (publication_id, user_id) VALUES (?, ?)", [publicationId, userId], (err) => {
        if (err) {
          console.error("Error al dar like:", err)
          return res.status(500).send("Error al dar like")
        }

        // Obtener el nuevo conteo de likes
        db.get("SELECT COUNT(*) as count FROM likes WHERE publication_id = ?", [publicationId], (err, result) => {
          const likesCount = result ? result.count : 0

          // Emitir evento de nuevo like
          if (io) {
            io.to(`clan_${clanId}`).emit("likeUpdated", {
              publication_id: publicationId,
              user_id: userId,
              liked: true,
              likesCount,
            })
          }

          if (req.headers["x-requested-with"] === "XMLHttpRequest") {
            // Si es una petición AJAX, devolver respuesta JSON
            res.json({ success: true, liked: true, likesCount })
          } else {
            // Si es una petición normal, redirigir
            res.redirect(`/publicacion/${clanId}`)
          }
        })
      })
    }
  })
})

// Ruta para servir imágenes de publicaciones
router.get("/imagen/:publicationId", (req, res) => {
  const publicationId = req.params.publicationId

  db.get("SELECT image FROM publications WHERE id = ?", [publicationId], (err, row) => {
    if (err || !row || !row.image) {
      return res.status(404).send("Imagen no encontrada")
    }

    res.writeHead(200, { "Content-Type": "image/png" })
    res.end(row.image)
  })
})

// pipipi
router.post("/:clanId/mark-read", isAuthenticated, isMember, (req, res) => {
  const clanId = req.params.clanId
  const userId = req.session.user.id

  // entren a mi discord
  db.all("SELECT id FROM publications WHERE clan_id = ?", [clanId], (err, publications) => {
    if (err) {
      console.error("Error getting publications:", err)
      return res.status(500).json({ error: "Error marking publications as read" })
    }

    if (publications.length === 0) {
      return res.json({ success: true })
    }

    const placeholders = publications.map(() => "(?, ?)").join(", ")
    const values = []

    publications.forEach((pub) => {
      values.push(pub.id, userId)
    })

    const query = `INSERT OR IGNORE INTO publication_views (publication_id, user_id) VALUES ${placeholders}`

    db.run(query, values, (err) => {
      if (err) {
        console.error("Error marking publications as read:", err)
        return res.status(500).json({ error: "Error marking publications as read" })
      }

      res.json({ success: true })
    })
  })
})

router.get("/:clanId/unread-count", isAuthenticated, (req, res) => {
  const clanId = req.params.clanId
  const userId = req.session.user.id

  db.get(
    `SELECT COUNT(*) as count 
     FROM publications p 
     WHERE p.clan_id = ? 
     AND NOT EXISTS (
       SELECT 1 FROM publication_views v 
       WHERE v.publication_id = p.id AND v.user_id = ?
     )`,
    [clanId, userId],
    (err, result) => {
      if (err) {
        console.error("Error getting unread count:", err)
        return res.status(500).json({ error: "Error getting unread count" })
      }

      res.json({ count: result ? result.count : 0 })
    },
  )
})

module.exports = {
  router,
  setSocketIO,
}

