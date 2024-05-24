const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const forge = require('node-forge');
const cookieParser = require('cookie-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(cookieParser());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'usersweb'
});

db.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err);
    return;
  }
  console.log('Connected to the database.');
});



app.post('/getUserRole', (req, res) => {
  const { username } = req.body;
  const query = 'SELECT role FROM users WHERE username = ?';

  db.query(query, [username], (err, results) => {
    if (err) {
      return res.status(500).send(err);
    }
    if (results.length > 0) {
      res.send({ success: true, role: results[0].role });
    } else {
      res.send({ success: false, message: 'User not found' });
    }
  });
});


app.get('/publicKey', (req, res) => {
  fs.readFile('publicKey.pem', (err, data) => {
    if (err) {
      console.error('Error reading publicKey.pem:', err);
      res.status(500).send('Internal server error');
      return;
    }
    res.setHeader('Content-Type', 'text/plain');
    res.send(data);
  });
});



app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM users WHERE username = ?';

  db.query(query, [username], (err, results) => {
    if (err) {
      return res.status(500).send(err);
    }
    if (results.length > 0) {
      const user = results[0];
      const privateKeyPem = fs.readFileSync('privateKey.pem', 'utf8');
      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

      try {
        const encryptedPassword = forge.util.decode64(user.password);
        const decryptedPassword = privateKey.decrypt(encryptedPassword, 'RSA-OAEP', {
          md: forge.md.sha256.create(),
        });
        const decryptedPasswordUtf8 = forge.util.decodeUtf8(decryptedPassword);

        console.log('---------------------------------------------------');
        console.log('password', password);
        console.log('---------------------------------------------------');
        console.log('Decrypted stored password:', decryptedPasswordUtf8);
        console.log('---------------------------------------------------');

        if (decryptedPasswordUtf8 === password) {
          res.send({ success: true });
        } else {
          res.send({ success: false });
        }
      } catch (decryptionError) {
        console.error('Error decrypting password:', decryptionError);
        res.status(500).send('Error decrypting password');
      }
    } else {
      res.send({ success: false });
    }
  });
});

app.get('/tipo_docs', (req, res) => {
  db.query('SELECT * FROM tipo_doc', (err, results) => {
    if (err) {
      console.error('Error fetching tipo_docs:', err);
      res.status(500).send(err);
      return;
    }
    res.json(results);
  });
});

app.get('/tipo_docs_2', (req, res) => {
  db.query('SELECT * FROM tipo_doc WHERE estado = 1', (err, results) => {
    if (err) {
      console.error('Error fetching tipo_docs:', err);
      res.status(500).send(err);
      return;
    }
    res.json(results);
  });
});


app.get('/generos', (req, res) => {
  db.query('SELECT * FROM generos', (err, results) => {
    if (err) {
      console.error('Error fetching generos:', err);
      res.status(500).send(err);
      return;
    }
    res.json(results);
  });
});


app.get('/roles', (req, res) => {
  const { estado } = req.query;
  db.query('SELECT * FROM roles WHERE estado = ?', [estado], (err, results) => {
    if (err) {
      console.error('Error fetching roles:', err);
      res.status(500).send(err);
      return;
    }
    res.json(results);
  });
});

// Ver
app.get('/users', (req, res) => {
  db.query('SELECT * FROM users', (err, results) => {
    if (err) {
      console.error('Error fetching users:', err); // Mostrar el error específico
      res.status(500).send({ success: false, error: 'Error fetching users' });
      return;
    }
    res.json(results);
  });
});

// Eliminar
app.put('/actualizar_estado_usuario/:id', (req, res) => {
  const { id } = req.params;
  const estado = 0; // Estado inactivo

  const query = 'UPDATE users SET estado = ? WHERE id = ?';
  db.query(query, [estado, id], (err, result) => {
    if (err) {
      console.error('Error updating user state:', err); // Mostrar el error específico
      res.status(500).send({ success: false, error: 'Error updating user state' });
      return;
    }
    res.send({ success: true });
  });
});

// Editar
app.get('/usuario/:id', (req, res) => {
  const { id } = req.params;
  const query = 'SELECT * FROM users WHERE id = ?';

  db.query(query, [id], (err, result) => {
    if (err) {
      console.error('Error fetching user data:', err);
      res.status(500).send(err);
      return;
    }
    if (result.length > 0) {
      const user = result[0];
      
      try {
        const privateKeyPem = fs.readFileSync('privateKey.pem', 'utf8');
        const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
        const encryptedPassword = forge.util.decode64(user.password);
        const decryptedPassword = privateKey.decrypt(encryptedPassword, 'RSA-OAEP', {
          md: forge.md.sha256.create(),
        });
        const decryptedPasswordUtf8 = forge.util.decodeUtf8(decryptedPassword);

        user.password = decryptedPasswordUtf8;
        res.json(user);
      } catch (decryptionError) {
        console.error('Error decrypting password:', decryptionError);
        res.status(500).send('Error decrypting password');
      }
    } else {
      res.status(404).send({ message: 'User not found' });
    }
  });
});

app.get('/usuario_2/:id', (req, res) => {
  const { id } = req.params;
  const query = 'SELECT * FROM users WHERE id = ?';

  db.query(query, [id], (err, result) => {
    if (err) {
      console.error('Error fetching user data:', err);
      res.status(500).send(err);
      return;
    }
    if (result.length > 0) {
      const user = result[0];
      
      try {
        const privateKeyPem = fs.readFileSync('privateKey.pem', 'utf8');
        const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
        const encryptedPassword = forge.util.decode64(user.password);
        const decryptedPassword = privateKey.decrypt(encryptedPassword, 'RSA-OAEP', {
          md: forge.md.sha256.create(),
        });
        const decryptedPasswordUtf8 = forge.util.decodeUtf8(decryptedPassword);

        user.password = decryptedPasswordUtf8;
        res.json(user);
      } catch (decryptionError) {
        console.error('Error decrypting password:', decryptionError);
        res.status(500).send('Error decrypting password');
      }
    } else {
      res.status(404).send({ message: 'User not found' });
    }
  });
});
// Actualizar usuario
app.put('/usuario/:id', (req, res) => {
  const { id } = req.params;
  const { username, password, nombre, apellido, tipo_doc, n_doc, genero, email, telefono, role, fecha_naci, estado } = req.body;

  const query = `
    UPDATE users 
    SET 
      username = ?, 
      password = ?, 
      nombre = ?, 
      apellido = ?, 
      tipo_doc = ?, 
      n_doc = ?, 
      genero = ?, 
      email = ?, 
      telefono = ?, 
      role = ?, 
      fecha_naci = ?, 
      estado = ? 
    WHERE id = ?`;
  
  const values = [username, password, nombre, apellido, tipo_doc, n_doc, genero, email, telefono, role, fecha_naci, estado, id];


    // Si no hay dos SuperAdmin o el usuario no está cambiando su rol a SuperAdmin, continuar con la actualización
    db.query(query, values, (err, result) => {
      if (err) {
        console.error('Error updating user:', err);
        return res.status(500).send({ success: false, error: err });
      }
      res.send({ success: true });
    });
  
});

app.put('/usuario_2/:id', (req, res) => {
  const { id } = req.params;
  const { username, password, nombre, apellido, tipo_doc, n_doc, genero, email, telefono, role, fecha_naci, estado } = req.body;

  const query = `
    UPDATE users 
    SET 
      username = ?, 
      password = ?, 
      nombre = ?, 
      apellido = ?, 
      tipo_doc = ?, 
      n_doc = ?, 
      genero = ?, 
      email = ?, 
      telefono = ?, 
      role = ?, 
      fecha_naci = ?, 
      estado = ? 
    WHERE id = ?`;
  
  const values = [username, password, nombre, apellido, tipo_doc, n_doc, genero, email, telefono, role, fecha_naci, estado, id];
  
  const countSuperAdminQuery = 'SELECT COUNT(*) AS superAdminCount FROM users WHERE role = 2 AND estado=1';

  db.query(countSuperAdminQuery, (err, results) => {
    if (err) {
      console.error('Error counting SuperAdmin:', err);
      return res.status(500).send({ success: false, error: err });
    }

    const superAdminCount = results[0].superAdminCount;
    console.log('Contador' ,superAdminCount);
    console.log('Role', role );
    // Verificar si el usuario está cambiando su rol a SuperAdmin y si ya hay dos SuperAdmin en la base de datos
    if (role == 2 && superAdminCount >= 2) {
      console.log('Entro');
      return res.status(403).send({ success: false, message: 'Ya se han creado el máximo de SuperAdmin' });
    }

    // Si no hay dos SuperAdmin o el usuario no está cambiando su rol a SuperAdmin, continuar con la actualización
    db.query(query, values, (err, result) => {
      if (err) {
        console.error('Error updating user:', err);
        return res.status(500).send({ success: false, error: err });
      }
      res.send({ success: true });
    });
  });
});

app.post('/register', (req, res) => {
  const {
    username, password, nombre, apellido, tipo_doc, n_doc,
    id_genero, email, telefono, id_role, fecha_naci, estado
  } = req.body;

  // Query para contar el número de SuperAdmin
  const countSuperAdminQuery = 'SELECT COUNT(*) AS superAdminCount FROM users WHERE role = 2';

  // Query para insertar un nuevo usuario
  const insertUserQuery = 'INSERT INTO users (username, password, nombre, apellido, tipo_doc, n_doc, genero, email, telefono, role, fecha_naci, estado) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
  const values = [username, password, nombre, apellido, tipo_doc, n_doc, id_genero, email, telefono, id_role, fecha_naci, estado];

  db.query(countSuperAdminQuery, (err, results) => {
    if (err) {
      console.error('Error counting SuperAdmin:', err);
      return res.status(500).send({ success: false, error: err });
    }

    const superAdminCount = results[0].superAdminCount;
    console.log("contador: ",superAdminCount);
    console.log("role: ",id_role);
    // Verificar si el número de SuperAdmin es menor que 2
    if (id_role == 2) {
      if(superAdminCount < 2){
        // Si es menor, permitir el registro del nuevo usuario
        db.query(insertUserQuery, values, (err, result) => {
        console.log("Entro: ");
          if (err) {
            console.error('Error registering user:', err);
            return res.status(500).send({ success: false, error: err });
          }
          res.send({ success: true });
        });
      }else {
        // Si es mayor o igual a 2, indicar que ya se han creado el máximo de SuperAdmin
        res.status(403).send({ success: false, message: 'Ya se han creado el máximo de SuperAdmin' });
      }
    }else{
      // Si es menor, permitir el registro del nuevo usuario
      db.query(insertUserQuery, values, (err, result) => {
      console.log("Diferente a super admin");
        if (err) {
          console.error('Error registering user:', err);
          return res.status(500).send({ success: false, error: err });
        }
        res.send({ success: true });
      });
    }
  });
});

// Obtener un usuario específico por ID
app.get('/users/:id', (req, res) => {
  const userId = req.params.id;
  const query = 'SELECT * FROM users WHERE id = ?';
  db.query(query, [userId], (err, result) => {
    if (err) {
      console.error('Error fetching user:', err);
      res.status(500).send(err);
      return;
    }
    res.json(result);
  });
});

app.post('/tipo_docs', (req, res) => {
  const { tipo, usuario } = req.body;
  const query = 'INSERT INTO tipo_doc (tipo, fecha_mod, usuario, estado) VALUES (?, NOW(), ?, 1)';
  db.query(query, [tipo, usuario], (err, result) => {
    if (err) {
      console.error('Error creating tipo_doc:', err);
      res.status(500).send(err);
      return;
    }
    res.send({ success: true });
  });
});

app.get('/tipo_docs', (req, res) => {
  const query = 'SELECT * FROM tipo_doc WHERE estado = 1';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching tipo_docs:', err);
      res.status(500).send(err);
      return;
    }
    res.json(results);
  });
});

// Read (Leer un tipo_doc específico por ID)
app.get('/tipo_docs/:id', (req, res) => {
  const id_doc = req.params.id;
  const query = 'SELECT * FROM tipo_doc WHERE id_doc = ? AND estado = 1';
  db.query(query, [id_doc], (err, result) => {
    if (err) {
      console.error('Error fetching tipo_doc:', err);
      res.status(500).send(err);
      return;
    }
    res.json(result);
  });
});

// Update (Actualizar)
app.put('/tipo_docs/:id', (req, res) => {
  const id_doc = req.params.id;
  const { tipo, usuario } = req.body;
  const query = 'UPDATE tipo_doc SET tipo = ?, fecha_mod = NOW(), usuario = ? WHERE id_doc = ? AND estado = 1';
  db.query(query, [tipo, usuario, id_doc], (err, result) => {
    if (err) {
      console.error('Error updating tipo_doc:', err);
      res.status(500).send(err);
      return;
    }
    res.send({ success: true });
  });
});

app.delete('/tipo_docs/:id', (req, res) => {
  const id_doc = req.params.id;
  const { usuario } = req.body;
  const query = 'UPDATE tipo_doc SET estado = 0, fecha_mod = NOW(), usuario = ? WHERE id_doc = ?';
  db.query(query, [usuario, id_doc], (err, result) => {
    if (err) {
      console.error('Error deleting tipo_doc:', err);
      res.status(500).send(err);
      return;
    }
    res.send({ success: true });
  });
});

app.put('/tipo_docs/:id/activate', (req, res) => {
  const id_doc = req.params.id;
  const { usuario } = req.body;
  const query = 'UPDATE tipo_doc SET estado = 1, fecha_mod = NOW(), usuario = ? WHERE id_doc = ?';
  db.query(query, [usuario, id_doc], (err, result) => {
    if (err) {
      console.error('Error activating tipo_doc:', err);
      res.status(500).send(err);
      return;
    }
    res.send({ success: true });
  });
});


//=================================================
//Agregué este paralos roles
app.get('/roles', (req, res) => {
  const { estado } = req.query;
  const query = estado ? 'SELECT * FROM roles WHERE estado = ?' : 'SELECT * FROM roles';
  const params = estado ? [estado] : [];

  db.query(query, params, (err, results) => {
    if (err) {
      console.error('Error fetching roles:', err);
      res.status(500).send(err);
      return;
    }
    res.json(results);
  });
});


app.put('/actualizar_estado_roles/:id', (req, res) => {
  const { id } = req.params;
  const estado = 0; // Estado inactivo
  console.error('Entró aquí');

  const query = 'UPDATE roles SET estado = ? WHERE id_role = ?';
  db.query(query, [estado, id], (err, result) => {
    if (err) {
      console.error('Error updating user state:', err);
      res.status(500).send({ success: false, error: err });
      return;
    }
    res.send({ success: true });
  });
});

app.put('/activar/:id', (req, res) => {
  const { id } = req.params;
  const estado = 1; // Estado activo
  console.error('Entró aquí');
  console.error(id);

  const query = 'UPDATE roles SET estado = ? WHERE id_role = ?';
  db.query(query, [estado, id], (err, result) => {
    if (err) {
      console.error('Error updating user state:', err);
      res.status(500).send({ success: false, error: err });
      return;
    }
    res.send({ success: true });
  });
});


app.get('/roles/:id', (req, res) => {
  const roleId = req.params.id;
  db.query('SELECT * FROM roles WHERE id_role = ?', [roleId], (err, results) => {
    if (err) {
      console.error('Error fetching role:', err);
      res.status(500).send(err);
      return;
    }
    if (results.length === 0) {
      res.status(404).send('Role not found');
      return;
    }
    res.json(results[0]);
  });
});


app.put('/roles/:id', (req, res) => {
  const roleId = req.params.id;
  const { tipo, estado } = req.body;
  db.query('UPDATE roles SET tipo = ?, estado = ? WHERE id_role = ?', [tipo, estado, roleId], (err, results) => {
    if (err) {
      console.error('Error updating role:', err);
      res.status(500).send(err);
      return;
    }
    if (results.affectedRows === 0) {
      res.status(404).send('Role not found');
      return;
    }
    res.send('Role updated successfully');
  });
});

app.post('/roles/add', (req, res) => {
  const { tipo, estado } = req.body;
  db.query('INSERT INTO roles (tipo, estado) VALUES (?, ?)', [tipo, estado], (err, results) => {
    if (err) {
      console.error('Error adding role:', err);
      res.status(500).send(err);
      return;
    }
    res.send('Role added successfully');
  });
});


app.get('/roles', (req, res) => {
  const { estado } = req.query;
  db.query('SELECT * FROM roles WHERE estado = ?', [estado], (err, results) => {
    if (err) {
      console.error('Error fetching roles:', err);
      res.status(500).send(err);
      return;
    }
    res.json(results);
  });
});

app.get('/rolesTipo', (req, res) => {
  const { tipo } = req.query;

  if (!tipo) {
    res.status(400).send({ success: false, error: 'Tipo de rol no especificado' });
    return;
  }

  const query = 'SELECT * FROM roles WHERE tipo = ?';
  db.query(query, [tipo], (err, results) => {
    if (err) {
      console.error('Error fetching roles:', err);
      res.status(500).send({ success: false, error: err });
      return;
    }

    res.send(results);
  });
});


app.get('/tiposRoles', (req, res) => {
  const query = 'SELECT DISTINCT tipo FROM roles';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching role types:', err);
      res.status(500).send({ success: false, error: err });
      return;
    }

    res.send(results);
  });
});

app.get('/rolesBuscar', (req, res) => {
  const tipo = req.query.tipo; // Obtenemos el parámetro tipo de la consulta GET
  
  const query = 'SELECT * FROM roles WHERE tipo = ?';
  db.query(query, [tipo], (err, results) => {
    if (err) {
      console.error('Error fetching roles:', err);
      res.status(500).send({ success: false, error: err });
      return;
    }

    res.send(results);
  });
});



//Buscar
app.get('/buscar_usuario_por_documento/:n_doc', (req, res) => {
  const { n_doc } = req.params;
  const query = 'SELECT * FROM users WHERE n_doc = ?';

  db.query(query, [n_doc], (err, results) => {
    if (err) {
      console.error('Error searching user by document:', err);
      res.status(500).send('Error searching user by document');
      return;
    }
    if (results.length > 0) {
      res.json(results[0]);
    } else {
      res.status(404).send('User not found');
    }
  });
});
// Ver usuarios por estado
app.get('/users_by_estado', (req, res) => {
  const { estado } = req.query;
  const query = estado !== undefined ? 'SELECT * FROM users WHERE estado = ?' : 'SELECT * FROM users';

  db.query(query, estado ? [estado] : [], (err, results) => {
    if (err) {
      console.error('Error fetching users:', err);
      res.status(500).send({ success: false, error: 'Error fetching users' });
      return;
    }
    res.json(results);
  });
});

app.put('/actualizar_estado_usuario_2/:id', (req, res) => {
  const { id } = req.params;
  const { estado } = req.body; // Obtener el estado desde el cuerpo de la solicitud

  if (estado == 1) { // Solo verificar si se está activando el usuario
    const countSuperAdminQuery = 'SELECT COUNT(*) AS superAdminCount FROM users WHERE role = 2 AND estado = 1';
    const userQuery = 'SELECT role FROM users WHERE id = ?';

    db.query(userQuery, [id], (err, results) => {
      if (err) {
        console.error('Error fetching user role:', err);
        return res.status(500).send({ success: false, error: 'Error fetching user role' });
      }

      if (results.length === 0) {
        return res.status(404).send({ success: false, message: 'User not found' });
      }

      const userRole = results[0].role;

      if (userRole == 2) { // Si el usuario es SuperAdmin
        db.query(countSuperAdminQuery, (err, results) => {
          if (err) {
            console.error('Error counting SuperAdmin:', err);
            return res.status(500).send({ success: false, error: 'Error counting SuperAdmin' });
          }

          const superAdminCount = results[0].superAdminCount;

          if (superAdminCount >= 2) {
            return res.status(403).send({ success: false, message: 'Ya se han creado el máximo de SuperAdmin' });
          }

          // Si no hay más de dos SuperAdmin, continuar con la activación
          const query = 'UPDATE users SET estado = ? WHERE id = ?';
          db.query(query, [estado, id], (err, result) => {
            if (err) {
              console.error('Error updating user state:', err);
              return res.status(500).send({ success: false, error: 'Error updating user state' });
            }
            res.send({ success: true, message: 'User activated successfully' });
          });
        });
      } else {
        // Si el usuario no es SuperAdmin, simplemente actualizar el estado
        const query = 'UPDATE users SET estado = ? WHERE id = ?';
        db.query(query, [estado, id], (err, result) => {
          if (err) {
            console.error('Error updating user state:', err);
            return res.status(500).send({ success: false, error: 'Error updating user state' });
          }
          res.send({ success: true, message: 'User activated successfully' });
        });
      }
    });
  } else {
    // Si se está desactivando el usuario, simplemente actualizar el estado
    const query = 'UPDATE users SET estado = ? WHERE id = ?';
    db.query(query, [estado, id], (err, result) => {
      if (err) {
        console.error('Error updating user state:', err);
        return res.status(500).send({ success: false, error: 'Error updating user state' });
      }
      res.send({ success: true, message: 'User deactivated successfully' });
    });
  }
});
// Verificar si el username ya está registrado y si el usuario está inactivo
app.get('/verificar_username', (req, res) => {
  const { username } = req.query;

  if (!username) {
    return res.status(400).send({ success: false, error: 'Username no proporcionado' });
  }

  const query = 'SELECT * FROM users WHERE username = ?';

  db.query(query, [username], (err, results) => {
    if (err) {
      console.error('Error checking username:', err);
      return res.status(500).send({ success: false, error: 'Error checking username' });
    }

    if (results.length > 0) {
      const user = results[0];
      if (user.estado == 0) {
        res.send({ success: true, message: 'Username registrado e inactivo', user });
      } else {
        res.send({ success: false, message: 'Username ya está registrado y activo' });
      }
    } else {
      res.send({ success: true, message: 'Username disponible' });
    }
  });
});



//===========================================



app.get('/getUserRole', (req, res) => {
  const { username } = req.query; // Cambiar a req.query para aceptar parámetros de URL
  const query = 'SELECT role FROM users WHERE username = ?';

  db.query(query, [username], (err, results) => {
    if (err) {
      return res.status(500).send(err);
    }
    if (results.length > 0) {
      res.send({ success: true, role: results[0].role });
    } else {
      res.send({ success: false, message: 'User not found' });
    }
  });
});

app.get('/rolesVer', (req, res) => {
  db.query('SELECT * FROM roles', (err, results) => {
    if (err) {
      console.error('Error fetching roles:', err);
      res.status(500).send(err);
      return;
    }
    res.json(results);
  });
});

// Obtener ID de usuario por nombre de usuario
app.get('/userId', (req, res) => {
  const { username } = req.query;
  const query = 'SELECT id FROM users WHERE username = ?';

  db.query(query, [username], (err, results) => {
    if (err) {
      return res.status(500).send(err);
    }
    if (results.length > 0) {
      res.send({ success: true, id: results[0].id });
    } else {
      res.send({ success: false, message: 'User not found' });
    }
  });
});

app.listen(5001, () => {
  console.log('Server running on port 5000');
});
