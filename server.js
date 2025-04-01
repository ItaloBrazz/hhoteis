const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();

// Configuração do banco de dados SQLite para Vercel
const dbPath = process.env.NODE_ENV === 'production' 
  ? '/tmp/banco.db' 
  : './banco.db';

// Conecta ao banco de dados
const db = new sqlite3.Database(dbPath);

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Rotas estáticas
app.get('/cadastro', (req, res) => {
  res.sendFile(path.join(__dirname, 'cadastro.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Rotas de API
app.post('/auth/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Preencha todos os campos!' });
  }

  try {
    db.get('SELECT email FROM usuarios WHERE email = ?', [email], async (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Erro no servidor' });
      }
      
      if (row) {
        return res.status(400).json({ error: 'E-mail já cadastrado!' });
      }

      const salt = await bcrypt.genSalt(10);
      const senhaHash = await bcrypt.hash(password, salt);

      db.run(
        'INSERT INTO usuarios (login, senha, email) VALUES (?, ?, ?)',
        [name, senhaHash, email],
        (err) => {
          if (err) {
            console.error(err);
            return res.status(500).json({ error: 'Erro no servidor' });
          }
          res.json({ success: 'Cadastro realizado!' });
        }
      );
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Preencha todos os campos!' });
  }

  try {
    db.get('SELECT * FROM usuarios WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Erro no servidor' });
      }
      
      if (!user) {
        return res.status(404).json({ error: 'E-mail não cadastrado!' });
      }

      const senhaValida = await bcrypt.compare(password, user.senha);
      
      if (!senhaValida) {
        return res.status(401).json({ error: 'Senha incorreta!' });
      }

      res.json({ 
        success: 'Login realizado!',
        user: {
          id: user.id,
          login: user.login,
          email: user.email
        }
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

app.get('/auth/user/:id', (req, res) => {
  const userId = req.params.id;

  db.get('SELECT login, email FROM usuarios WHERE id = ?', [userId], (err, user) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Erro no servidor' });
    }
    if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

    res.json(user);
  });
});

app.delete('/auth/delete/:id', (req, res) => {
  const userId = req.params.id;

  db.run('DELETE FROM usuarios WHERE id = ?', [userId], function(err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Erro ao excluir o perfil.' });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado!' });
    }
    res.json({ success: 'Perfil excluído com sucesso!' });
  });
});

app.put('/auth/update', async (req, res) => {
  const { id, name, email, password } = req.body;

  if (!id || !name || !email) {
    return res.status(400).json({ error: 'ID, Nome e E-mail são obrigatórios!' });
  }

  try {
    let senhaHash = null;

    if (password) {
      const salt = await bcrypt.genSalt(10);
      senhaHash = await bcrypt.hash(password, salt);
    }

    db.run(
      `UPDATE usuarios SET login = ?, email = ?, senha = COALESCE(?, senha) WHERE id = ?`,
      [name, email, senhaHash, id],
      function (err) {
        if (err) {
          console.error(err);
          return res.status(500).json({ error: 'Erro ao atualizar o perfil.' });
        }
        if (this.changes === 0) {
          return res.status(404).json({ error: 'Usuário não encontrado!' });
        }
        res.json({ success: 'Perfil atualizado com sucesso!' });
      }
    );
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro no servidor' });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`✅ Servidor rodando em http://localhost:${PORT}`);
}).on('error', (err) => {
  console.error('❌ Falha ao iniciar o servidor:', err.message);
});


module.exports = app;