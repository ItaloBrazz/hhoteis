const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const db = new sqlite3.Database('./banco.db');

// Configurações
app.use(cors()); 
app.use(express.json()); 
app.use(express.urlencoded({ extended: true })); // Para processar requisições urlencoded
app.use(express.static(path.join(__dirname, 'public')));

// Rota para a página de cadastro (GET)
app.get('/cadastro', (req, res) => {
    res.sendFile(path.join(__dirname, 'cadastro.html'));
});

// Rota para a página de login (GET)
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Rota de cadastro (POST)
app.post('/auth/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Preencha todos os campos!' });
    }

    try {
        db.get('SELECT email FROM usuarios WHERE email = ?', [email], async (err, row) => {
            if (err) throw err;
            
            if (row) {
                return res.status(400).json({ error: 'E-mail já cadastrado!' });
            }

            const salt = await bcrypt.genSalt(10);
            const senhaHash = await bcrypt.hash(password, salt);

            db.run(
                'INSERT INTO usuarios (login, senha, email) VALUES (?, ?, ?)',
                [name, senhaHash, email],
                (err) => {
                    if (err) throw err;
                    res.json({ success: 'Cadastro realizado!' });
                }
            );
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Erro no servidor' });
    }
});

// Rota de login (POST)
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Preencha todos os campos!' });
    }

    try {
        db.get('SELECT * FROM usuarios WHERE email = ?', [email], async (err, user) => {
            if (err) throw err;
            
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

// Rota para buscar os dados do usuário (GET)
app.get('/auth/user/:id', (req, res) => {
    const userId = req.params.id;

    db.get('SELECT login, email FROM usuarios WHERE id = ?', [userId], (err, user) => {
        if (err) return res.status(500).json({ error: 'Erro no servidor' });
        if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });

        res.json(user); // Agora retorna { login: '...', email: '...' }
    });
});


app.delete('/auth/delete/:id', (req, res) => {
    const userId = req.params.id;

    db.run('DELETE FROM usuarios WHERE id = ?', [userId], function(err) {
        if (err) {
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

// Inicia o servidor
app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});
