const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const db = new sqlite3.Database('./banco.db');

// Configurações
app.use(cors({ origin: 'http://localhost:5500' })); // Libera acesso do frontend
app.use(bodyParser.urlencoded({ extended: true }));
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
        // Busca o usuário no banco
        db.get('SELECT * FROM usuarios WHERE email = ?', [email], async (err, user) => {
            if (err) throw err;
            
            if (!user) {
                return res.status(404).json({ error: 'E-mail não cadastrado!' });
            }

            // Compara a senha com o hash armazenado
            const senhaValida = await bcrypt.compare(password, user.senha);
            
            if (!senhaValida) {
                return res.status(401).json({ error: 'Senha incorreta!' });
            }

            // Login bem-sucedido
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

// Inicia o servidor
app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});