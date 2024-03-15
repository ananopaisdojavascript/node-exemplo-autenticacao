import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();

// Serializador: organiza as informações no formato .json
app.use(express.json())

// Encriptar a senha
const saltrounds = 10;
const salt = bcrypt.genSaltSync(saltrounds);
const hash = bcrypt.hashSync('senha12345', salt);
const hash2 = bcrypt.hashSync('senha54321', salt);

const users = [
  {
    username: "Ana",
    password: hash
  },
  {
    username: "Pituco",
    password: hash2
  }
]

// Rota de teste
app.get("/", async (_request, response) => {
  return response.status(200).json({ "message": "Estamos no ar!!!" })
})

// Rota de login
app.post("/login", async (request, response) => {
  const { username, password } = request.body;

  // Procurar o usuário na base de dados
  const user = users.find(u => u.username === username);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return response.status(401).json({ "message": "Credenciais inválidas!" })
  }

  const token = jwt.sign({ username: user.username }, salt, { expiresIn: '60min' })
  return response.status(200).json({ token })
})

const verifyToken = (request, response, next) => {
  const token = request.headers['authorization']

  if (!token) {
    return response.status(401).json({ "message": "Token não fornecido!" })
  }

  console.log(token)

  jwt.verify(token, salt, (error, decoded) => {
    if (error) {
      return response.status(403).json({ "message": "Falha na verificação do token!" })
    }
    console.log(decoded.username)

    next()
  })

}

// Rota protegida
app.get("/recurso-protegido", verifyToken, (request, response) => {
  return response.status(200).json({ "message": `Recurso protegido!` })
})

export default app;