const express = require('express')
const http = require('http')
const { Server } = require('socket.io')
const path = require('path')

const app = express()
const server = http.createServer(app)
const io = new Server(server)

// For storing code -> socket.id
let codeMap = {}

app.use(express.static(path.join(__dirname))) // serve index.html etc.

io.on('connection', (socket) => {
  // Generate a random code and send to client
  const userCode = Math.floor(Math.random() * 100000).toString().padStart(5, '0')
  codeMap[userCode] = socket.id

  socket.emit('assignedCode', userCode)

  // When user tries to connect with a code
  socket.on('joinWithCode', (code) => {
    const partnerId = codeMap[code]
    if (partnerId) {
      // Let both sockets know they have joined successfully
      socket.emit('connected', code)
      io.to(partnerId).emit('connected', userCode)
    } else {
      socket.emit('errorMsg', 'Invalid code')
    }
  })

  // Forward encrypted messages between two partners
  socket.on('messageTo', ({ code, payload }) => {
    const partnerId = codeMap[code]
    if (partnerId) {
      io.to(partnerId).emit('messageFrom', payload)
    }
  })

  socket.on('disconnect', () => {
    // Clean up codeMap on disconnect
    for (const c of Object.keys(codeMap)) {
      if (codeMap[c] === socket.id) {
        delete codeMap[c]
      }
    }
  })
})

// Start server
server.listen(3000, () => {
  console.log('Server is running on http://localhost:3000')
})