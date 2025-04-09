const express = require('express');
const cors = require('cors');
const app = express();
const port = 3000;

app.use(cors());

let requestCount = 0;
let requestsPerSecond = [];

app.use((req, res, next) => {
  requestCount++;
  next();
});

setInterval(() => {
  requestsPerSecond.push(requestCount);
  if (requestsPerSecond.length > 30) requestsPerSecond.shift();
  requestCount = 0;
}, 1000);

app.get('/', (req, res) => {
  res.status(200).send('<a href="https://t.me/tretraunetwork">https://t.me/tretraunetwork</a>');
});

app.get('/api/requests', (req, res) => {
  res.status(200).json(requestsPerSecond);
});

app.listen(port, () => {
  console.log(`Server 1 (No Anti-DDoS) running on http://localhost:${port}`);
});