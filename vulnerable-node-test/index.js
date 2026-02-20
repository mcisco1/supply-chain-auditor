
const express = require('express');
const _ = require('lodash');

const app = express();
app.get('/', (req, res) => {
  res.send(_.join(['Vulnerable', 'Test', 'App'], ' '));
});

app.listen(3000, () => {
  console.log('Vulnerable test app running on port 3000');
});
