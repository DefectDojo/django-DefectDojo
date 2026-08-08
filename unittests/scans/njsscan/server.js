const express = require('express');
const { exec } = require('child_process');
const crypto = require('crypto');

const app = express();

app.get('/run', (req, res) => {
  exec('ls ' + req.query.dir, (err, stdout) => {
    res.send(stdout);
  });
});

app.get('/eval', (req, res) => {
  res.send(eval(req.query.expression));
});

app.get('/hash', (req, res) => {
  res.send(crypto.createHash('md5').update(req.query.value).digest('hex'));
});

module.exports = app;
