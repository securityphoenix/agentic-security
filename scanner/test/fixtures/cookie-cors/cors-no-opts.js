// No opts (defaults to origin '*') — should fire 1 finding.
const cors = require('cors');
const express = require('express');
const app = express();

app.use(cors());
