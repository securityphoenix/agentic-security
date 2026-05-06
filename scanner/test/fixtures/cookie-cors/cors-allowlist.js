// Specific origin — should NOT fire.
const cors = require('cors');
const express = require('express');
const app = express();

app.use(cors({ origin: 'https://app.example.com', credentials: true }));
