const express = require("express");

const app = express();
const PORT = 8008;

// middleware
app.use(express.json());

// route
app.get("/", (req, res) => {
  res.send("Hello from Express 👋");
});

// start server
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
