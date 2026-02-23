const mysql = require("mysql2/promise");

const pool = mysql.createPool(
  process.env.DATABASE_URL + "?ssl=true"
);

module.exports = pool;