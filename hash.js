const bcrypt = require("bcryptjs");

async function run() {
  const janeHash   = await bcrypt.hash("janepass123", 10);
  const priyaHash  = await bcrypt.hash("doctorpass2025", 10);

  console.log("Jane hash:", janeHash);
  console.log("Priya hash:", priyaHash);
}

run();

