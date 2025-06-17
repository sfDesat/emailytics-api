// scripts/resetMonthly.js
const { Pool } = require('pg');
require('dotenv').config();

(async () => {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false
  });

  try {
    const { rowCount } = await pool.query(`
      UPDATE users
      SET emails_analyzed_this_month = 0,
          month_reset_date = CURRENT_DATE
      WHERE month_reset_date < date_trunc('month', CURRENT_DATE)
    `);
    console.log('🔄 Monthly reset applied to', rowCount, 'rows');
  } catch (err) {
    console.error('❌ Reset failed:', err);
    process.exit(1);
  } finally {
    await pool.end();
  }
})();
