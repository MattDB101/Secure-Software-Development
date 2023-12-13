const winston = require('winston');
require('winston-mongodb');
const { createLogger, format, transports } = winston;
require('dotenv').config();

const logger = createLogger({
  level: 'warn',
  format: format.combine(
    format.timestamp(),
    format.json()
  ),
  transports: [
    new transports.MongoDB({
      level: 'warn',
      db: process.env.DB_LOGGING,
      options: { useUnifiedTopology: true,
        auth: {
            username: process.env.LOGGING_USER,
            password: process.env.LOGGING_PASS,
          }
      },
      collection: 'logging',
      format: format.combine(
        format.timestamp(),
        format.json()
      ),
    }),
  ],
});



module.exports = logger;
