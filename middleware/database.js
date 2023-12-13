const mongoose = require('mongoose');

require('dotenv').config();

const conn = process.env.DB_STRING;

const connection = mongoose.createConnection(conn, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    user: process.env.DB_USER,
    pass: process.env.DB_PASS,
});

const UserSchema = new mongoose.Schema({
    username: String,
    hash: String,
    salt: String,
    admin: Boolean
});

const EncryptedFileSchema  = new mongoose.Schema({
    username: { type: String, required: true },
    fileName: { type: String, required: true },
    fileSize: { type: Number, required: true },
    uploadDate: { type: Date, default: Date.now },
    file: { type: String, data: Buffer}
    //encryptedFile: { data: Buffer }
});

const FileUpload = connection.model('FileUpload', EncryptedFileSchema );
const User = connection.model('User', UserSchema);

module.exports = connection;

