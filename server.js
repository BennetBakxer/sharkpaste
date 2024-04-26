const express = require('express');
const app = express();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

app.use(express.json());
app.use(express.static('public'));

const storagePath = path.join(__dirname, 'storage');
if (!fs.existsSync(storagePath)) {
    fs.mkdirSync(storagePath);
}

function generateId(length = 6) {
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function encryptData(data, password) {
    const algorithm = 'aes-256-ctr';
    const secretKey = crypto.createHash('sha256').update(String(password)).digest('base64').substr(0, 32);
    const iv = crypto.randomBytes(16);

    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);

    return {
        iv: iv.toString('hex'),
        content: encrypted.toString('hex')
    };
}

function decryptData(hash, password) {
    const algorithm = 'aes-256-ctr';
    const secretKey = crypto.createHash('sha256').update(String(password)).digest('base64').substr(0, 32);
    const decipher = crypto.createDecipheriv(algorithm, secretKey, Buffer.from(hash.iv, 'hex'));

    const decrypted = Buffer.concat([decipher.update(Buffer.from(hash.content, 'hex')), decipher.final()]);
    return decrypted.toString();
}

app.post('/upload', async (req, res) => {
    const { name, content, syntax, expiration, password } = req.body;
    const fileId = generateId();
    const filePath = path.join(storagePath, fileId + '.json');

    let readableExpiration;
    if (expiration !== 'never' && expiration !== 'burn') {
        let expTime = 0;
        switch (expiration) {
            case '10m':
                expTime = 10 * 60 * 1000;
                readableExpiration = '10 Minutes';
                break;
            case '1h':
                expTime = 60 * 60 * 1000;
                readableExpiration = '1 Hour';
                break;
            case '1d':
                expTime = 24 * 60 * 60 * 1000;
                readableExpiration = '1 Day';
                break;
            case '1w':
                expTime = 7 * 24 * 60 * 60 * 1000;
                readableExpiration = '1 Week';
                break;
            case '2w':
                expTime = 14 * 24 * 60 * 60 * 1000;
                readableExpiration = '2 Weeks';
                break;
            default:
                return res.status(400).json({ error: 'Invalid expiration option' });
        }

        setTimeout(() => {
            try {
                fs.unlinkSync(filePath);
            } catch (err) {
                console.error(`Failed to delete expired paste: ${err}`);
            }
        }, expTime);
    } else if (expiration === 'burn') {
        readableExpiration = 'Burn After Read';
    }

    let fileData = {
        name,
        content,
        syntax,
        burnAfterRead: expiration === 'burn',
        expiration: readableExpiration
    };

    if (password) {
        const encryptedContent = encryptData(content, password);
        const hashedPassword = await bcrypt.hash(password, 10);
        fileData.content = encryptedContent;
        fileData.password = hashedPassword;
    }

    const protocol = req.headers['x-forwarded-proto'] || 'http';
    const host = req.headers['x-forwarded-host'] || req.hostname;
    const url = `${protocol}://${host}/${fileId}`;

    fs.writeFileSync(filePath, JSON.stringify(fileData));

    // Return the relative URL or the constructed URL from above
    res.json({ url: url });
});
app.get('/:id', async (req, res) => {
    const pastePath = path.join(__dirname, 'public', 'upload.html');
    res.sendFile(pastePath);
});
app.get('/api/paste/:id', async (req, res) => {
    const { id } = req.params;
    const filePath = path.join(storagePath, `${id}.json`);

    try {
        let fileData = JSON.parse(fs.readFileSync(filePath, 'utf8'));

        if (fileData.burnAfterRead) {
            fs.unlinkSync(filePath);
            fileData = { ...fileData, burnAfterRead: true }; // Preserve data to send back before deletion
        }

        res.json({
            name: fileData.name,
            content: fileData.content,
            passwordProtected: !!fileData.password,
            syntax: fileData.syntax,
            expiration: fileData.expiration
        });
    } catch (err) {
        console.error(err);
        res.status(404).json({ error: 'Paste not found or an error occurred.' });
    }
});

app.post('/api/burn/:id', async (req, res) => {
    const { id } = req.params;
    const filePath = path.join(storagePath, `${id}.json`);

    try {
        fs.unlinkSync(filePath);
        res.status(200).send('Paste has been burned.');
    } catch (err) {
        console.error(err);
        res.status(404).send('Paste not found or already burned.');
    }
});

app.post('/api/verifyPassword/:id', async (req, res) => {
    const { id } = req.params;
    const { password } = req.body;
    const filePath = path.join(storagePath, `${id}.json`);

    try {
        const fileData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        if (await bcrypt.compare(password, fileData.password)) {
            const decryptedContent = decryptData(fileData.content, password);
            res.send(decryptedContent);
        } else {
            res.status(401).send('Invalid password');
        }
    } catch (err) {
        console.error(err);
        res.status(404).send('Paste not found or password incorrect');
    }
});

if(process.env.NODE_ENV !== 'production') {
    const port = 3000;
    app.listen(port, () => {
        console.log(`Server running at http://localhost:${port}`);
    });
}
