const express = require('express');
const child_process = require('child_process');
const fs = require('fs');
const axios = require('axios');
const crypto = require('crypto');
const app = express();

// 1. Hardcoded Secret (CWE-798)
const apiKey = "sk_test_51MzXYZabc1234567890abcdef";

// 2. Cross-Site Scripting (CWE-79)
function renderUserProfile(container, userInput) {
    container.innerHTML = "<div>" + userInput + "</div>";
}

// 2b. React JSX XSS (CWE-79)
function DangerousComponent({ rawMarkup }) {
    return <div dangerouslySetInnerHTML={{ __html: rawMarkup }} />;
}

// 3. Command Injection (CWE-78)
function executeBackup(targetDir) {
    child_process.exec("tar -czf backup.tar.gz " + targetDir);
}

// 4. SQL Injection (CWE-89)
function findAccount(pool, accountId) {
    return pool.query("SELECT * FROM accounts WHERE id = " + accountId);
}

// 5. Prototype Pollution (CWE-1321)
function unsafeMerge(target, source) {
    target['__proto__'] = source;
}

// 6. Path Traversal (CWE-22)
app.get('/download', (req, res) => {
    fs.readFile(req.query.file, (err, data) => {
        res.send(data);
    });
});

// 7. SSRF (CWE-918)
app.get('/proxy', async (req, res) => {
    const response = await axios.get(req.query.url);
    res.json(response.data);
});

// 8. Weak Cryptography (CWE-327)
function computeChecksum(data) {
    return crypto.createHash('md5').update(data).digest('hex');
}
