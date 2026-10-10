// server.ts
import express from 'express';
import cors from 'cors';
import path from 'path';
import { initializeRepo, addFiles } from './src/gitCommands'; // Importing your existing logic

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());

// Endpoint to initialize a repo
app.post('/api/init', (req, res) => {
    const { repoName } = req.body;
    try {
        initializeRepo(repoName); 
        res.json({ success: true, message: `Repository initialized in ${repoName || '.'}` });
    } catch (error) {
        res.status(500).json({ success: false, error: error });
    }
});

// Endpoint to add files
app.post('/api/add', (req, res) => {
    const { files } = req.body;
    try {
        addFiles(files);
        res.json({ success: true, message: 'Files staged successfully' });
    } catch (error) {
        res.status(500).json({ success: false, error: error });
    }
});

// server.ts
app.post('/api/init', (req, res) => {
    const { repoName } = req.body;
    const result = initializeRepo(repoName);
    res.json(result);
});

app.post('/api/add', (req, res) => {
    const { files } = req.body;
    const result = addFiles(files);
    res.json(result);
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});