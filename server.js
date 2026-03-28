import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import multer from 'multer';
import compression from 'compression';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import sharp from 'sharp';
import { PDFDocument } from 'pdf-lib';
import archiver from 'archiver';
import mongoose from 'mongoose';
import dns from 'dns';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();

// ========== MIDDLEWARE ==========
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:5174',
  "https://online-file-editor-frontend.onrender.com",
  "https://online-file-editor-backend.onrender.com",
];

if (process.env.CLIENT_URL) {
  allowedOrigins.push(process.env.CLIENT_URL);
}
if (process.env.RENDER_EXTERNAL_URL) {
  allowedOrigins.push(process.env.RENDER_EXTERNAL_URL);
}

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '150mb' }));
app.use(express.urlencoded({ extended: true, limit: '150mb' }));
app.use(compression());

// ========== STATIC FOLDERS ==========
const uploadDir = path.join(__dirname, 'uploads');
const processedDir = path.join(__dirname, 'processed');
[uploadDir, processedDir].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ========== MONGODB CONNECTION ==========
const mongoUri = process.env.MONGODB_URI;
if (!mongoUri) {
  console.error('❌ MONGODB_URI is not defined in .env');
  process.exit(1);
}

dns.setServers(['8.8.8.8', '8.8.4.4']);

mongoose.connect(mongoUri, {
  family: 4,
})
  .then(() => console.log('✅ MongoDB Connected'))
  .catch(err => {
    console.error('❌ MongoDB error:', err.message);
    process.exit(1);
  });

// ========== MONGOOSE MODELS ==========
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true, minlength: 3 },
  email:    { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  role:     { type: String, enum: ['user', 'admin'], default: 'user' },
  profile:  { type: Object, default: {} },
  preferences: {
    type: Object,
    default: { theme: 'light', notifications: true }
  },
  stats: {
    type: Object,
    default: {
      totalFiles: 0,
      totalSize: 0,
      totalCompressed: 0,
      spaceSaved: 0,
      totalDownloads: 0
    }
  }
}, { timestamps: true });

const fileSchema = new mongoose.Schema({
  filename:       { type: String, required: true },
  originalName:   { type: String, required: true },
  size:           { type: Number, required: true },
  compressedSize: { type: Number, required: true },
  type:           { type: String, required: true },
  downloadCount:  { type: Number, default: 0 },
  compressionRatio: Number,
  toolUsed:       String,
  ownerId:        { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true });

const uploadSchema = new mongoose.Schema({
  filename:       { type: String, required: true },
  originalName:   { type: String, required: true },
  size:           { type: Number, required: true },
  mimeType:       { type: String, required: true },
  ownerId:        { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  expiresAt:      { type: Date, default: () => Date.now() + 60 * 60 * 1000 }
}, { timestamps: true });

uploadSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const User = mongoose.model('User', userSchema);
const File = mongoose.model('File', fileSchema);
const Upload = mongoose.model('Upload', uploadSchema);

// ========== MULTER CONFIGURATION ==========
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/[^a-zA-Z0-9.\-]/g, '_');
    cb(null, `${Date.now()}-${Math.random().toString(36).substr(2, 9)}-${safe}`);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 150 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, true)
});

// ========== AUTH MIDDLEWARE ==========
const auth = async (req, res, next) => {
  try {
    let token = null;
    
    // Check Authorization header
    const authHeader = req.header('Authorization');
    if (authHeader) {
      if (authHeader.startsWith('Bearer ')) {
        token = authHeader.slice(7).trim();
      } else {
        token = authHeader.trim();
      }
    }
    
    // Check query parameter (for downloads)
    if (!token && req.query.token) {
      token = req.query.token;
    }
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'No authorization header or token' });
    }

    if (token === 'null' || token === 'undefined' || token === '') {
      return res.status(401).json({ success: false, message: 'Invalid token' });
    }

    const tokenParts = token.split('.');
    if (tokenParts.length !== 3) {
      return res.status(401).json({ success: false, message: 'Invalid token format' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');

    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found' });
    }

    req.user = user;
    next();
  } catch (e) {
    console.error('Auth error:', e.message);
    if (e.name === 'JsonWebTokenError') {
      return res.status(401).json({ success: false, message: 'Invalid token' });
    }
    if (e.name === 'TokenExpiredError') {
      return res.status(401).json({ success: false, message: 'Token expired' });
    }
    res.status(401).json({ success: false, message: 'Authentication failed' });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  next();
};

// ========== HELPER FUNCTIONS ==========
const updateStats = async (userId, orig, comp) => {
  const user = await User.findById(userId);
  if (!user) return;

  const stats = user.stats || {};
  stats.totalFiles = (stats.totalFiles || 0) + 1;
  stats.totalSize = (stats.totalSize || 0) + orig;
  stats.totalCompressed = (stats.totalCompressed || 0) + comp;
  stats.spaceSaved = (stats.spaceSaved || 0) + (orig - comp);

  user.stats = stats;
  await user.save();
};

const getContentType = (filename) => {
  const ext = path.extname(filename).toLowerCase();
  const types = {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.webp': 'image/webp',
    '.pdf': 'application/pdf',
    '.zip': 'application/zip',
    '.mp3': 'audio/mpeg',
    '.wav': 'audio/wav',
    '.mp4': 'video/mp4'
  };
  return types[ext] || 'application/octet-stream';
};

// ========== API ROUTES ==========
app.get('/api/health', (req, res) => {
  res.json({
    success: true,
    message: 'Server running',
    db: 'OK'
  });
});

// ----- REGISTER -----
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, fullName = '', company = '' } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ success: false, message: 'Username, email, and password are required' });
    }
    if (username.length < 3) return res.status(400).json({ success: false, message: 'Username must be at least 3 characters' });
    if (password.length < 6) return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });

    const existing = await User.findOne({
      $or: [{ email: email.toLowerCase() }, { username }]
    });
    if (existing) {
      return res.status(400).json({
        success: false,
        message: existing.email === email.toLowerCase() ? 'Email already in use' : 'Username already taken'
      });
    }

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({
      username,
      email: email.toLowerCase(),
      password: hashed,
      role: 'user',
      profile: { fullName, company }
    });

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        profile: user.profile,
        stats: user.stats,
        preferences: user.preferences
      }
    });
  } catch (e) {
    console.error('Register error:', e);
    res.status(500).json({ success: false, message: 'Server error during registration' });
  }
});

// ----- LOGIN -----
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password are required' });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid email or password' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ success: false, message: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        profile: user.profile,
        stats: user.stats,
        preferences: user.preferences
      }
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ success: false, message: 'Server error during login' });
  }
});

// ----- PROFILE -----
app.get('/api/profile', auth, async (req, res) => {
  try {
    const files = await File.find({ ownerId: req.user._id });
    const stats = {
      totalFiles: files.length,
      totalSize: files.reduce((s, f) => s + f.size, 0),
      totalCompressed: files.reduce((s, f) => s + f.compressedSize, 0),
      spaceSaved: files.reduce((s, f) => s + (f.size - f.compressedSize), 0),
      totalDownloads: files.reduce((s, f) => s + f.downloadCount, 0)
    };

    res.json({
      success: true,
      user: {
        id: req.user._id,
        username: req.user.username,
        email: req.user.email,
        role: req.user.role,
        profile: req.user.profile,
        preferences: req.user.preferences,
        stats
      }
    });
  } catch (e) {
    console.error('Profile fetch error:', e);
    res.status(500).json({ success: false, message: 'Failed to fetch profile' });
  }
});

// ----- UPDATE PROFILE -----
app.put('/api/profile', auth, async (req, res) => {
  try {
    const updates = req.body;
    const allowed = ['fullName', 'company', 'phone', 'location', 'theme', 'notifications'];
    const profileUpdate = {};
    const prefsUpdate = {};

    allowed.forEach(f => {
      if (updates[f] !== undefined) {
        if (['theme', 'notifications'].includes(f)) {
          prefsUpdate[f] = updates[f];
        } else {
          profileUpdate[f] = updates[f];
        }
      }
    });

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    user.profile = { ...user.profile, ...profileUpdate };
    user.preferences = { ...user.preferences, ...prefsUpdate };
    await user.save();

    const files = await File.find({ ownerId: user._id });
    const stats = {
      totalFiles: files.length,
      totalSize: files.reduce((s, f) => s + f.size, 0),
      totalCompressed: files.reduce((s, f) => s + f.compressedSize, 0),
      spaceSaved: files.reduce((s, f) => s + (f.size - f.compressedSize), 0),
      totalDownloads: files.reduce((s, f) => s + f.downloadCount, 0)
    };

    res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        profile: user.profile,
        preferences: user.preferences,
        stats
      }
    });
  } catch (e) {
    console.error('Profile update error:', e);
    res.status(500).json({ success: false, message: 'Profile update failed' });
  }
});

// ========== AUTHENTICATED FILE SERVING ==========

// Serve temporary upload files (for preview)
app.get('/api/uploads/:filename', auth, async (req, res) => {
  try {
    const filename = req.params.filename;
    const upload = await Upload.findOne({ filename, ownerId: req.user._id });
    if (!upload) {
      return res.status(404).json({ success: false, message: 'File not found or expired' });
    }

    const filePath = path.join(uploadDir, filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ success: false, message: 'File missing from disk' });
    }

    res.setHeader('Content-Type', upload.mimeType);
    res.setHeader('Content-Disposition', `inline; filename="${upload.originalName}"`);
    res.sendFile(filePath);
  } catch (err) {
    console.error('Error serving upload:', err);
    res.status(500).json({ success: false, message: 'Failed to serve file' });
  }
});

// Serve processed files (permanent)
app.get('/api/processed/:filename', auth, async (req, res) => {
  try {
    const filename = req.params.filename;
    const file = await File.findOne({ filename, ownerId: req.user._id });
    if (!file) {
      return res.status(404).json({ success: false, message: 'Processed file not found' });
    }

    const filePath = path.join(processedDir, filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ success: false, message: 'File missing from disk' });
    }

    res.setHeader('Content-Type', file.type);
    res.setHeader('Content-Disposition', `inline; filename="${file.originalName}"`);
    res.sendFile(filePath);
  } catch (err) {
    console.error('Error serving processed file:', err);
    res.status(500).json({ success: false, message: 'Failed to serve file' });
  }
});

// ----- DOWNLOAD FILE (UPDATED WITH BETTER AUTH) -----
app.get('/api/download/:filename', auth, async (req, res) => {
  try {
    const filename = req.params.filename;
    
    // Security: Prevent directory traversal
    const safeFilename = path.basename(filename);
    const filePath = path.join(processedDir, safeFilename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ success: false, message: 'File not found' });
    }

    // Find the file in database and verify ownership
    const file = await File.findOne({ filename: safeFilename, ownerId: req.user._id });
    
    if (!file) {
      return res.status(403).json({ success: false, message: 'You do not have permission to download this file' });
    }

    // Increment download count
    file.downloadCount += 1;
    await file.save();

    // Update user stats
    const user = await User.findById(req.user._id);
    if (user) {
      const stats = { ...user.stats };
      stats.totalDownloads = (stats.totalDownloads || 0) + 1;
      user.stats = stats;
      await user.save();
    }

    // Get file stats for content length
    const stats = fs.statSync(filePath);
    
    // Set headers for download
    res.setHeader('Content-Type', getContentType(safeFilename));
    res.setHeader('Content-Disposition', `attachment; filename="${file.originalName}"`);
    res.setHeader('Content-Length', stats.size);
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    
    // Stream the file
    const fileStream = fs.createReadStream(filePath);
    fileStream.pipe(res);
    
    fileStream.on('error', (error) => {
      console.error('Error streaming file:', error);
      if (!res.headersSent) {
        res.status(500).json({ success: false, message: 'Error downloading file' });
      }
    });
    
  } catch (e) {
    console.error('Download error:', e);
    res.status(500).json({ success: false, message: 'Download failed' });
  }
});

// ----- PROCESS FILES (FIXED - ONLY ONE FEATURE AT A TIME) -----
app.post('/api/process', auth, upload.array('files'), async (req, res) => {
  try {
    const files = req.files;
    if (!files?.length) {
      return res.status(400).json({ success: false, message: 'No files uploaded' });
    }

    const { tool, compressLevel, format, order } = req.body;

    const validTools = ['compress', 'merge', 'convert', 'enhance', 'preview'];
    if (!validTools.includes(tool)) {
      return res.status(400).json({
        success: false,
        message: `Invalid tool: ${tool}. Valid tools are: ${validTools.join(', ')}`
      });
    }

    // PREVIEW TOOL
    if (tool === 'preview') {
      const fileInfo = [];
      for (const f of files) {
        const upload = await Upload.create({
          filename: f.filename,
          originalName: f.originalname,
          size: f.size,
          mimeType: f.mimetype,
          ownerId: req.user._id
        });

        fileInfo.push({
          id: upload._id,
          name: upload.originalName,
          size: upload.size,
          type: upload.mimeType,
          url: `/api/uploads/${upload.filename}`,
          expiresAt: upload.expiresAt
        });
      }

      return res.json({
        success: true,
        files: fileInfo,
        message: 'Files ready for preview (available for 1 hour)'
      });
    }

    // COMPRESS TOOL - ONLY COMPRESS, NO OTHER FEATURES
    if (tool === 'compress') {
      // Validate: compress only works with one file or multiple files (creates zip)
      const level = Math.max(1, Math.min(9, parseInt(compressLevel) || 6));
      const outPath = path.join(processedDir, `${Date.now()}-compressed.zip`);
      const output = fs.createWriteStream(outPath);
      const archive = archiver('zip', { zlib: { level } });

      await new Promise((resolve, reject) => {
        archive.pipe(output);
        files.forEach(f => archive.file(f.path, { name: f.originalname }));
        archive.on('error', reject);
        output.on('close', resolve);
        archive.finalize();
      });

      const compSize = fs.statSync(outPath).size;
      const origSize = files.reduce((s, f) => s + f.size, 0);
      const fileName = files.length === 1
        ? `${path.parse(files[0].originalname).name}_compressed.zip`
        : `batch_${Date.now()}.zip`;
      const mime = 'application/zip';

      // Save to database
      const processed = await File.create({
        filename: path.basename(outPath),
        originalName: fileName,
        size: origSize,
        compressedSize: compSize,
        type: mime,
        ownerId: req.user._id,
        compressionRatio: origSize > 0 ? Number(((origSize - compSize) / origSize * 100).toFixed(2)) : 0,
        toolUsed: 'compress'
      });

      await updateStats(req.user._id, origSize, compSize);

      return res.json({
        success: true,
        url: `/api/processed/${path.basename(outPath)}`,
        fileName,
        size: compSize,
        originalSize: origSize,
        savings: origSize - compSize,
        tool: 'compress'
      });
    }

    // MERGE TOOL - ONLY MERGE PDFs
    if (tool === 'merge') {
      if (files.length < 2) {
        return res.status(400).json({ success: false, message: 'Merge requires at least 2 files' });
      }

      const nonPdfFiles = files.filter(f => f.mimetype !== 'application/pdf');
      if (nonPdfFiles.length > 0) {
        return res.status(400).json({
          success: false,
          message: 'All files must be PDFs for merging'
        });
      }

      const pdfDoc = await PDFDocument.create();
      const orderArr = order ? JSON.parse(order) : files.map(f => f.originalname);
      const origSize = files.reduce((s, f) => s + f.size, 0);

      for (const name of orderArr) {
        const file = files.find(f => f.originalname === name);
        if (!file) continue;

        const srcBytes = fs.readFileSync(file.path);
        const src = await PDFDocument.load(srcBytes);
        const pages = await pdfDoc.copyPages(src, src.getPageIndices());
        pages.forEach(p => pdfDoc.addPage(p));
      }

      const pdfBytes = await pdfDoc.save();
      const outPath = path.join(processedDir, `${Date.now()}-merged.pdf`);
      fs.writeFileSync(outPath, pdfBytes);
      const compSize = pdfBytes.length;
      const fileName = 'merged.pdf';
      const mime = 'application/pdf';

      const processed = await File.create({
        filename: path.basename(outPath),
        originalName: fileName,
        size: origSize,
        compressedSize: compSize,
        type: mime,
        ownerId: req.user._id,
        compressionRatio: origSize > 0 ? Number(((origSize - compSize) / origSize * 100).toFixed(2)) : 0,
        toolUsed: 'merge'
      });

      await updateStats(req.user._id, origSize, compSize);

      return res.json({
        success: true,
        url: `/api/processed/${path.basename(outPath)}`,
        fileName,
        size: compSize,
        originalSize: origSize,
        savings: origSize - compSize,
        tool: 'merge'
      });
    }

    // CONVERT TOOL - ONLY CONVERT ONE FILE
    if (tool === 'convert') {
      if (files.length !== 1) {
        return res.status(400).json({
          success: false,
          message: 'Convert requires exactly 1 file'
        });
      }

      if (!format) {
        return res.status(400).json({ success: false, message: 'Format is required for conversion' });
      }

      const file = files[0];
      const ext = format.toLowerCase();
      const validImageFormats = ['jpg', 'jpeg', 'png', 'webp'];
      const validAudioFormats = ['mp3', 'wav'];

      if (![...validImageFormats, ...validAudioFormats].includes(ext)) {
        return res.status(400).json({
          success: false,
          message: 'Unsupported format. Use: jpg, png, webp, mp3, wav'
        });
      }

      const outPath = path.join(processedDir, `${Date.now()}-converted.${ext}`);
      let mime;

      if (validImageFormats.includes(ext)) {
        await sharp(file.path)
          .toFormat(ext === 'jpg' ? 'jpeg' : ext)
          .toFile(outPath);
        mime = `image/${ext === 'jpg' ? 'jpeg' : ext}`;
      } else {
        fs.copyFileSync(file.path, outPath);
        mime = `audio/${ext}`;
      }

      const compSize = fs.statSync(outPath).size;
      const origSize = file.size;
      const fileName = `${path.parse(file.originalname).name}_converted.${ext}`;

      const processed = await File.create({
        filename: path.basename(outPath),
        originalName: fileName,
        size: origSize,
        compressedSize: compSize,
        type: mime,
        ownerId: req.user._id,
        compressionRatio: origSize > 0 ? Number(((origSize - compSize) / origSize * 100).toFixed(2)) : 0,
        toolUsed: 'convert'
      });

      await updateStats(req.user._id, origSize, compSize);

      return res.json({
        success: true,
        url: `/api/processed/${path.basename(outPath)}`,
        fileName,
        size: compSize,
        originalSize: origSize,
        savings: origSize - compSize,
        tool: 'convert'
      });
    }

    // ENHANCE TOOL - ONLY ENHANCE ONE IMAGE
    if (tool === 'enhance') {
      if (files.length !== 1) {
        return res.status(400).json({
          success: false,
          message: 'Enhance requires exactly 1 file'
        });
      }

      const file = files[0];
      if (!file.mimetype.startsWith('image/')) {
        return res.status(400).json({
          success: false,
          message: 'Only images can be enhanced'
        });
      }

      const outPath = path.join(processedDir, `${Date.now()}-enhanced.webp`);
      await sharp(file.path)
        .rotate()
        .sharpen()
        .modulate({ brightness: 1.1, saturation: 1.2 })
        .webp({ quality: 90 })
        .toFile(outPath);

      const compSize = fs.statSync(outPath).size;
      const origSize = file.size;
      const fileName = `${path.parse(file.originalname).name}_enhanced.webp`;
      const mime = 'image/webp';

      const processed = await File.create({
        filename: path.basename(outPath),
        originalName: fileName,
        size: origSize,
        compressedSize: compSize,
        type: mime,
        ownerId: req.user._id,
        compressionRatio: origSize > 0 ? Number(((origSize - compSize) / origSize * 100).toFixed(2)) : 0,
        toolUsed: 'enhance'
      });

      await updateStats(req.user._id, origSize, compSize);

      return res.json({
        success: true,
        url: `/api/processed/${path.basename(outPath)}`,
        fileName,
        size: compSize,
        originalSize: origSize,
        savings: origSize - compSize,
        tool: 'enhance'
      });
    }

  } catch (e) {
    console.error('Process error:', e);
    res.status(500).json({
      success: false,
      message: e.message || 'File processing failed'
    });
  } finally {
    // Clean up uploaded files
    if (req.files) {
      req.files.forEach(f => {
        try {
          if (fs.existsSync(f.path)) {
            fs.unlinkSync(f.path);
          }
        } catch (cleanupError) {
          console.warn('Cleanup error:', cleanupError.message);
        }
      });
    }
  }
});

// ----- HISTORY -----
app.get('/api/history', auth, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = 10;
    const skip = (page - 1) * limit;

    const total = await File.countDocuments({ ownerId: req.user._id });
    const files = await File.find({ ownerId: req.user._id })
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    res.json({
      success: true,
      files,
      total,
      page,
      pages: Math.ceil(total / limit)
    });
  } catch (e) {
    console.error('History error:', e);
    res.status(500).json({ success: false, message: 'Failed to fetch history' });
  }
});

// ========== ADMIN ROUTES ==========
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json({ success: true, data: users });
  } catch (err) {
    console.error('Admin users fetch error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch users' });
  }
});

app.get('/api/admin/file-processes', auth, adminOnly, async (req, res) => {
  try {
    const processes = await File.find()
      .populate('ownerId', 'email username')
      .sort({ createdAt: -1 });

    const formatted = processes.map(proc => ({
      id: proc._id,
      userEmail: proc.ownerId?.email || 'Unknown',
      userName: proc.ownerId?.username || 'Unknown',
      fileName: proc.originalName,
      fileType: proc.type,
      originalSize: (proc.size / (1024 * 1024)).toFixed(2),
      compressedSize: (proc.compressedSize / (1024 * 1024)).toFixed(2),
      processDate: proc.createdAt,
      status: 'Completed',
      tool: proc.toolUsed
    }));

    res.json({ success: true, data: formatted });
  } catch (err) {
    console.error('Admin file processes fetch error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch file processes' });
  }
});

// ========== BACKGROUND CLEANUP ==========
const CLEANUP_INTERVAL = 60 * 60 * 1000;
setInterval(async () => {
  try {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    const expiredUploads = await Upload.find({ createdAt: { $lt: oneHourAgo } });
    
    for (const upload of expiredUploads) {
      const filePath = path.join(uploadDir, upload.filename);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        console.log(`🧹 Deleted expired upload file: ${upload.filename}`);
      }
      await upload.deleteOne();
    }

    const files = await fs.promises.readdir(uploadDir);
    for (const file of files) {
      const filePath = path.join(uploadDir, file);
      const stat = await fs.promises.stat(filePath);
      if (stat.isFile() && (Date.now() - stat.mtimeMs) > 60 * 60 * 1000) {
        const upload = await Upload.findOne({ filename: file });
        if (!upload) {
          await fs.promises.unlink(filePath);
          console.log(`🧹 Deleted orphaned upload file: ${file}`);
        }
      }
    }
  } catch (err) {
    console.error('Cleanup error:', err);
  }
}, CLEANUP_INTERVAL);

// ========== START SERVER ==========
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log('\n🚀 Online-File-Editor Backend STARTED');
  console.log(`   http://localhost:${PORT}`);
  console.log(`   Health check: http://localhost:${PORT}/api/health`);
});