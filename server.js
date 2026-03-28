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
  credentials: true
}));

app.use(express.json({ limit: '150mb' }));
app.use(express.urlencoded({ extended: true, limit: '150mb' }));
app.use(compression());

// ========== STATIC FOLDERS (not served publicly anymore) ==========
const uploadDir = path.join(__dirname, 'uploads');
const processedDir = path.join(__dirname, 'processed');
[uploadDir, processedDir].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});
// ❌ REMOVED public static serving – now handled by authenticated routes

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
  role:     { type: String, enum: ['user', 'admin'], default: 'user' }, // 👈 ADDED role
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
  ownerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true });

// 🔹 NEW: Temporary upload model for preview
const uploadSchema = new mongoose.Schema({
  filename:       { type: String, required: true },
  originalName:   { type: String, required: true },
  size:           { type: Number, required: true },
  mimeType:       { type: String, required: true },
  ownerId:        { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  expiresAt:      { type: Date, default: () => Date.now() + 60 * 60 * 1000 } // 1 hour TTL
}, { timestamps: true });

// Index for automatic MongoDB TTL deletion (optional but useful)
uploadSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const User = mongoose.model('User', userSchema);
const File = mongoose.model('File', fileSchema);
const Upload = mongoose.model('Upload', uploadSchema);

// ========== MULTER ==========
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
    const authHeader = req.header('Authorization');
    if (!authHeader) {
      return res.status(401).json({ success: false, message: 'No authorization header' });
    }

    let token;
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7).trim();
    } else {
      token = authHeader.trim();
    }

    if (!token || token === 'null' || token === 'undefined' || token === '') {
      return res.status(401).json({ success: false, message: 'Token is empty' });
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

// 👇 NEW: Admin middleware – must be used after auth
const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Admin access required' });
  }
  next();
};

// ========== HELPER ==========
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
      role: 'user', // default role
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
        role: user.role, // 👈 include role
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
        role: user.role, // 👈 include role
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
        role: req.user.role, // 👈 include role
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
        role: user.role, // 👈 include role
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

// Serve temporary upload files (for preview) – only owner can access
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

// Serve processed files (permanent) – only owner can access
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

// ----- PROCESS FILES -----
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

    // ---------- PREVIEW BRANCH (UPDATED) ----------
    if (tool === 'preview') {
      const fileInfo = [];
      for (const f of files) {
        // Store metadata in temporary Upload collection
        const upload = await Upload.create({
          filename: f.filename,
          originalName: f.originalname,
          size: f.size,
          mimeType: f.mimetype,
          ownerId: req.user._id
          // expiresAt uses default (1 hour)
        });

        fileInfo.push({
          id: upload._id,
          name: upload.originalName,
          size: upload.size,
          type: upload.mimeType,
          url: `/api/uploads/${upload.filename}`,   // authenticated URL
          expiresAt: upload.expiresAt
        });
      }

      // Do NOT delete the files here; they will be cleaned up by TTL/background job
      return res.json({
        success: true,
        files: fileInfo,
        message: 'Files ready for preview (available for 1 hour)'
      });
    }

    // ---------- PROCESSING TOOLS (compress, merge, convert, enhance) ----------
    if (tool === 'merge' && files.length < 2) {
      return res.status(400).json({ success: false, message: 'Merge requires at least 2 files' });
    }

    if (['convert', 'enhance'].includes(tool) && files.length !== 1) {
      return res.status(400).json({
        success: false,
        message: `${tool.charAt(0).toUpperCase() + tool.slice(1)} requires exactly 1 file`
      });
    }

    if (tool === 'convert' && !format) {
      return res.status(400).json({ success: false, message: 'Format is required for conversion' });
    }

    let outPath, mime, compSize;
    const origSize = files.reduce((s, f) => s + f.size, 0);
    let fileName = '';

    if (tool === 'compress') {
      const level = Math.max(1, Math.min(9, parseInt(compressLevel) || 6));
      outPath = path.join(processedDir, `${Date.now()}-compressed.zip`);
      const output = fs.createWriteStream(outPath);
      const archive = archiver('zip', { zlib: { level } });

      await new Promise((resolve, reject) => {
        archive.pipe(output);
        files.forEach(f => archive.file(f.path, { name: f.originalname }));
        archive.on('error', reject);
        output.on('close', resolve);
        archive.finalize();
      });

      compSize = fs.statSync(outPath).size;
      fileName = files.length === 1
        ? `${path.parse(files[0].originalname).name}_compressed.zip`
        : `batch_${Date.now()}.zip`;
      mime = 'application/zip';

    } else if (tool === 'merge') {
      const nonPdfFiles = files.filter(f => f.mimetype !== 'application/pdf');
      if (nonPdfFiles.length > 0) {
        return res.status(400).json({
          success: false,
          message: 'All files must be PDFs for merging'
        });
      }

      const pdfDoc = await PDFDocument.create();
      const orderArr = order ? JSON.parse(order) : files.map(f => f.originalname);

      for (const name of orderArr) {
        const file = files.find(f => f.originalname === name);
        if (!file) continue;

        const srcBytes = fs.readFileSync(file.path);
        const src = await PDFDocument.load(srcBytes);
        const pages = await pdfDoc.copyPages(src, src.getPageIndices());
        pages.forEach(p => pdfDoc.addPage(p));
      }

      const pdfBytes = await pdfDoc.save();
      outPath = path.join(processedDir, `${Date.now()}-merged.pdf`);
      fs.writeFileSync(outPath, pdfBytes);
      compSize = pdfBytes.length;
      fileName = 'merged.pdf';
      mime = 'application/pdf';

    } else if (tool === 'convert') {
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

      outPath = path.join(processedDir, `${Date.now()}-converted.${ext}`);

      if (validImageFormats.includes(ext)) {
        await sharp(file.path)
          .toFormat(ext === 'jpg' ? 'jpeg' : ext)
          .toFile(outPath);
        mime = `image/${ext === 'jpg' ? 'jpeg' : ext}`;
      } else {
        fs.copyFileSync(file.path, outPath);
        mime = `audio/${ext}`;
      }

      compSize = fs.statSync(outPath).size;
      fileName = `${path.parse(file.originalname).name}_converted.${ext}`;

    } else if (tool === 'enhance') {
      const file = files[0];

      if (!file.mimetype.startsWith('image/')) {
        return res.status(400).json({
          success: false,
          message: 'Only images can be enhanced'
        });
      }

      outPath = path.join(processedDir, `${Date.now()}-enhanced.webp`);
      await sharp(file.path)
        .rotate()
        .sharpen()
        .modulate({ brightness: 1.1, saturation: 1.2 })
        .webp({ quality: 90 })
        .toFile(outPath);

      compSize = fs.statSync(outPath).size;
      fileName = `${path.parse(file.originalname).name}_enhanced.webp`;
      mime = 'image/webp';
    }

    // Save processed file metadata in permanent File collection
    const processed = await File.create({
      filename: path.basename(outPath),
      originalName: fileName,
      size: origSize,
      compressedSize: compSize,
      type: mime,
      ownerId: req.user._id,
      compressionRatio: origSize > 0 ? Number(((origSize - compSize) / origSize * 100).toFixed(2)) : 0,
      toolUsed: tool
    });

    await updateStats(req.user._id, origSize, compSize);

    res.json({
      success: true,
      url: `/api/processed/${path.basename(outPath)}`, // authenticated URL
      fileName,
      size: compSize,
      originalSize: origSize,
      savings: origSize - compSize,
      tool: tool
    });

  } catch (e) {
    console.error('Process error:', e);
    res.status(500).json({
      success: false,
      message: e.message || 'File processing failed'
    });
  } finally {
    // Clean up the uploaded files from disk (they are no longer needed)
    if (req.files) {
      req.files.forEach(f => {
        try {
          fs.unlinkSync(f.path);
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

// ----- DOWNLOAD FILE (forces download) -----
app.get('/api/download/:filename', auth, async (req, res) => {
  try {
    const filename = req.params.filename;
    const filePath = path.join(processedDir, filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ success: false, message: 'File not found' });
    }

    const file = await File.findOne({ filename, ownerId: req.user._id });
    if (file) {
      file.downloadCount += 1;
      await file.save();
    }

    const user = await User.findById(req.user._id);
    if (user) {
      const stats = { ...user.stats };
      stats.totalDownloads = (stats.totalDownloads || 0) + 1;
      user.stats = stats;
      await user.save();
    }

    res.download(filePath);
  } catch (e) {
    console.error('Download error:', e);
    res.status(500).json({ success: false, message: 'Download failed' });
  }
});

// ========== ADMIN ROUTES (NEW) ==========

// Get all users (admin only)
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json({ success: true, data: users });
  } catch (err) {
    console.error('Admin users fetch error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch users' });
  }
});

// Get all file processes (admin only) – includes user email via population
app.get('/api/admin/file-processes', auth, adminOnly, async (req, res) => {
  try {
    // Fetch all files and populate ownerId to get user email
    const processes = await File.find()
      .populate('ownerId', 'email username') // get email and username from User
      .sort({ createdAt: -1 });

    // Transform to match expected structure for admin frontend
    const formatted = processes.map(proc => ({
      id: proc._id,
      userEmail: proc.ownerId?.email || 'Unknown',
      userName: proc.ownerId?.username || 'Unknown',
      fileName: proc.originalName,
      fileType: proc.type,
      originalSize: (proc.size / (1024 * 1024)).toFixed(2), // bytes to MB
      compressedSize: (proc.compressedSize / (1024 * 1024)).toFixed(2),
      processDate: proc.createdAt,
      status: 'Completed', // all processed files are completed
      tool: proc.toolUsed
    }));

    res.json({ success: true, data: formatted });
  } catch (err) {
    console.error('Admin file processes fetch error:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch file processes' });
  }
});

// ========== BACKGROUND CLEANUP OF EXPIRED UPLOADS ==========
// Runs every hour to delete files older than 1 hour from disk
// (MongoDB TTL will remove the documents automatically)
const CLEANUP_INTERVAL = 60 * 60 * 1000; // 1 hour
setInterval(async () => {
  try {
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    
    // Find upload documents older than 1 hour (they should already be removed by TTL,
    // but we also clean up orphaned files just in case)
    const expiredUploads = await Upload.find({ createdAt: { $lt: oneHourAgo } });
    
    for (const upload of expiredUploads) {
      const filePath = path.join(uploadDir, upload.filename);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        console.log(`🧹 Deleted expired upload file: ${upload.filename}`);
      }
      // Also remove the document (in case TTL didn't fire)
      await upload.deleteOne();
    }

    // Additionally, scan the upload directory for files older than 1 hour
    // that are not in the Upload collection (orphans)
    const files = await fs.promises.readdir(uploadDir);
    for (const file of files) {
      const filePath = path.join(uploadDir, file);
      const stat = await fs.promises.stat(filePath);
      if (stat.isFile() && (Date.now() - stat.mtimeMs) > 60 * 60 * 1000) {
        // Check if it's still referenced in Upload
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

// ========== NO CATCH‑ALL ROUTE (API ONLY) ==========

// ========== START SERVER ==========
const PORT = process.env.PORT || 5001;
app.listen(PORT, () => {
  console.log('\n🚀Online-File-Editor Backend STARTED (MongoDB, API‑only mode)');
  console.log(`   http://localhost:${PORT}`);
  console.log(`   Health check: http://localhost:${PORT}/api/health`);
}); 