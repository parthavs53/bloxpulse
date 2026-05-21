const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

require('dotenv').config();

// ─── Cloudinary Setup ─────────────────────────────────────────────────────────
const cloudinary = require('cloudinary').v2;
const multer = require('multer');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Use memory storage for multer
const storage = multer.memoryStorage();
const upload = multer({ 
  storage,
  limits: { fileSize: 100 * 1024 * 1024 }, // 100MB max
  fileFilter: (req, file, cb) => {
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'video/quicktime', 'video/webm'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Only images and videos are allowed!'));
  }
});

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'bloxpulse-secret-change-in-production';
const DB_PATH = path.join(__dirname, 'db.json');

app.use(cors());
app.use(express.json());

// ─── Database ────────────────────────────────────────────────────────────────

function readDB() {
  if (!fs.existsSync(DB_PATH)) {
    const init = { users: [], posts: [], likes: [], follows: [], comments: [], pendingVerifications: [] };
    fs.writeFileSync(DB_PATH, JSON.stringify(init, null, 2));
    return init;
  }
  const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
  if (!db.pendingVerifications) db.pendingVerifications = [];
  return db;
}

function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
}

function generateVerificationCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = 'BLOXPULSE-';
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)];
  return code;
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password + 'bloxpulse_salt').digest('hex');
}

function verifyPassword(password, hash) {
  return hashPassword(password) === hash;
}

// ─── Auth Middleware ─────────────────────────────────────────────────────────

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ─── Roblox API Helpers ──────────────────────────────────────────────────────

async function getRobloxUser(username) {
  const res = await fetch('https://users.roblox.com/v1/usernames/users', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ usernames: [username], excludeBannedUsers: true }),
  });
  const data = await res.json();
  if (!data.data || data.data.length === 0) return null;
  return data.data[0];
}

async function getRobloxAvatar(robloxId) {
  try {
    const res = await fetch(`https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=${robloxId}&size=150x150&format=Png`);
    const data = await res.json();
    return data.data?.[0]?.imageUrl || null;
  } catch { return null; }
}

async function getRobloxBio(robloxId) {
  try {
    const res = await fetch(`https://users.roblox.com/v1/users/${robloxId}`);
    const data = await res.json();
    return data.description || '';
  } catch { return ''; }
}

// ─── Routes: Auth ────────────────────────────────────────────────────────────

// STEP 1: Request verification code
app.post('/api/auth/request-verification', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).json({ error: 'Roblox username is required' });

  try {
    const robloxUser = await getRobloxUser(username);
    if (!robloxUser) return res.status(404).json({ error: 'Roblox user not found. Check your username.' });

    const robloxId = robloxUser.id.toString();
    const db = readDB();

    // Check if already has a BloxPulse account
    const existing = db.users.find(u => u.robloxId === robloxId);
    if (existing) return res.status(409).json({ error: 'Account already exists. Please sign in instead.' });

    // Generate verification code
    const code = generateVerificationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 mins

    // Remove any old pending verification for this user
    db.pendingVerifications = db.pendingVerifications.filter(v => v.robloxId !== robloxId);

    // Save pending verification
    db.pendingVerifications.push({ robloxId, username: robloxUser.name, displayName: robloxUser.displayName || robloxUser.name, code, expiresAt });
    writeDB(db);

    res.json({ code, robloxId, displayName: robloxUser.displayName || robloxUser.name });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong. Try again.' });
  }
});

// STEP 2: Verify the code from Roblox bio and create account
app.post('/api/auth/verify-and-signup', async (req, res) => {
  const { robloxId, password } = req.body;
  if (!robloxId) return res.status(400).json({ error: 'Missing robloxId' });
  if (!password) return res.status(400).json({ error: 'Password is required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  try {
    const db = readDB();

    // Find pending verification
    const pending = db.pendingVerifications.find(v => v.robloxId === robloxId);
    if (!pending) return res.status(400).json({ error: 'No verification found. Please start again.' });

    // Check expiry
    if (new Date() > new Date(pending.expiresAt)) {
      db.pendingVerifications = db.pendingVerifications.filter(v => v.robloxId !== robloxId);
      writeDB(db);
      return res.status(400).json({ error: 'Verification code expired. Please start again.' });
    }

    // Check Roblox bio for the code
    const bio = await getRobloxBio(robloxId);
    if (!bio.includes(pending.code)) {
      return res.status(400).json({ error: `Code not found in your Roblox bio. Make sure you added: ${pending.code}` });
    }

    // Get avatar
    const avatarUrl = await getRobloxAvatar(robloxId);

    // Create the account
    // Hardcoded admin usernames
    const ADMIN_USERNAMES = ['GOD949399'];
    const isAdmin = ADMIN_USERNAMES.includes(pending.username);
    const user = {
      id: generateId(),
      robloxId,
      username: pending.username,
      displayName: pending.displayName,
      avatarUrl,
      password: hashPassword(password),
      bio: '',
      isAdmin,
      createdAt: new Date().toISOString(),
    };

    db.users.push(user);
    db.pendingVerifications = db.pendingVerifications.filter(v => v.robloxId !== robloxId);
    writeDB(db);

    const { password: _, ...safeUser } = user;
    const token = jwt.sign({ userId: user.id, robloxId }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, user: safeUser, message: 'Account created successfully!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong. Try again.' });
  }
});

// SIGN IN
app.post('/api/auth/signin', async (req, res) => {
  const { username, password } = req.body;
  if (!username) return res.status(400).json({ error: 'Roblox username is required' });
  if (!password) return res.status(400).json({ error: 'Password is required' });

  try {
    const robloxUser = await getRobloxUser(username);
    if (!robloxUser) return res.status(404).json({ error: 'Roblox user not found. Check your username.' });

    const robloxId = robloxUser.id.toString();
    const db = readDB();
    const user = db.users.find(u => u.robloxId === robloxId);
    if (!user) return res.status(404).json({ error: 'No account found. Please create an account first.' });
    if (!verifyPassword(password, user.password)) return res.status(401).json({ error: 'Wrong password. Try again.' });
    if (user.banned) return res.status(403).json({ error: 'This account has been banned from BloxPulse.' });

    const avatarUrl = await getRobloxAvatar(robloxId);
    user.avatarUrl = avatarUrl;
    writeDB(db);

    const { password: _, ...safeUser } = user;
    const token = jwt.sign({ userId: user.id, robloxId }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: safeUser });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong. Try again.' });
  }
});

// GET current user
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password: _, ...safeUser } = user;
  res.json({ user: safeUser });
});

// ─── Posts ───────────────────────────────────────────────────────────────────

app.get('/api/posts', (req, res) => {
  const db = readDB();
  const { tab = 'foryou', userId } = req.query;
  let posts = [...db.posts].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  if (tab === 'following' && userId) {
    const follows = db.follows.filter(f => f.followerId === userId).map(f => f.followingId);
    posts = posts.filter(p => follows.includes(p.authorId));
  }
  const enriched = posts.map(p => {
    const author = db.users.find(u => u.id === p.authorId) || {};
    const { password: _, ...safeAuthor } = author;
    const likes = db.likes.filter(l => l.postId === p.id).length;
    const comments = db.comments.filter(c => c.postId === p.id).length;
    const likedBy = userId ? db.likes.some(l => l.postId === p.id && l.userId === userId) : false;
    return { ...p, author: safeAuthor, likes, comments, likedBy };
  });
  res.json({ posts: enriched });
});

app.post('/api/posts', authMiddleware, (req, res) => {
  const { title, description, youtubeUrl, thumbnailUrl, mediaUrl, isVideo, tags, type } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required' });
  const ytId = youtubeUrl ? youtubeUrl.match(/(?:v=|youtu\.be\/)([^&\s]+)/)?.[1] : null;
  const thumb = thumbnailUrl || (ytId ? `https://img.youtube.com/vi/${ytId}/hqdefault.jpg` : null);
  const db = readDB();
  const post = {
    id: generateId(), authorId: req.user.userId, title,
    description: description || '', youtubeUrl: youtubeUrl || null, thumbnailUrl: thumb,
    mediaUrl: mediaUrl || null, isVideo: isVideo || false,
    youtubeId: ytId || null, tags: tags || [], type: type || 'gameplay',
    createdAt: new Date().toISOString(),
  };
  db.posts.push(post);
  writeDB(db);
  const author = db.users.find(u => u.id === req.user.userId);
  const { password: _, ...safeAuthor } = author;
  res.json({ post: { ...post, author: safeAuthor, likes: 0, comments: 0, likedBy: false } });
});

app.delete('/api/posts/:id', authMiddleware, (req, res) => {
  const db = readDB();
  const idx = db.posts.findIndex(p => p.id === req.params.id && p.authorId === req.user.userId);
  if (idx === -1) return res.status(404).json({ error: 'Post not found or not yours' });
  db.posts.splice(idx, 1);
  writeDB(db);
  res.json({ success: true });
});

// ─── Likes ───────────────────────────────────────────────────────────────────

app.post('/api/posts/:id/like', authMiddleware, (req, res) => {
  const db = readDB();
  const existing = db.likes.findIndex(l => l.postId === req.params.id && l.userId === req.user.userId);
  if (existing >= 0) {
    db.likes.splice(existing, 1);
    writeDB(db);
    return res.json({ liked: false, likes: db.likes.filter(l => l.postId === req.params.id).length });
  }
  db.likes.push({ postId: req.params.id, userId: req.user.userId, createdAt: new Date().toISOString() });
  writeDB(db);
  res.json({ liked: true, likes: db.likes.filter(l => l.postId === req.params.id).length });
});

// ─── Comments ────────────────────────────────────────────────────────────────

app.get('/api/posts/:id/comments', (req, res) => {
  const db = readDB();
  const comments = db.comments
    .filter(c => c.postId === req.params.id)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .map(c => {
      const author = db.users.find(u => u.id === c.userId) || {};
      const { password: _, ...safeAuthor } = author;
      return { ...c, author: safeAuthor };
    });
  res.json({ comments });
});

app.post('/api/posts/:id/comments', authMiddleware, (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Comment text required' });
  const db = readDB();
  const comment = { id: generateId(), postId: req.params.id, userId: req.user.userId, text, createdAt: new Date().toISOString() };
  db.comments.push(comment);
  writeDB(db);
  const author = db.users.find(u => u.id === req.user.userId);
  const { password: _, ...safeAuthor } = author;
  res.json({ comment: { ...comment, author: safeAuthor } });
});

// ─── Follow ──────────────────────────────────────────────────────────────────

app.post('/api/users/:id/follow', authMiddleware, (req, res) => {
  const db = readDB();
  const followerId = req.user.userId;
  const followingId = req.params.id;
  if (followerId === followingId) return res.status(400).json({ error: "Can't follow yourself" });
  const existing = db.follows.findIndex(f => f.followerId === followerId && f.followingId === followingId);
  if (existing >= 0) {
    db.follows.splice(existing, 1);
    writeDB(db);
    return res.json({ following: false });
  }
  db.follows.push({ followerId, followingId, createdAt: new Date().toISOString() });
  writeDB(db);
  res.json({ following: true });
});

// ─── Users ───────────────────────────────────────────────────────────────────

app.get('/api/users/:id', (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.params.id || u.username === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const { password: _, ...safeUser } = user;
  const followers = db.follows.filter(f => f.followingId === user.id).length;
  const following = db.follows.filter(f => f.followerId === user.id).length;
  const posts = db.posts.filter(p => p.authorId === user.id).length;
  res.json({ user: { ...safeUser, followers, following, posts } });
});

app.patch('/api/users/me', authMiddleware, (req, res) => {
  const { bio, displayName } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (bio !== undefined) user.bio = bio;
  if (displayName !== undefined) user.displayName = displayName;
  writeDB(db);
  const { password: _, ...safeUser } = user;
  res.json({ user: safeUser });
});



// ─── Upload Route ─────────────────────────────────────────────────────────────

app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  try {
    const isVideo = req.file.mimetype.startsWith('video/');
    
    // Upload to cloudinary from buffer
    const result = await new Promise((resolve, reject) => {
      const uploadStream = cloudinary.uploader.upload_stream(
        {
          resource_type: isVideo ? 'video' : 'image',
          folder: 'bloxpulse',
          transformation: isVideo ? [] : [{ quality: 'auto', fetch_format: 'auto' }],
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      );
      uploadStream.end(req.file.buffer);
    });

    res.json({
      url: result.secure_url,
      thumbnailUrl: isVideo 
        ? result.secure_url.replace('/upload/', '/upload/so_0/').replace(/\.mp4$/, '.jpg').replace(/\.webm$/, '.jpg').replace(/\.mov$/, '.jpg')
        : result.secure_url,
      isVideo,
      publicId: result.public_id,
    });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Upload failed. Try again.' });
  }
});

// ─── Admin Routes ────────────────────────────────────────────────────────────

const ADMIN_IDS = process.env.ADMIN_IDS ? process.env.ADMIN_IDS.split(',') : [];

function adminMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const db = readDB();
    const user = db.users.find(u => u.id === decoded.userId);
    if (!user || !user.isAdmin) return res.status(403).json({ error: 'Admin access required' });
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Get all users (admin)
app.get('/api/admin/users', adminMiddleware, (req, res) => {
  const db = readDB();
  const users = db.users.map(u => {
    const { password: _, ...safe } = u;
    return { ...safe, posts: db.posts.filter(p => p.authorId === u.id).length };
  });
  res.json({ users });
});

// Ban/unban user (admin)
app.post('/api/admin/users/:id/ban', adminMiddleware, (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.banned = !user.banned;
  writeDB(db);
  res.json({ banned: user.banned, username: user.username });
});

// Delete any post (admin)
app.delete('/api/admin/posts/:id', adminMiddleware, (req, res) => {
  const db = readDB();
  const idx = db.posts.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Post not found' });
  db.posts.splice(idx, 1);
  writeDB(db);
  res.json({ success: true });
});

// Get all reports (admin)
app.get('/api/admin/reports', adminMiddleware, (req, res) => {
  const db = readDB();
  if (!db.reports) db.reports = [];
  const enriched = db.reports.map(r => ({
    ...r,
    post: db.posts.find(p => p.id === r.postId) || null,
    reporter: db.users.find(u => u.id === r.reporterId) || null,
  }));
  res.json({ reports: enriched });
});

// Make user admin (admin)
app.post('/api/admin/users/:id/makeadmin', adminMiddleware, (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.isAdmin = !user.isAdmin;
  writeDB(db);
  res.json({ isAdmin: user.isAdmin });
});

// ─── Reports ─────────────────────────────────────────────────────────────────

app.post('/api/posts/:id/report', authMiddleware, (req, res) => {
  const { reason } = req.body;
  const db = readDB();
  if (!db.reports) db.reports = [];
  const existing = db.reports.find(r => r.postId === req.params.id && r.reporterId === req.user.userId);
  if (existing) return res.status(409).json({ error: 'You already reported this post' });
  db.reports.push({
    id: generateId(),
    postId: req.params.id,
    reporterId: req.user.userId,
    reason: reason || 'No reason given',
    createdAt: new Date().toISOString(),
  });
  writeDB(db);
  res.json({ success: true });
});

// ─── Start ───────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`BloxPulse backend running on http://localhost:${PORT}`);
});
