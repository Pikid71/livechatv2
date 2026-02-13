require('dotenv').config();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const mongoose = require('mongoose');
const multer = require('multer');
const sharp = require('sharp');
const fs = require('fs').promises;

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
    credentials: true
  },
  maxHttpBufferSize: 10 * 1024 * 1024 // 10MB for file uploads
});

// ============================================
// 🔐 ENVIRONMENT VARIABLES
// ============================================
const MONGODB_URI = process.env.MONGODB_URI;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const PORT = process.env.PORT || 3000;
const OWNER_USERNAME = 'Pi_Kid71'; // Owner username - special rank

// Validate environment variables
if (!MONGODB_URI || !ADMIN_PASSWORD) {
  console.error('❌ Missing required environment variables!');
  process.exit(1);
}

// ============================================
// 📁 FILE UPLOAD CONFIGURATION
// ============================================
const uploadDir = path.join(__dirname, 'uploads');
fs.mkdir(uploadDir, { recursive: true }).catch(console.error);

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'application/pdf', 'text/plain'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type'), false);
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: fileFilter
});

// Serve uploaded files
app.use('/uploads', express.static(uploadDir));

// ============================================
// 🔌 CONNECT TO MONGODB ATLAS
// ============================================
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('✅✅✅ MONGODB ATLAS CONNECTED SUCCESSFULLY!'))
.catch(err => {
  console.error('❌❌❌ MONGODB CONNECTION FAILED:', err.message);
  process.exit(1);
});

// ============================================
// 📊 MONGODB SCHEMAS
// ============================================

// User Schema with Ranks
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  rank: { 
    type: String, 
    enum: ['owner', 'admin', 'moderator', 'vip', 'member'],
    default: 'member'
  },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
  isBanned: { type: Boolean, default: false },
  avatar: { type: String, default: null },
  theme: { type: String, default: 'default' },
  effects: [{ type: String }] // Effects user has unlocked
});

// Room Schema
const RoomSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  password: { type: String, default: '' },
  isDefault: { type: Boolean, default: false },
  createdBy: { type: String },
  createdAt: { type: Date, default: Date.now },
  theme: { type: String, default: 'default' }
});

// Message Schema (includes private messages)
const MessageSchema = new mongoose.Schema({
  roomName: { type: String, index: true },
  username: { type: String, required: true },
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  isSystem: { type: Boolean, default: false },
  isPrivate: { type: Boolean, default: false },
  recipient: { type: String, default: null },
  senderRank: { type: String, default: 'member' },
  fileUrl: { type: String, default: null },
  fileName: { type: String, default: null },
  fileType: { type: String, default: null }
});

// Ban Schema
const BanSchema = new mongoose.Schema({
  roomName: { type: String, required: true, index: true },
  username: { type: String, required: true },
  bannedBy: { type: String, required: true },
  bannedByRank: { type: String, default: 'admin' },
  bannedAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true },
  isActive: { type: Boolean, default: true }
});

// Session Schema
const SessionSchema = new mongoose.Schema({
  socketId: { type: String, required: true, unique: true },
  username: { type: String, required: true },
  userRank: { type: String, default: 'member' },
  roomName: { type: String },
  connectedAt: { type: Date, default: Date.now },
  lastActivity: { type: Date, default: Date.now }
});

// Private Message Schema (for DM history)
const PrivateMessageSchema = new mongoose.Schema({
  from: { type: String, required: true },
  to: { type: String, required: true },
  message: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  read: { type: Boolean, default: false },
  fromRank: { type: String, default: 'member' }
});

// File Schema
const FileSchema = new mongoose.Schema({
  filename: { type: String, required: true },
  originalName: { type: String, required: true },
  uploadedBy: { type: String, required: true },
  uploadedAt: { type: Date, default: Date.now },
  fileSize: { type: Number, required: true },
  fileType: { type: String, required: true },
  roomName: { type: String, default: null },
  recipient: { type: String, default: null } // null = public, otherwise private
});

// ============================================
// 📁 MODELS
// ============================================
const User = mongoose.model('User', UserSchema);
const Room = mongoose.model('Room', RoomSchema);
const Message = mongoose.model('Message', MessageSchema);
const Ban = mongoose.model('Ban', BanSchema);
const Session = mongoose.model('Session', SessionSchema);
const PrivateMessage = mongoose.model('PrivateMessage', PrivateMessageSchema);
const File = mongoose.model('File', FileSchema);

// ============================================
// 🚀 EXPRESS SETUP
// ============================================
app.use(express.static(path.join(__dirname)));
app.use(express.json({ limit: '10mb' }));

// File upload endpoint
app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    // Optimize image if it's an image
    let finalPath = req.file.path;
    let fileSize = req.file.size;

    if (req.file.mimetype.startsWith('image/')) {
      const optimizedPath = path.join(uploadDir, 'optimized-' + req.file.filename);
      await sharp(req.file.path)
        .resize(1200, 1200, { fit: 'inside', withoutEnlargement: true })
        .jpeg({ quality: 80 })
        .toFile(optimizedPath);
      
      await fs.unlink(req.file.path);
      finalPath = optimizedPath;
      const stats = await fs.stat(optimizedPath);
      fileSize = stats.size;
    }

    const fileDoc = await File.create({
      filename: path.basename(finalPath),
      originalName: req.file.originalname,
      uploadedBy: req.body.username,
      fileSize: fileSize,
      fileType: req.file.mimetype,
      roomName: req.body.roomName || null,
      recipient: req.body.recipient || null
    });

    const fileUrl = `/uploads/${path.basename(finalPath)}`;
    
    res.json({
      success: true,
      fileUrl,
      fileName: req.file.originalname,
      fileType: req.file.mimetype,
      fileId: fileDoc._id
    });

  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy', 
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    version: '2.0.0',
    timestamp: new Date().toISOString()
  });
});

// Stats endpoint
app.get('/stats', async (req, res) => {
  try {
    const stats = {
      users: {
        total: await User.countDocuments(),
        owners: await User.countDocuments({ rank: 'owner' }),
        admins: await User.countDocuments({ rank: 'admin' }),
        moderators: await User.countDocuments({ rank: 'moderator' }),
        vips: await User.countDocuments({ rank: 'vip' }),
        members: await User.countDocuments({ rank: 'member' })
      },
      rooms: await Room.countDocuments(),
      messages: {
        total: await Message.countDocuments(),
        private: await PrivateMessage.countDocuments()
      },
      files: await File.countDocuments(),
      activeBans: await Ban.countDocuments({ isActive: true, expiresAt: { $gt: new Date() } }),
      activeSessions: await Session.countDocuments(),
      timestamp: new Date()
    };
    res.json(stats);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Main route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ============================================
// 🏠 INITIALIZE DEFAULT DATA
// ============================================
async function initializeDefaultData() {
  try {
    // Create default Main room
    const defaultRoom = await Room.findOne({ name: 'Main' });
    if (!defaultRoom) {
      await Room.create({
        name: 'Main',
        password: '',
        isDefault: true,
        createdBy: 'System',
        theme: 'default'
      });
      console.log('🏠 Default "Main" room created');
    }

    // Create owner account (Pi_Kid71)
    const ownerExists = await User.findOne({ username: OWNER_USERNAME });
    if (!ownerExists) {
      await User.create({
        username: OWNER_USERNAME,
        password: ADMIN_PASSWORD,
        rank: 'owner',
        lastLogin: new Date(),
        theme: 'dark',
        effects: ['glitch', 'flashbang', 'black', 'firework', 'gameroom', 'confetti', 'hack', 'matrix', 'rainbow', 'neon']
      });
      console.log(`👑 Owner account created: ${OWNER_USERNAME}`);
    } else {
      // Ensure owner has correct rank
      await User.updateOne(
        { username: OWNER_USERNAME },
        { rank: 'owner' }
      );
    }

    // Create default admin account
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
      await User.create({
        username: 'admin',
        password: ADMIN_PASSWORD,
        rank: 'admin',
        lastLogin: new Date()
      });
      console.log('👮 Default admin account created');
    }

  } catch (err) {
    console.error('Error initializing default data:', err);
  }
}

// Run initialization
initializeDefaultData();

// ============================================
// 🧹 CLEANUP FUNCTIONS
// ============================================
async function cleanupExpiredBans() {
  try {
    const result = await Ban.updateMany(
      { expiresAt: { $lt: new Date() }, isActive: true },
      { isActive: false }
    );
    if (result.modifiedCount > 0) {
      console.log(`🧹 Cleaned up ${result.modifiedCount} expired bans`);
    }
  } catch (err) {
    console.error('Error cleaning up bans:', err);
  }
}

async function cleanupOldFiles() {
  try {
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const oldFiles = await File.find({ uploadedAt: { $lt: oneDayAgo } });
    
    for (const file of oldFiles) {
      try {
        await fs.unlink(path.join(uploadDir, file.filename)).catch(() => {});
        await File.deleteOne({ _id: file._id });
      } catch (err) {
        console.error('Error deleting file:', err);
      }
    }
    
    if (oldFiles.length > 0) {
      console.log(`🧹 Cleaned up ${oldFiles.length} old files`);
    }
  } catch (err) {
    console.error('Error cleaning up files:', err);
  }
}

// Run cleanups every hour
setInterval(cleanupExpiredBans, 60 * 60 * 1000);
setInterval(cleanupOldFiles, 60 * 60 * 1000);

// ============================================
// 🔐 RANK PERMISSIONS SYSTEM
// ============================================
const PERMISSIONS = {
  owner: {
    level: 100,
    commands: ['*'], // All commands
    canBan: true,
    canUnban: true,
    canDeleteRoom: true,
    canClearMessages: true,
    canGrantRank: ['admin', 'moderator', 'vip', 'member'],
    canSeePrivateMessages: true,
    canUseEffects: true,
    canUploadFiles: true,
    maxFileSize: 50 * 1024 * 1024 // 50MB
  },
  admin: {
    level: 80,
    commands: ['clear', 'ban', 'unban', 'delete', 'effect', 'msg', 'file', 'theme', 'announce'],
    canBan: true,
    canUnban: true,
    canDeleteRoom: true,
    canClearMessages: true,
    canGrantRank: ['moderator', 'vip', 'member'],
    canSeePrivateMessages: true,
    canUseEffects: true,
    canUploadFiles: true,
    maxFileSize: 20 * 1024 * 1024 // 20MB
  },
  moderator: {
    level: 60,
    commands: ['clear', 'ban', 'msg', 'file', 'flip', 'roll'],
    canBan: true,
    canUnban: false,
    canDeleteRoom: false,
    canClearMessages: true,
    canGrantRank: [],
    canSeePrivateMessages: false,
    canUseEffects: false,
    canUploadFiles: true,
    maxFileSize: 10 * 1024 * 1024 // 10MB
  },
  vip: {
    level: 40,
    commands: ['msg', 'file', 'flip', 'roll', 'theme', 'color'],
    canBan: false,
    canUnban: false,
    canDeleteRoom: false,
    canClearMessages: false,
    canGrantRank: [],
    canSeePrivateMessages: false,
    canUseEffects: false,
    canUploadFiles: true,
    maxFileSize: 5 * 1024 * 1024 // 5MB
  },
  member: {
    level: 20,
    commands: ['msg', 'flip', 'roll', 'color'],
    canBan: false,
    canUnban: false,
    canDeleteRoom: false,
    canClearMessages: false,
    canGrantRank: [],
    canSeePrivateMessages: false,
    canUseEffects: false,
    canUploadFiles: false,
    maxFileSize: 0 // Cannot upload
  }
};

// Helper function to check if user has permission
function hasPermission(user, command) {
  if (!user) return false;
  const permissions = PERMISSIONS[user.rank];
  if (!permissions) return false;
  
  if (permissions.commands.includes('*')) return true;
  return permissions.commands.includes(command);
}

// ============================================
// 🔌 SOCKET.IO HANDLERS
// ============================================
io.on('connection', (socket) => {
  console.log('👤 User connected:', socket.id);
  
  // ========== AUTHENTICATION ==========
  
  // Register new user
  socket.on('register', async (data) => {
    try {
      const { username, password } = data;
      
      if (!username || !password) {
        socket.emit('auth_error', { message: 'Username and password required' });
        return;
      }
      
      if (username.length < 3) {
        socket.emit('auth_error', { message: 'Username must be at least 3 characters' });
        return;
      }
      
      if (password.length < 4) {
        socket.emit('auth_error', { message: 'Password must be at least 4 characters' });
        return;
      }
      
      // Check if username already exists
      const existingUser = await User.findOne({ username });
      if (existingUser) {
        socket.emit('auth_error', { message: 'Username already exists' });
        return;
      }
      
      // Check if this is the owner username
      let rank = 'member';
      if (username === OWNER_USERNAME) {
        rank = 'owner';
      }
      
      // Create user
      await User.create({
        username,
        password,
        rank,
        lastLogin: new Date()
      });
      
      // Create session
      await Session.create({
        socketId: socket.id,
        username,
        userRank: rank
      });
      
      socket.emit('auth_success', { 
        username, 
        rank,
        message: 'Registration successful!' 
      });
      
      console.log(`✅ User registered: ${username} (${rank})`);
      
    } catch (err) {
      console.error('Registration error:', err);
      socket.emit('auth_error', { message: 'Server error during registration' });
    }
  });
  
  // Login user
  socket.on('login', async (data) => {
    try {
      const { username, password } = data;
      
      if (!username || !password) {
        socket.emit('auth_error', { message: 'Username and password required' });
        return;
      }
      
      let user = await User.findOne({ username });
      
      // If user doesn't exist and it's the owner username, create owner account
      if (!user && username === OWNER_USERNAME) {
        user = await User.create({
          username: OWNER_USERNAME,
          password: ADMIN_PASSWORD,
          rank: 'owner',
          lastLogin: new Date()
        });
        console.log(`👑 Owner account created on login: ${OWNER_USERNAME}`);
      } else if (!user) {
        socket.emit('auth_error', { message: 'Username not found' });
        return;
      }
      
      if (user.password !== password) {
        socket.emit('auth_error', { message: 'Incorrect password' });
        return;
      }
      
      // Check if user is banned globally
      if (user.isBanned) {
        socket.emit('auth_error', { message: 'This account has been banned' });
        return;
      }
      
      // Ensure owner always has owner rank
      if (username === OWNER_USERNAME && user.rank !== 'owner') {
        user.rank = 'owner';
      }
      
      // Update last login
      user.lastLogin = new Date();
      await user.save();
      
      // Create session
      await Session.create({
        socketId: socket.id,
        username,
        userRank: user.rank
      });
      
      socket.emit('auth_success', { 
        username, 
        rank: user.rank,
        theme: user.theme || 'default',
        message: 'Login successful!' 
      });
      
      console.log(`✅ User logged in: ${username} (${user.rank})`);
      
    } catch (err) {
      console.error('Login error:', err);
      socket.emit('auth_error', { message: 'Server error during login' });
    }
  });
  
  // Logout
  socket.on('logout', async () => {
    try {
      await Session.deleteOne({ socketId: socket.id });
      socket.emit('logged_out');
      console.log('👋 User logged out:', socket.id);
    } catch (err) {
      console.error('Logout error:', err);
    }
  });
  
  // Check authentication
  socket.on('check_auth', async () => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      if (session) {
        const user = await User.findOne({ username: session.username });
        socket.emit('auth_status', { 
          authenticated: true, 
          username: session.username,
          rank: user ? user.rank : 'member',
          theme: user ? user.theme : 'default'
        });
      } else {
        socket.emit('auth_status', { authenticated: false });
      }
    } catch (err) {
      socket.emit('auth_status', { authenticated: false });
    }
  });
  
  // ========== ROOMS ==========
  
  // Get rooms list
  socket.on('get_rooms', async () => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      if (!session) {
        socket.emit('auth_error', { message: 'Not authenticated' });
        return;
      }
      
      const rooms = await Room.find();
      
      const roomList = await Promise.all(rooms.map(async (room) => {
        const sessions = await Session.find({ roomName: room.name });
        return {
          name: room.name,
          hasPassword: !!room.password,
          members: sessions.length,
          isDefault: room.isDefault,
          theme: room.theme || 'default'
        };
      }));
      
      socket.emit('rooms_list', roomList);
      
    } catch (err) {
      console.error('Get rooms error:', err);
      socket.emit('error', { message: 'Failed to get rooms' });
    }
  });
  
  // Create room
  socket.on('create_room', async (data) => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      if (!session) {
        socket.emit('auth_error', { message: 'Not authenticated' });
        return;
      }
      
      const user = await User.findOne({ username: session.username });
      
      const { roomName, password, theme = 'default' } = data;
      
      if (!roomName || roomName.trim() === '') {
        socket.emit('error', { message: 'Room name cannot be empty' });
        return;
      }
      
      const existingRoom = await Room.findOne({ name: roomName });
      if (existingRoom) {
        socket.emit('error', { message: 'Room already exists' });
        return;
      }
      
      await Room.create({
        name: roomName,
        password: password || '',
        createdBy: session.username,
        isDefault: false,
        theme
      });
      
      // Join room
      session.roomName = roomName;
      await session.save();
      socket.join(roomName);
      
      socket.emit('joined_room', { 
        roomName, 
        username: session.username,
        rank: user.rank,
        theme
      });
      
      const roomSessions = await Session.find({ roomName });
      io.to(roomName).emit('user_joined', {
        username: session.username,
        rank: user.rank,
        members: roomSessions.length
      });
      
      const systemMessage = await Message.create({
        roomName,
        username: 'System',
        message: `🎉 Room "${roomName}" created by ${session.username} (${user.rank})`,
        isSystem: true,
        senderRank: 'system'
      });
      
      io.to(roomName).emit('chat message', {
        username: 'System',
        message: systemMessage.message,
        timestamp: systemMessage.timestamp.toLocaleTimeString(),
        rank: 'system'
      });
      
      io.emit('room_created', { 
        name: roomName, 
        hasPassword: !!password,
        members: 1,
        theme
      });
      
      console.log(`🏠 Room created: ${roomName} by ${session.username} (${user.rank})`);
      
    } catch (err) {
      console.error('Create room error:', err);
      socket.emit('error', { message: 'Failed to create room' });
    }
  });
  
  // Join room
  socket.on('join_room', async (data) => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      if (!session) {
        socket.emit('auth_error', { message: 'Not authenticated' });
        return;
      }
      
      const user = await User.findOne({ username: session.username });
      
      const { roomName, password } = data;
      
      const room = await Room.findOne({ name: roomName });
      if (!room) {
        socket.emit('error', { message: 'Room does not exist' });
        return;
      }
      
      // Check if banned
      const activeBan = await Ban.findOne({
        roomName,
        username: session.username,
        isActive: true,
        expiresAt: { $gt: new Date() }
      });
      
      if (activeBan) {
        socket.emit('error', { message: '❌ You are banned from this room' });
        return;
      }
      
      // Check password
      if (room.password && room.password !== password) {
        socket.emit('error', { message: 'Incorrect password' });
        return;
      }
      
      // Leave old room if exists
      if (session.roomName && session.roomName !== roomName) {
        const oldRoom = session.roomName;
        session.roomName = null;
        await session.save();
        socket.leave(oldRoom);
        
        const oldRoomSessions = await Session.find({ roomName: oldRoom });
        io.to(oldRoom).emit('user_left', {
          username: session.username,
          rank: user.rank,
          members: oldRoomSessions.length
        });
      }
      
      // Join new room
      session.roomName = roomName;
      await session.save();
      socket.join(roomName);
      
      socket.emit('joined_room', { 
        roomName, 
        username: session.username,
        rank: user.rank,
        theme: room.theme || 'default'
      });
      
      // Send room history (last 50 messages)
      const recentMessages = await Message.find({ roomName })
        .sort({ timestamp: -1 })
        .limit(50)
        .sort({ timestamp: 1 });
      
      socket.emit('room_history', {
        messages: recentMessages.map(msg => ({
          username: msg.username,
          message: msg.message,
          timestamp: msg.timestamp.toLocaleTimeString(),
          rank: msg.senderRank,
          isPrivate: msg.isPrivate,
          recipient: msg.recipient,
          fileUrl: msg.fileUrl,
          fileName: msg.fileName,
          fileType: msg.fileType
        }))
      });
      
      // Notify others
      const roomSessions = await Session.find({ roomName });
      io.to(roomName).emit('user_joined', {
        username: session.username,
        rank: user.rank,
        members: roomSessions.length
      });
      
      // System message
      const systemMessage = await Message.create({
        roomName,
        username: 'System',
        message: `👋 ${session.username} (${user.rank}) joined the room`,
        isSystem: true,
        senderRank: 'system'
      });
      
      io.to(roomName).emit('chat message', {
        username: 'System',
        message: systemMessage.message,
        timestamp: systemMessage.timestamp.toLocaleTimeString(),
        rank: 'system'
      });
      
      console.log(`🚪 ${session.username} (${user.rank}) joined room: ${roomName}`);
      
    } catch (err) {
      console.error('Join room error:', err);
      socket.emit('error', { message: 'Failed to join room' });
    }
  });
  
  // Leave room
  socket.on('leave_room', async () => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      if (!session) return;
      
      const user = await User.findOne({ username: session.username });
      const roomName = session.roomName;
      if (!roomName) return;
      
      session.roomName = null;
      await session.save();
      socket.leave(roomName);
      
      const roomSessions = await Session.find({ roomName });
      const memberCount = roomSessions.length;
      
      io.to(roomName).emit('user_left', {
        username: session.username,
        rank: user ? user.rank : 'member',
        members: memberCount
      });
      
      const systemMessage = await Message.create({
        roomName,
        username: 'System',
        message: `👋 ${session.username} left the room`,
        isSystem: true,
        senderRank: 'system'
      });
      
      io.to(roomName).emit('chat message', {
        username: 'System',
        message: systemMessage.message,
        timestamp: systemMessage.timestamp.toLocaleTimeString(),
        rank: 'system'
      });
      
      console.log(`🚪 ${session.username} left room: ${roomName} (${memberCount} members remain)`);
      
      // Delete empty non-default rooms
      if (memberCount === 0) {
        const room = await Room.findOne({ name: roomName });
        if (room && !room.isDefault) {
          await Room.deleteOne({ name: roomName });
          await Message.deleteMany({ roomName });
          await Ban.deleteMany({ roomName });
          io.emit('room_deleted', { name: roomName });
          console.log('🗑️ Empty room deleted:', roomName);
        }
      }
      
    } catch (err) {
      console.error('Leave room error:', err);
    }
  });
  
  // ========== MESSAGES & PRIVATE MESSAGES ==========
  
  // Public chat message
  socket.on('chat message', async (msg) => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      if (!session || !session.roomName) return;
      
      const user = await User.findOne({ username: session.username });
      const roomName = session.roomName;
      const username = msg.username;
      
      // Check if banned
      const activeBan = await Ban.findOne({
        roomName,
        username,
        isActive: true,
        expiresAt: { $gt: new Date() }
      });
      
      if (activeBan) {
        socket.emit('error', { message: '❌ You are currently banned from this room' });
        return;
      }
      
      const messageData = await Message.create({
        roomName,
        username,
        message: msg.message,
        isSystem: false,
        senderRank: user ? user.rank : 'member',
        isPrivate: false
      });
      
      socket.broadcast.to(roomName).emit('chat message', {
        username,
        message: msg.message,
        timestamp: messageData.timestamp.toLocaleTimeString(),
        rank: user ? user.rank : 'member'
      });
      
      session.lastActivity = new Date();
      await session.save();
      
    } catch (err) {
      console.error('Message error:', err);
    }
  });
  
  // Private message (/msg command)
  socket.on('private_message', async (data) => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      if (!session) {
        socket.emit('error', { message: 'Not authenticated' });
        return;
      }
      
      const sender = await User.findOne({ username: session.username });
      const { recipient, message } = data;
      
      // Check if recipient exists
      const recipientUser = await User.findOne({ username: recipient });
      if (!recipientUser) {
        socket.emit('error', { message: `User '${recipient}' not found` });
        return;
      }
      
      // Check if recipient is online
      const recipientSession = await Session.findOne({ username: recipient });
      
      // Save private message to database
      const privateMsg = await PrivateMessage.create({
        from: session.username,
        to: recipient,
        message,
        timestamp: new Date(),
        fromRank: sender.rank,
        read: false
      });
      
      // Send to recipient if online
      if (recipientSession) {
        io.to(recipientSession.socketId).emit('private_message', {
          from: session.username,
          fromRank: sender.rank,
          message,
          timestamp: privateMsg.timestamp.toLocaleTimeString()
        });
      }
      
      // Send confirmation to sender
      socket.emit('private_message_sent', {
        to: recipient,
        toRank: recipientUser.rank,
        message,
        timestamp: privateMsg.timestamp.toLocaleTimeString()
      });
      
      // ADMINS AND OWNER can see private messages in their current room
      if (sender.rank === 'admin' || sender.rank === 'owner') {
        if (session.roomName) {
          io.to(session.roomName).emit('admin_private_message_log', {
            from: session.username,
            to: recipient,
            message,
            timestamp: privateMsg.timestamp.toLocaleTimeString()
          });
        }
      }
      
      console.log(`💌 Private message: ${session.username} -> ${recipient}`);
      
    } catch (err) {
      console.error('Private message error:', err);
      socket.emit('error', { message: 'Failed to send private message' });
    }
  });
  
  // Get private message history
  socket.on('get_private_messages', async (data) => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      if (!session) return;
      
      const { withUser } = data;
      
      const messages = await PrivateMessage.find({
        $or: [
          { from: session.username, to: withUser },
          { from: withUser, to: session.username }
        ]
      })
      .sort({ timestamp: -1 })
      .limit(50)
      .sort({ timestamp: 1 });
      
      socket.emit('private_message_history', {
        with: withUser,
        messages: messages.map(msg => ({
          from: msg.from,
          fromRank: msg.fromRank,
          message: msg.message,
          timestamp: msg.timestamp.toLocaleTimeString(),
          read: msg.read
        }))
      });
      
    } catch (err) {
      console.error('Get private messages error:', err);
    }
  });
  
  // ========== FILE SHARING ==========
  
  // Share file in room
  socket.on('share_file', async (data) => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      if (!session || !session.roomName) {
        socket.emit('error', { message: 'Not in a room' });
        return;
      }
      
      const user = await User.findOne({ username: session.username });
      const permissions = PERMISSIONS[user.rank];
      
      if (!permissions.canUploadFiles) {
        socket.emit('error', { message: '❌ Your rank does not allow file sharing' });
        return;
      }
      
      const { fileUrl, fileName, fileType } = data;
      const roomName = session.roomName;
      
      const messageData = await Message.create({
        roomName,
        username: session.username,
        message: `📁 Shared file: ${fileName}`,
        isSystem: false,
        senderRank: user.rank,
        fileUrl,
        fileName,
        fileType
      });
      
      io.to(roomName).emit('chat message', {
        username: session.username,
        message: `📁 Shared file: ${fileName}`,
        fileUrl,
        fileName,
        fileType,
        timestamp: messageData.timestamp.toLocaleTimeString(),
        rank: user.rank
      });
      
      console.log(`📁 File shared by ${session.username}: ${fileName}`);
      
    } catch (err) {
      console.error('Share file error:', err);
      socket.emit('error', { message: 'Failed to share file' });
    }
  });
  
  // ========== RANK MANAGEMENT ==========
  
  // Grant rank (admin/owner only)
  socket.on('grant_rank', async (data) => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      if (!session) return;
      
      const granter = await User.findOne({ username: session.username });
      const { targetUser, newRank, password } = data;
      
      // Check permissions
      const granterPermissions = PERMISSIONS[granter.rank];
      
      if (!granterPermissions.canGrantRank || granterPermissions.canGrantRank.length === 0) {
        socket.emit('error', { message: '❌ You do not have permission to grant ranks' });
        return;
      }
      
      // Check if target rank is allowed
      if (!granterPermissions.canGrantRank.includes(newRank)) {
        socket.emit('error', { message: `❌ You cannot grant the rank '${newRank}'` });
        return;
      }
      
      // Verify password for non-owners
      if (granter.rank !== 'owner' && password !== ADMIN_PASSWORD) {
        socket.emit('error', { message: '❌ Incorrect admin password' });
        return;
      }
      
      const target = await User.findOne({ username: targetUser });
      if (!target) {
        socket.emit('error', { message: 'User not found' });
        return;
      }
      
      // Cannot change owner's rank
      if (target.username === OWNER_USERNAME) {
        socket.emit('error', { message: '❌ Cannot change owner rank' });
        return;
      }
      
      target.rank = newRank;
      await target.save();
      
      // Notify target if online
      const targetSession = await Session.findOne({ username: targetUser });
      if (targetSession) {
        io.to(targetSession.socketId).emit('rank_changed', {
          newRank,
          grantedBy: session.username
        });
      }
      
      io.emit('system_notification', {
        message: `👑 ${session.username} promoted ${targetUser} to ${newRank}`
      });
      
      console.log(`👑 Rank granted: ${targetUser} is now ${newRank} by ${session.username}`);
      
    } catch (err) {
      console.error('Grant rank error:', err);
      socket.emit('error', { message: 'Failed to grant rank' });
    }
  });
  
  // ========== EFFECTS & THEMES ==========
  
  // Apply effect to room (admin/owner only)
  socket.on('effect_command', async (data) => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      if (!session || !session.roomName) return;
      
      const user = await User.findOne({ username: session.username });
      const permissions = PERMISSIONS[user.rank];
      
      if (!permissions.canUseEffects) {
        socket.emit('command_error', { message: '❌ Your rank does not allow effects' });
        return;
      }
      
      const { effect } = data;
      const roomName = session.roomName;
      
      const validEffects = [
        'glitch', 'flashbang', 'black', 'firework', 
        'gameroom', 'confetti', 'hack', 'matrix', 
        'rainbow', 'neon', 'vintage', 'ocean'
      ];
      
      if (!validEffects.includes(effect)) {
        socket.emit('command_error', { message: '❌ Invalid effect!' });
        return;
      }
      
      io.to(roomName).emit('room_effect', {
        effect,
        triggeredBy: session.username,
        rank: user.rank
      });
      
      const systemMessage = await Message.create({
        roomName,
        username: 'System',
        message: `✨ ${session.username} (${user.rank}) triggered effect: ${effect}`,
        isSystem: true,
        senderRank: 'system'
      });
      
      io.to(roomName).emit('chat message', {
        username: 'System',
        message: systemMessage.message,
        timestamp: systemMessage.timestamp.toLocaleTimeString(),
        rank: 'system'
      });
      
      console.log(`✨ Effect ${effect} triggered by ${session.username} in ${roomName}`);
      
    } catch (err) {
      console.error('Effect command error:', err);
      socket.emit('command_error', { message: 'Failed to trigger effect' });
    }
  });
  
  // Change theme (vip+ only)
  socket.on('change_theme', async (data) => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      if (!session) return;
      
      const user = await User.findOne({ username: session.username });
      const permissions = PERMISSIONS[user.rank];
      
      // Vip and above can change themes
      if (user.rank !== 'vip' && user.rank !== 'moderator' && 
          user.rank !== 'admin' && user.rank !== 'owner') {
        socket.emit('error', { message: '❌ Vip+ only can change themes' });
        return;
      }
      
      const { theme, scope } = data; // scope: 'personal' or 'room'
      
      const validThemes = [
        'default', 'dark', 'light', 'neon', 'midnight', 
        'sunset', 'forest', 'ocean', 'cyberpunk', 'vintage'
      ];
      
      if (!validThemes.includes(theme)) {
        socket.emit('error', { message: '❌ Invalid theme' });
        return;
      }
      
      if (scope === 'personal') {
        user.theme = theme;
        await user.save();
        socket.emit('theme_applied', { theme, scope: 'personal' });
      } else if (scope === 'room' && session.roomName) {
        const room = await Room.findOne({ name: session.roomName });
        if (room) {
          room.theme = theme;
          await room.save();
          io.to(session.roomName).emit('theme_applied', { 
            theme, 
            scope: 'room',
            changedBy: session.username 
          });
        }
      }
      
      console.log(`🎨 Theme changed: ${theme} (${scope}) by ${session.username}`);
      
    } catch (err) {
      console.error('Theme change error:', err);
      socket.emit('error', { message: 'Failed to change theme' });
    }
  });
  
  // ========== MODERATION COMMANDS ==========
  
  // Clear messages
  socket.on('clear_messages', async (data) => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      if (!session || !session.roomName) return;
      
      const user = await User.findOne({ username: session.username });
      const { roomName, password } = data;
      
      if (!hasPermission(user, 'clear')) {
        socket.emit('error', { message: '❌ You do not have permission to clear messages' });
        return;
      }
      
      // Check password for non-admins/owners
      if (user.rank !== 'admin' && user.rank !== 'owner' && password !== ADMIN_PASSWORD) {
        socket.emit('error', { message: '❌ Incorrect admin password' });
        return;
      }
      
      await Message.deleteMany({ roomName });
      
      io.to(roomName).emit('messages_cleared', { roomName });
      
      const systemMessage = await Message.create({
        roomName,
        username: 'System',
        message: `🧹 ${session.username} (${user.rank}) cleared all messages`,
        isSystem: true,
        senderRank: 'system'
      });
      
      io.to(roomName).emit('chat message', {
        username: 'System',
        message: systemMessage.message,
        timestamp: systemMessage.timestamp.toLocaleTimeString(),
        rank: 'system'
      });
      
      console.log(`🧹 Messages cleared in ${roomName} by ${session.username} (${user.rank})`);
      
    } catch (err) {
      console.error('Clear messages error:', err);
    }
  });
  
  // Ban user
  socket.on('ban_user', async (data) => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      if (!session || !session.roomName) return;
      
      const banner = await User.findOne({ username: session.username });
      const permissions = PERMISSIONS[banner.rank];
      
      if (!permissions.canBan) {
        socket.emit('error', { message: '❌ You do not have permission to ban users' });
        return;
      }
      
      const { roomName, bannedUser, duration = '10m', bannerName, password } = data;
      
      // Check password for moderators (admins/owners don't need password)
      if (banner.rank === 'moderator' && password !== ADMIN_PASSWORD) {
        socket.emit('error', { message: '❌ Incorrect admin password' });
        return;
      }
      
      const room = await Room.findOne({ name: roomName });
      if (!room) {
        socket.emit('error', { message: 'Room does not exist' });
        return;
      }
      
      // Cannot ban owner or admins if you're not owner
      const targetUser = await User.findOne({ username: bannedUser });
      if (targetUser) {
        if (targetUser.rank === 'owner') {
          socket.emit('error', { message: '❌ Cannot ban the owner' });
          return;
        }
        if (targetUser.rank === 'admin' && banner.rank !== 'owner') {
          socket.emit('error', { message: '❌ Only the owner can ban admins' });
          return;
        }
      }
      
      // Parse duration
      let durationMs = 10 * 60 * 1000;
      const match = duration.match(/^(\d+)([hmd]?)$/);
      if (match) {
        const value = parseInt(match[1]);
        const unit = match[2] || 'm';
        if (unit === 'h') durationMs = value * 60 * 60 * 1000;
        else if (unit === 'm') durationMs = value * 60 * 1000;
        else if (unit === 'd') durationMs = value * 24 * 60 * 60 * 1000;
      }
      
      const expiresAt = new Date(Date.now() + durationMs);
      
      await Ban.updateMany(
        { roomName, username: bannedUser, isActive: true },
        { isActive: false }
      );
      
      await Ban.create({
        roomName,
        username: bannedUser,
        bannedBy: bannerName,
        bannedByRank: banner.rank,
        expiresAt,
        isActive: true
      });
      
      io.to(roomName).emit('user_banned', { 
        bannedUser, 
        duration, 
        bannerName,
        bannerRank: banner.rank 
      });
      
      const systemMessage = await Message.create({
        roomName,
        username: 'System',
        message: `⛔ ${banner.rank} ${bannerName} banned ${bannedUser} for ${duration}`,
        isSystem: true,
        senderRank: 'system'
      });
      
      io.to(roomName).emit('chat message', {
        username: 'System',
        message: systemMessage.message,
        timestamp: systemMessage.timestamp.toLocaleTimeString(),
        rank: 'system'
      });
      
      // Kick user if in room
      const bannedSession = await Session.findOne({ username: bannedUser, roomName });
      if (bannedSession) {
        bannedSession.roomName = null;
        await bannedSession.save();
        io.to(bannedSession.socketId).emit('force_leave', { roomName, reason: 'banned' });
      }
      
      console.log(`🔨 ${bannedUser} banned from ${roomName} for ${duration} by ${bannerName} (${banner.rank})`);
      
    } catch (err) {
      console.error('Ban error:', err);
      socket.emit('error', { message: 'Failed to ban user' });
    }
  });
  
  // Unban user
  socket.on('unban_user', async (data) => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      if (!session || !session.roomName) return;
      
      const unbanner = await User.findOne({ username: session.username });
      const permissions = PERMISSIONS[unbanner.rank];
      
      if (!permissions.canUnban) {
        socket.emit('error', { message: '❌ You do not have permission to unban users' });
        return;
      }
      
      const { roomName, unbannedUser, unbannerName, password } = data;
      
      if (unbanner.rank === 'moderator' && password !== ADMIN_PASSWORD) {
        socket.emit('error', { message: '❌ Incorrect admin password' });
        return;
      }
      
      const room = await Room.findOne({ name: roomName });
      if (!room) {
        socket.emit('error', { message: 'Room does not exist' });
        return;
      }
      
      await Ban.updateMany(
        { roomName, username: unbannedUser, isActive: true },
        { isActive: false }
      );
      
      io.to(roomName).emit('user_unbanned', { 
        unbannedUser, 
        unbannerName,
        unbannerRank: unbanner.rank 
      });
      
      const systemMessage = await Message.create({
        roomName,
        username: 'System',
        message: `✅ ${unbanner.rank} ${unbannerName} unbanned ${unbannedUser}`,
        isSystem: true,
        senderRank: 'system'
      });
      
      io.to(roomName).emit('chat message', {
        username: 'System',
        message: systemMessage.message,
        timestamp: systemMessage.timestamp.toLocaleTimeString(),
        rank: 'system'
      });
      
      console.log(`✅ ${unbannedUser} unbanned from ${roomName} by ${unbannerName} (${unbanner.rank})`);
      
    } catch (err) {
      console.error('Unban error:', err);
      socket.emit('error', { message: 'Failed to unban user' });
    }
  });
  
  // Delete room
  socket.on('delete_room', async (data) => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      if (!session) return;
      
      const user = await User.findOne({ username: session.username });
      const permissions = PERMISSIONS[user.rank];
      
      if (!permissions.canDeleteRoom) {
        socket.emit('error', { message: '❌ You do not have permission to delete rooms' });
        return;
      }
      
      const { roomName, password } = data;
      
      if (user.rank !== 'admin' && user.rank !== 'owner' && password !== ADMIN_PASSWORD) {
        socket.emit('error', { message: '❌ Incorrect admin password' });
        return;
      }
      
      const room = await Room.findOne({ name: roomName });
      if (!room) {
        socket.emit('error', { message: 'Room does not exist' });
        return;
      }
      
      if (room.isDefault) {
        socket.emit('error', { message: 'Cannot delete the Main room' });
        return;
      }
      
      await Room.deleteOne({ name: roomName });
      await Message.deleteMany({ roomName });
      await Ban.deleteMany({ roomName });
      
      const roomSessions = await Session.find({ roomName });
      for (const session of roomSessions) {
        session.roomName = null;
        await session.save();
        io.to(session.socketId).emit('room_deleted_by_owner', { roomName });
      }
      
      io.emit('room_deleted', { name: roomName });
      
      console.log(`🗑️ Room deleted: ${roomName} by ${session.username} (${user.rank})`);
      
    } catch (err) {
      console.error('Delete room error:', err);
      socket.emit('error', { message: 'Failed to delete room' });
    }
  });
  
  // ========== VOICE CHAT (WebRTC Signaling) ==========
  
  // Voice chat signaling
  socket.on('voice_offer', (data) => {
    const { target, offer, roomName } = data;
    io.to(target).emit('voice_offer', {
      from: socket.id,
      offer,
      roomName
    });
  });
  
  socket.on('voice_answer', (data) => {
    const { target, answer } = data;
    io.to(target).emit('voice_answer', {
      from: socket.id,
      answer
    });
  });
  
  socket.on('ice_candidate', (data) => {
    const { target, candidate } = data;
    io.to(target).emit('ice_candidate', {
      from: socket.id,
      candidate
    });
  });
  
  socket.on('join_voice', (data) => {
    const { roomName } = data;
    socket.join(`voice:${roomName}`);
    socket.to(`voice:${roomName}`).emit('user_joined_voice', {
      userId: socket.id,
      username: session?.username || 'Unknown'
    });
  });
  
  socket.on('leave_voice', (data) => {
    const { roomName } = data;
    socket.leave(`voice:${roomName}`);
    socket.to(`voice:${roomName}`).emit('user_left_voice', {
      userId: socket.id
    });
  });
  
  // ========== DISCONNECT ==========
  
  socket.on('disconnect', async () => {
    try {
      const session = await Session.findOne({ socketId: socket.id });
      
      if (session) {
        const user = await User.findOne({ username: session.username });
        const roomName = session.roomName;
        const username = session.username;
        
        if (roomName) {
          await Session.deleteOne({ socketId: socket.id });
          const roomSessions = await Session.find({ roomName });
          const memberCount = roomSessions.length;
          
          io.to(roomName).emit('user_left', {
            username,
            rank: user ? user.rank : 'member',
            members: memberCount
          });
          
          const systemMessage = await Message.create({
            roomName,
            username: 'System',
            message: `👋 ${username} disconnected`,
            isSystem: true,
            senderRank: 'system'
          });
          
          io.to(roomName).emit('chat message', {
            username: 'System',
            message: systemMessage.message,
            timestamp: systemMessage.timestamp.toLocaleTimeString(),
            rank: 'system'
          });
          
          console.log(`👋 ${username} disconnected from ${roomName} (${memberCount} members remain)`);
          
          if (memberCount === 0) {
            const room = await Room.findOne({ name: roomName });
            if (room && !room.isDefault) {
              await Room.deleteOne({ name: roomName });
              await Message.deleteMany({ roomName });
              await Ban.deleteMany({ roomName });
              io.emit('room_deleted', { name: roomName });
              console.log('🗑️ Empty room deleted:', roomName);
            }
          }
        } else {
          await Session.deleteOne({ socketId: socket.id });
          console.log('👋 User disconnected:', username);
        }
      }
      
    } catch (err) {
      console.error('Disconnect error:', err);
      await Session.deleteOne({ socketId: socket.id }).catch(() => {});
    }
  });
});

// ============================================
// 🚀 START SERVER
// ============================================
server.listen(PORT, '0.0.0.0', () => {
  console.log('\n' + '='.repeat(70));
  console.log('🚀🚀🚀 BLACK HOLE CHAT V2 - PRODUCTION READY 🚀🚀🚀');
  console.log('='.repeat(70));
  console.log(`\n📡 Port: ${PORT}`);
  console.log(`💾 MongoDB: ${MONGODB_URI.replace(/:[^:@]*@/, ':****@')}`);
  console.log(`👑 Owner: ${OWNER_USERNAME}`);
  console.log(`🔑 Admin Password: ${ADMIN_PASSWORD.replace(/./g, '*')} (hidden)`);
  console.log('\n📊 RANK SYSTEM:');
  console.log('   👑 Owner    - Full access, can grant any rank');
  console.log('   👮 Admin    - Can ban, delete rooms, effects, see DMs');
  console.log('   🛡️ Moderator - Can ban, clear messages');
  console.log('   ⭐ VIP      - Can share files, change themes');
  console.log('   👤 Member   - Basic chat, /flip, /roll');
  console.log('\n🎮 NEW FEATURES:');
  console.log('   💬 Private messages - /msg <user> <text>');
  console.log('   📁 File sharing     - Images, PDFs, text files');
  console.log('   🎨 Custom themes    - /theme <name>');
  console.log('   🎯 New effects      - hack, matrix, rainbow, neon');
  console.log('   🎤 Voice chat       - Click voice button in room');
  console.log('\n' + '='.repeat(70) + '\n');
});

module.exports = { app, server, io };