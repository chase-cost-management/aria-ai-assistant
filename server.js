// server.js
require('dotenv').config();

const session = require('express-session');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const express  = require('express');
const cors     = require('cors');
const multer   = require('multer');
const mysql    = require('mysql2/promise');
const path     = require('path');
const fs       = require('fs');
const axios    = require('axios');
const pdf      = require('pdf-parse');
const mammoth  = require('mammoth');
const AWS      = require('aws-sdk');
const XLSX     = require('xlsx');


const app = express();
app.set('trust proxy', 1);

const limiter = rateLimit({
    windowMs: 20 * 60 * 1000,
    max: 5000,                
  });
  
  app.use(limiter);

console.log('=== Server Starting ===');
console.log('Time:', new Date().toISOString());
console.log('Node version:', process.version);
console.log('Port:', process.env.PORT || 8080);

app.use(express.json());
app.use(cors({
    origin: true, 
    credentials: true
}));

const clientMapping = {
    4: "Alston & Bird LLP", 5: "Ruden McClosky", 6: "Dykema Gossett PLLC", 8: "Miller & Martin PLLC",
    9: "Hogan Lovells US LLP", 10: "Cranfill, Sumner, & Hartzog, L.L.P.", 12: "Poyner & Spruill LLP",
    13: "Warner Norcross & Judd", 14: "Olshan Frome Wolosky LLP", 15: "Cadwalader, Wickersham & Taft LLP",
    16: "Baker & Hostetler LLP", 17: "Brown Rudnick LLP", 18: "Phillips Lytle LLP", 19: "Andrews Kurth LLP",
    20: "Miller & Chevalier", 21: "Baker, Donelson, Bearman, Caldwell & Berkowitz PC", 22: "Jones Vargas",
    23: "Paul, Weiss, Rifkind, Wharton & Garrison LLP", 24: "Robins Kaplan LLP", 26: "Ropes & Gray LLP",
    27: "Royston, Rayzor, Vickery & Williams, L.L.P.", 28: "Vinson & Elkins L.L.P.", 30: "Wilson Sonsini Goodrich & Rosati",
    31: "Stinson Leonard Street", 32: "Bank Street College of Education", 33: "Keker & Van Nest L.L.P.",
    34: "ESL Federal Credit Union", 35: "Chamberlain, Hrdlicka, White, Williams & Martin", 36: "Meagher & Geer, P.L.L.P.",
    37: "Farella Braun & Martel LLP", 38: "Bingham McHale LLP", 39: "Wolf Haldenstein Adler Freeman & Herz LLP",
    40: "Nixon Peabody LLP", 41: "Gray Plant Mooty", 42: "Schiff Hardin LLP", 43: "Procopio, Cory, Hargreaves & Savitch LLP",
    44: "Akin Gump Strauss Hauer & Feld LLP", 45: "Sterne, Kessler, Goldstein & Fox P.L.L.C.", 46: "Snell & Wilmer L.L.P.",
    47: "Parker Poe Adams & Berstein LLP", 48: "Seward & Kissel LLP", 49: "Burns & Levinson LLP",
    50: "Smith, Anderson, Blount, Dorsett, Mitchell & Jernigan, L.L.P", 51: "McDonough, Holland & Allen PC",
    52: "Zelle, Hofmann, Voelbel & Mason LLP", 53: "Litchfield Cavo LLP", 54: "Margolin, Winer & Evens LLP",
    55: "Gallaudet University", 56: "Quarles & Brady LLP", 57: "McNees Wallace & Nurick LLC", 58: "Bingham McCutchen LLP",
    59: "McGlinchey Stafford PLLC", 60: "Carlton Fields Jorden Burt", 62: "Davis Polk & Wardwell LLP",
    63: "Faegre & Benson LLP", 64: "Morrison & Foerster LLP", 65: "Montgomery, McCracken, Walker & Rhoads, LLP",
    66: "Holland & Knight LLP", 67: "Rawle & Henderson LLP", 68: "Winthrop & Weinstine, P.A.",
    69: "Lindabury, McCormick, Estabrook & Cooper, P.C.", 70: "Blake, Cassels & Graydon LLP",
    71: "Cassels Brock & Blackwell LLP", 72: "Fasken Martineau DuMoulin LLP", 73: "Fraser Milner Casgrain LLP",
    74: "Goodmans LLP", 75: "Gowling Lafleur Henderson LLP", 76: "Heenan Blaikie LLP", 77: "McMillan LLP",
    78: "McCarthy Tétrault LLP", 79: "Norton Rose Fulbright Canada LLP", 80: "Torys LLP", 81: "Osler, Hoskin & Harcourt LLP",
    82: "Stikeman Elliott LLP", 83: "O'Melveny & Myers LLP", 84: "Hirschler Fleischer", 85: "Lewis, Rice & Fingersh, L.C.",
    87: "Stikeman Elliott LLP (WAVG)", 88: "Anderson Kill & Olick, PC", 89: "Calfee, Halter & Griswold LLP",
    90: "Torys LLP (NY)", 91: "Miller Thomson LLP", 92: "Allen & Overy LLP", 93: "Osler, Hoskin & Harcourt LLP (New York)",
    94: "K&L Gates LLP", 95: "Jenner & Block LLP", 96: "Genesis HealthCare Corporation 1-200", 97: "Health Plus",
    98: "Li & Fung USA", 99: "Fisher & Phillips LLP", 100: "Irving Place Capital", 101: "Jennings, Strouss & Salmon, P.L.C.",
    102: "Wilkinson Barker Knauer, LLP", 103: "Day Pitney LLP", 104: "Wegmans Food Markets", 105: "Kobre & Kim LLP",
    106: "Global Brands Group", 107: "Baker Botts L.L.P.", 108: "Holy Redeemer Health System", 109: "Swiss Re Management (US) Corporation",
    110: "Geller & Company", 111: "Miller, Canfield, Paddock & Stone", 112: "Borden Ladner Gervais", 113: "Tulane University",
    115: "MRC Global", 116: "Reyes Holdings", 118: "Hawkins Parnell & Young LLP", 119: "McIness Cooper", 121: "Stewart McKelvey",
    122: "Graydon Head & Ritchey LLP", 123: "ZZZZ", 124: "The Kenan Advantage Group - Staples", 125: "Mayer Brown LLP",
    126: "U.S. Security Associates, Inc.", 127: "The Hershey Company", 128: "Norris McLaughlin & Marcus, P.A.",
    129: "Genesis HealthCare Corporation 201-400", 130: "Genesis HealthCare Corporation 401-600", 131: "Constangy, Brooks, Smith & Prophete, LLP",
    132: "McAfee Taft LLP", 133: "PSS Companies", 134: "Harris Beach PLLC", 135: "Montefiore Health Systems",
    136: "GCA Services Group", 137: "Morris, Nichols, Arsht & Tunnell LLP", 138: "Kelley Drye & Warren LLP",
    139: "Neopost USA", 140: "Chiesa Shahinian & Giantomasi PC", 141: "TZP Group", 142: "Manning Gross + Massenburg LLP (MG+M The Law Firm)",
    143: "Beveridge & Diamond, PC", 148: "Young Conaway Stargatt & Taylor, LLP", 149: "Buckley LLP", 150: "The Kenan Advantage Group-Office Depot",
    151: "Mount Sinai Health Systems", 153: "Zelle LLP", 154: "Sterling", 155: "Strategic Financial Solutions",
    156: "Capital Vision", 157: "The Carpenter Health Network", 158: "Mt Sinai Health Systems Toner School",
    159: "Mt Sinai Health Systems Reports", 160: "Commonwealth Care Alliance", 161: "Cleary Gottlieb Steen & Hamilton LLP",
    162: "Kaufman Borgeest Ryan LLP - FedEx Pricing Audit", 163: "Simpson Thacher & Bartlett LLP", 164: "Winget, Spadafora & Schwartzberg, LLP",
    165: "Advanced Recovery Systems, LLC", 166: "Diversified", 167: "Monotype", 168: "Skadden, Arps, Slate, Meagher & Flom LLP",
    169: "HERRICK FEINSTEIN LLP", 170: "Armstrong Flooring", 171: "Berger & Montague P.C.", 172: "Robinson Bradshaw & Hinson PA",
    173: "Archer & Greiner, P.C.", 174: "McCarter & English", 175: "Hospital for Special Care", 176: "Ballard Spahr",
    177: "Ballard Spahr", 178: "Shumaker, Loop & Kendrick", 179: "Dorsey & Whitney", 180: "Munger, Tolles & Olson",
    181: "Paul Hastings", 182: "Nelson Mullins Riley & Scarborough", 183: "Davis Wright Tremaine", 184: "Stoel Rives",
    185: "Blank Rome", 186: "Invesco ltd", 187: "Promedica", 188: "Davis Polk", 191: "Monarch Healthcare",
    192: "Genesis HealthCare", 193: "Big Lift LLC", 194: "Invesco", 195: "IB Goodman", 196: "Sentrilock, LLC",
    197: "United Courier", 198: "Reliant Healthcare", 199: "Keller & Heckman", 200: "Chapman and Cutler LLP",
    201: "Schulte Roth & Zabel LLP", 202: "Maplewood Senior Living", 203: "Food to Live", 204: "Enexia Specialty Pharmacy",
    205: "GLDN", 206: "Precision Compounding Pharmacy and Wellness", 207: "GHC", 208: "Demo Client", 209: "MBK Senior Living",
    210: "Calavo", 211: "Huntons Andrew Kurth", 212: "Adler Pollock & Sheehan PC", 213: "Moses & Singer LLP",
    214: "SavaSeniorCare, LLC", 215: "Bond, Schoeneck & King", 216: "American Broadcasting Company (ABC)", 217: "Brownstein Hyatt Farber Schreck",
    218: "Carter Ledyard & Milburn", 219: "Condon & Forsyth LLP", 220: "Cravath, Swaine & Moore", 221: "Finn Dixon & Herling",
    222: "Foley & Lardner", 223: "Katten Muchin Rosenman", 224: "Kirkland & Ellis", 225: "Manatt, Phelps & Phillips",
    226: "Milbank", 227: "Pace LLP", 228: "Proskauer Rose LLP", 229: "Zuckerman Spaeder", 230: "Greenberg Traurig",
    231: "Care Initiatives", 232: "Stamford JCC", 233: "Natures Sunshine", 234: "Legacy Senior Living",
    235: "Healthcare Services Group", 236: "Willkie Farr & Gallagher LLP", 237: "Freshfields", 238: "Shalby Advanced Technologies",
    239: "Elara Caring", 240: "Ogletree Deakins", 241: "Ogletree Deakins benchm", 242: "C Spire", 243: "Consensus Health",
    244: "ENT and Allergy Associates", 245: "Anderson Automotive Group", 246: "Bricker Graydon LLP", 247: "Pulmonary Exchange",
    248: "Bria", 249: "Internal Portal", 250: "Frost Brown Todd LLP", 251: "Imagination Technologies", 252: "DocGo",
    253: "Prospect Demo", 254: "Transitions Healthcare LLC", 255: "Crash Champions", 256: "HWG LLP", 257: "PL Development",
    258: "Super Natural Distributors", 259: "Steptoe", 260: "Windy City", 261: "House of Cheatham", 262: "CareAbout Health",
    263: "Sullivan & Cromwell", 265: "Baker Botts", 266: "Morrison Cohen LLP",
    264: "Ankura Consulting Group", 268: "Small Demo", 269: "Akerman LLP"
};

// AWS S3 configuration (add your credentials here)
const AWS_CONFIG = {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION || 'us-east-1'
};

// Configure AWS
AWS.config.update(AWS_CONFIG);
const s3 = new AWS.S3();

// OpenAI API Configuration
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

const JIRA_CONFIG = {
    baseUrl: process.env.JIRA_BASE_URL || 'https://ccmchase.atlassian.net',
    username: process.env.JIRA_USERNAME,
    apiToken: process.env.JIRA_API_TOKEN,
    projectKeys: ['AP','CCP','FBT','OGLE','PROSKAUER','RP','REQUEST']
};

const PROJECT_MAPPING = {
    'AP': { clnum: 267, companyName: "Ankura Consulting Group" },
    // 'BBP': { clnum: 107, companyName: "Baker Botts L.L.P." },
    'CCP': { clnum: 255, companyName: "Crash Champions" },
    'FBT': { clnum: 250, companyName: "Frost Brown Todd LLP" },
    'OGLE': { clnum: 240, companyName: "Ogletree Deakins" },
    'PROSKAUER': { clnum: 228, companyName: "Proskauer Rose LLP" },
    'RP': { clnum: 26, companyName: "Ropes & Gray LLP" },
    'REQUEST': { clnum: 208, companyName: "Demo Client" }
};

// Validate Jira configuration on startup
if (!JIRA_CONFIG.apiToken || JIRA_CONFIG.apiToken === 'your-jira-api-token') {
    console.warn('⚠️  WARNING: Jira API token not configured. Jira integration will not work.');
    console.warn('   Please update JIRA_CONFIG in server.js with your actual Jira credentials');
} else {
    console.log('✅ Jira API Configuration loaded');
}

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Configure multer for file uploadss
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = 'uploads/';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + '-' + file.originalname);
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 50 * 1024 * 1024 // 50MB limit
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['.pdf', '.docx', '.txt'];
        const fileExt = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.includes(fileExt)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only PDF, DOCX, and TXT files are allowed.'));
        }
    }
});

const DB_CONFIG = {
    host: process.env.DB_HOST || '35.227.28.240',
    port: parseInt(process.env.DB_PORT) || 3306,
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || 'qlik_spreadsheets'
};

let dbPool = null;

// Initialize database connection with your existing database
async function initializeDatabase(config = null) {
    try {
        // Use provided config or default DB_CONFIG
        const dbConfig = config || DB_CONFIG;
            
        dbPool = mysql.createPool({
            ...dbConfig,
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0,
            timezone: '+00:00'
        });

        // Make dbPool globally accessible
        global.dbPool = dbPool;

        // Test connection
        const connection = await dbPool.getConnection();
        await connection.ping();
        connection.release();
        
        console.log('✅ Database connected successfully to qlik_spreadsheets');
        return true;
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        return false;
    }
}

// Verify ccm_sync_table exists and get its structure
async function verifyContractsTable() {
    if (!global.dbPool) return false;
    
    try {
        const [tables] = await global.dbPool.execute(
            "SHOW TABLES LIKE 'ccm_sync_table'"
        );
        
        if (tables.length === 0) {
            console.error('❌ ccm_sync_table does not exist in the database');
            return false;
        }

        const [columns] = await global.dbPool.execute(
            "DESCRIBE ccm_sync_table"
        );
        
        console.log('✅ ccm_sync_table structure verified');
        return true;
    } catch (error) {
        console.error('❌ Error verifying ccm_sync_table:', error.message);
        return false;
    }
}

// Format date from number format (20210101) to readable format (2021-01-01)
function formatDateFromNumber(dateNumber) {
    if (!dateNumber) return null;
    
    // Convert to string if it's a number
    const dateStr = dateNumber.toString();
    
    // Check if it's in YYYYMMDD format (8 digits)
    if (dateStr.length === 8) {
        const year = dateStr.substring(0, 4);
        const month = dateStr.substring(4, 6);
        const day = dateStr.substring(6, 8);
        return `${year}-${month}-${day}`;
    }
    
    // If it's already in a different format, try to parse it
    try {
        const date = new Date(dateNumber);
        if (!isNaN(date.getTime())) {
            return date.toISOString().split('T')[0];
        }
    } catch (error) {
        console.warn('Could not parse date:', dateNumber);
    }
    
    return dateNumber; // Return as-is if can't format
}

// Extract text from different file types
async function extractTextFromFile(filePath, mimeType) {
    try {
        if (mimeType === 'application/pdf') {
            const dataBuffer = fs.readFileSync(filePath);
            
            // Check if file exists and has content
            if (!dataBuffer || dataBuffer.length === 0) {
                throw new Error('PDF file is empty or corrupted');
            }
            
            try {
                const data = await pdf(dataBuffer);
                if (!data || !data.text) {
                    throw new Error('Could not extract text from PDF - file may be corrupted or password protected');
                }
                return data.text;
            } catch (pdfError) {
                console.error('PDF parsing error:', pdfError.message);
                throw new Error(`Invalid PDF structure: ${pdfError.message}`);
            }
        } else if (mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
            const result = await mammoth.extractRawText({ path: filePath });
            return result.value;
        } else if (mimeType === 'text/plain') {
            return fs.readFileSync(filePath, 'utf8');
        } else {
            throw new Error(`Unsupported file type: ${mimeType}`);
        }
    } catch (error) {
        console.error('Error extracting text:', error.message);
        throw error;
    }
}

// Call OpenAI API with configured key
async function callOpenAI(prompt) {
    try {
        const response = await axios.post('https://api.openai.com/v1/chat/completions', {
            model: 'o4-mini',
            messages: [
                {
                    role: 'system',
                    content: 'You are a legal contract analysis expert. Provide detailed, professional analysis of contracts in JSON format when requested, or formatted text otherwise.'
                },
                {
                    role: 'user',
                    content: prompt
                }
            ],
            max_completion_tokens: 4000,
        }, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`
            }
        });

        return response.data.choices[0].message.content;
    } catch (error) {
        console.error('OpenAI API error:', error.response?.data || error.message);
        if (error.response?.status === 401) {
            throw new Error('Invalid OpenAI API key. Please check your API key configuration.');
        } else if (error.response?.status === 429) {
            throw new Error('OpenAI API rate limit exceeded. Please try again later.');
        } else if (error.response?.status === 402) {
            throw new Error('OpenAI API quota exceeded. Please check your billing.');
        }
        throw new Error('Failed to analyze contract with OpenAI: ' + (error.response?.data?.error?.message || error.message));
    }
}

function highlightTerm(text, term, maxLength = 100) {
    if (!text || !term) return text || '';
    
    const termIndex = text.toLowerCase().indexOf(term.toLowerCase());
    if (termIndex === -1) return text.substring(0, maxLength) + (text.length > maxLength ? '...' : '');
    
    const start = Math.max(0, termIndex - Math.floor((maxLength - term.length) / 2));
    const end = Math.min(text.length, start + maxLength);
    
    let context = text.substring(start, end);
    
    // Add ellipsis if truncated
    if (start > 0) context = '...' + context;
    if (end < text.length) context = context + '...';
    
    // Highlight the term (case-insensitive)
    const regex = new RegExp(`(${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
    context = context.replace(regex, '**$1**');
    
    return context;
}

app.use(cookieParser());
app.use(session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // false for development
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'lax'
    },
    name: 'sessionId'
}));

app.use((req, res, next) => {
    const timestamp = new Date().toISOString();
    const sessionInfo = req.session?.userId ? 
        `Logged in (User ID: ${req.session.userId})` : 
        'Not logged in';
    
    console.log(`${timestamp} - ${req.method} ${req.url}`);
    console.log(`Session: ${sessionInfo}`);
    
    // Only show detailed auth check for protected routes
    if (req.url.startsWith('/api/chat/') || req.url.startsWith('/api/admin/')) {
        console.log('=== Auth Check ===');
        console.log('Session ID:', req.sessionID);
        console.log('Session exists:', !!req.session);
        console.log('User ID in session:', req.session?.userId);
        console.log('================');
    }
    
    next();
});

// Login attempt rate limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Maximum 5 attempts
    message: { error: 'Too many login attempts, please try again after 15 minutes' },
    standardHeaders: true,
    legacyHeaders: false,
});

async function createChatTables() {
    try {
        if (!dbPool) {
            throw new Error('Database pool not initialized');
        }
        
        // 创建对话表
        await dbPool.execute(`
            CREATE TABLE IF NOT EXISTS chat_conversations (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                title VARCHAR(500) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_updated (user_id, updated_at)
            )
        `);

        // 创建消息表
        await dbPool.execute(`
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INT AUTO_INCREMENT PRIMARY KEY,
                conversation_id INT NOT NULL,
                content TEXT NOT NULL,
                sender ENUM('user', 'bot') NOT NULL,
                file_info JSON NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (conversation_id) REFERENCES chat_conversations(id) ON DELETE CASCADE,
                INDEX idx_conversation_created (conversation_id, created_at)
            )
        `);
        
        console.log('✅ Chat tables created successfully');
    } catch (error) {
        console.error('❌ Error creating chat tables:', error);
        throw error;
    }
}

// 4. Database table creation (add to your database initialization function)
async function createUserTables() {
    try {
        if (!dbPool) {
            throw new Error('Database pool not initialized');
        }
        
        await dbPool.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                full_name VARCHAR(100),
                role ENUM('admin', 'user') DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                last_login TIMESTAMP NULL,
                login_count INT DEFAULT 0
            )
        `);

        // 添加login_count列（如果不存在）
        try {
            await dbPool.execute(`
                ALTER TABLE users ADD COLUMN login_count INT DEFAULT 0
            `);
            console.log('✅ Added login_count column to users table');
        } catch (error) {
            if (error.code !== 'ER_DUP_FIELDNAME') {
                console.warn('Could not add login_count column:', error.message);
            }
        }
        
        console.log('✅ User tables created successfully');
        
        // 创建聊天表
        await createChatTables();
        
    } catch (error) {
        console.error('❌ Error creating user tables:', error);
        throw error;
    }
}

// 5. Middleware: Check if user is logged in
function requireAuth(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    } else {
        console.log('❌ Authentication failed - no valid session for:', req.url);
        return res.status(401).json({ 
            error: 'Please login first',
            loggedIn: false 
        });
    }
}

// 6. Middleware: Check admin privileges
function requireAdmin(req, res, next) {
    if (req.session && req.session.userId && req.session.userRole === 'admin') {
        return next();
    } else {
        return res.status(403).json({ error: 'Admin privileges required' });
    }
}

// 7. User authentication API routes

app.get('/api/debug/session', (req, res) => {
    res.json({
        hasSession: !!req.session,
        sessionID: req.sessionID,
        userId: req.session?.userId,
        userRole: req.session?.userRole,
        username: req.session?.username,
        cookies: req.cookies,
        isAuthenticated: !!(req.session && req.session.userId),
        timestamp: new Date().toISOString()
    });
});

// Test auth endpoint
app.get('/api/debug/auth', requireAuth, (req, res) => {
    res.json({
        message: 'Authentication working!',
        userId: req.session.userId,
        username: req.session.username,
        timestamp: new Date().toISOString()
    });
});

// User login
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        console.log('🔍 Login attempt for:', username);

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        // 查找用户
        const [users] = await dbPool.execute(
            'SELECT id, username, email, password_hash, full_name, role, is_active, login_count FROM users WHERE username = ? OR email = ?',
            [username, username]
        );

        console.log('🔍 Users found:', users.length);

        if (users.length === 0) {
            console.log('❌ No user found with username/email:', username);
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const user = users[0];

        if (!user.is_active) {
            console.log('❌ User account is disabled:', username);
            return res.status(401).json({ error: 'Account has been disabled' });
        }

        // 验证密码
        console.log('🔍 Verifying password...');
        const isValidPassword = await bcrypt.compare(password, user.password_hash);
        console.log('🔍 Password valid:', isValidPassword);

        if (!isValidPassword) {
            console.log('❌ Invalid password for user:', username);
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // 更新最后登录时间和登录次数
        await dbPool.execute(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP, login_count = COALESCE(login_count, 0) + 1 WHERE id = ?',
            [user.id]
        );

        // 创建会话
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.userRole = user.role;
        req.session.fullName = user.full_name;

        console.log('✅ Login successful for:', username);

        res.json({
            success: true,
            message: 'Login successful',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                fullName: user.full_name,
                role: user.role,
                loginCount: (user.login_count || 0) + 1
            }
        });

    } catch (error) {
        console.error('❌ Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// User logout
app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.clearCookie('connect.sid'); // Clear session cookie
        res.json({ success: true, message: 'Logout successful' });
    });
});

// Check login status
app.get('/api/auth/me', (req, res) => {
    if (req.session && req.session.userId) {
        res.json({
            loggedIn: true,
            user: {
                id: req.session.userId,
                username: req.session.username,
                fullName: req.session.fullName,
                role: req.session.userRole
            }
        });
    } else {
        res.json({ loggedIn: false });
    }
});

// Get all users (admin only)
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const [users] = await dbPool.execute(
            `SELECT id, username, email, full_name, role, is_active, created_at, last_login, 
                    COALESCE(login_count, 0) as login_count 
             FROM users 
             ORDER BY created_at DESC`
        );

        res.json({ success: true, users });

    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Failed to get users' });
    }
});

// 4. 新增API：重置用户登录次数（管理员专用）
app.put('/api/admin/users/:id/reset-login-count', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        const [result] = await dbPool.execute(
            'UPDATE users SET login_count = 0 WHERE id = ?',
            [id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ success: true, message: 'Login count reset successfully' });

    } catch (error) {
        console.error('Reset login count error:', error);
        res.status(500).json({ error: 'Failed to reset login count' });
    }
});

app.get('/api/admin/login-stats', requireAuth, requireAdmin, async (req, res) => {
    try {
        // 获取总登录次数
        const [totalLogins] = await dbPool.execute(
            'SELECT SUM(COALESCE(login_count, 0)) as total_logins FROM users'
        );

        // 获取活跃用户（至少登录一次）
        const [activeUsers] = await dbPool.execute(
            'SELECT COUNT(*) as active_users FROM users WHERE login_count > 0'
        );

        // 获取最近7天内登录的用户
        const [recentUsers] = await dbPool.execute(
            'SELECT COUNT(*) as recent_users FROM users WHERE last_login >= DATE_SUB(NOW(), INTERVAL 7 DAY)'
        );

        // 获取登录次数最多的前5名用户
        const [topUsers] = await dbPool.execute(
            `SELECT username, full_name, login_count, last_login 
             FROM users 
             WHERE login_count > 0 
             ORDER BY login_count DESC 
             LIMIT 5`
        );

        res.json({
            success: true,
            stats: {
                totalLogins: totalLogins[0].total_logins || 0,
                activeUsers: activeUsers[0].active_users || 0,
                recentUsers: recentUsers[0].recent_users || 0,
                topUsers: topUsers
            }
        });

    } catch (error) {
        console.error('Get login stats error:', error);
        res.status(500).json({ error: 'Failed to get login statistics' });
    }
});

app.get('/api/chat/conversations', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        console.log('📋 Loading conversations for user:', userId);
        
        const [conversations] = await dbPool.execute(`
            SELECT 
                c.id,
                c.title,
                c.created_at,
                c.updated_at,
                (SELECT COUNT(*) FROM chat_messages WHERE conversation_id = c.id) as message_count,
                (SELECT created_at FROM chat_messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message_time
            FROM chat_conversations c
            WHERE c.user_id = ? AND c.is_active = TRUE
            ORDER BY c.updated_at DESC
            LIMIT 50
        `, [userId]);
        
        console.log('📋 Found conversations:', conversations.length);
        if (conversations.length > 0) {
            console.log('📋 Sample conversation:', conversations[0]);
        }
        
        res.json({
            success: true,
            conversations: conversations
        });
        
    } catch (error) {
        console.error('❌ Error fetching conversations:', error);
        res.status(500).json({ error: 'Failed to fetch conversations' });
    }
});

// 获取对话的消息
app.get('/api/chat/conversations/:id/messages', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const conversationId = req.params.id;
        
        console.log('📋 Loading messages for conversation:', conversationId, 'user:', userId);
        
        // Verify conversation belongs to user
        const [conversations] = await dbPool.execute(`
            SELECT id FROM chat_conversations 
            WHERE id = ? AND user_id = ? AND is_active = TRUE
        `, [conversationId, userId]);
        
        if (conversations.length === 0) {
            console.log('❌ Conversation not found or not accessible:', conversationId);
            return res.status(404).json({ error: 'Conversation not found' });
        }
        
        const [messages] = await dbPool.execute(`
            SELECT id, content, sender, file_info, created_at
            FROM chat_messages 
            WHERE conversation_id = ?
            ORDER BY created_at ASC
        `, [conversationId]);
        
        console.log('📋 Found messages:', messages.length);
        
        res.json({
            success: true,
            messages: messages
        });
        
    } catch (error) {
        console.error('❌ Error fetching messages:', error);
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

// Create new conversation
app.post('/api/chat/conversations', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { title = 'New Conversation' } = req.body;
        
        console.log('📝 Creating new conversation for user:', userId);
        
        const [result] = await dbPool.execute(`
            INSERT INTO chat_conversations (user_id, title) 
            VALUES (?, ?)
        `, [userId, title]);
        
        console.log('✅ New conversation created:', result.insertId);
        
        res.json({
            success: true,
            conversationId: result.insertId,
            title: title
        });
        
    } catch (error) {
        console.error('❌ Error creating conversation:', error);
        res.status(500).json({ error: 'Failed to create conversation' });
    }
});

// 添加消息到对话
app.post('/api/chat/conversations/:id/messages', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const conversationId = req.params.id;
        const { content, sender, fileInfo = null } = req.body;
        
        if (!content || !sender) {
            return res.status(400).json({ error: 'Content and sender are required' });
        }
        
        console.log('📝 Adding message to conversation:', conversationId, 'sender:', sender);
        
        // Truncate content if too long (assuming TEXT column has 65535 character limit)
        const maxContentLength = 65000; // Leave some buffer
        const truncatedContent = content.length > maxContentLength 
            ? content.substring(0, maxContentLength) + '... [Content truncated due to length]'
            : content;
        
        if (content.length > maxContentLength) {
            console.log(`⚠️  Content truncated from ${content.length} to ${truncatedContent.length} characters`);
        }
        
        // Verify conversation belongs to user
        const [conversations] = await dbPool.execute(`
            SELECT id, title FROM chat_conversations 
            WHERE id = ? AND user_id = ? AND is_active = TRUE
        `, [conversationId, userId]);
        
        if (conversations.length === 0) {
            return res.status(404).json({ error: 'Conversation not found' });
        }
        
        // Start transaction
        await dbPool.query('START TRANSACTION');
        
        try {
            // Add message
            const [messageResult] = await dbPool.execute(`
                INSERT INTO chat_messages (conversation_id, content, sender, file_info) 
                VALUES (?, ?, ?, ?)
            `, [conversationId, truncatedContent, sender, fileInfo ? JSON.stringify(fileInfo) : null]);
            
            // Update conversation timestamp and title in one query for user messages
            if (sender === 'user') {
                const conversation = conversations[0];
                if (conversation.title === 'New Conversation') {
                    // Update both title and timestamp in one query
                    const newTitle = content.length > 50 ? content.substring(0, 50) + '...' : content;
                    await executeWithRetry(async () => {
                        await dbPool.execute(`
                            UPDATE chat_conversations 
                            SET title = ?, updated_at = CURRENT_TIMESTAMP 
                            WHERE id = ?
                        `, [newTitle, conversationId]);
                    });
                } else {
                    // Only update timestamp
                    await executeWithRetry(async () => {
                        await dbPool.execute(`
                            UPDATE chat_conversations 
                            SET updated_at = CURRENT_TIMESTAMP 
                            WHERE id = ?
                        `, [conversationId]);
                    });
                }
            }
            
            await dbPool.query('COMMIT');
            
            console.log('✅ Message added successfully, messageId:', messageResult.insertId);
            
            res.json({
                success: true,
                messageId: messageResult.insertId,
                message: 'Message added successfully'
            });
            
        } catch (error) {
            await dbPool.execute('ROLLBACK');
            throw error;
        }
        
    } catch (error) {
        console.error('❌ Error adding message:', error);
        res.status(500).json({ error: 'Failed to add message' });
    }
});

// 删除对话
app.delete('/api/chat/conversations/:id', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        const conversationId = req.params.id;
        
        // 验证对话属于当前用户
        const [conversations] = await dbPool.execute(`
            SELECT id FROM chat_conversations 
            WHERE id = ? AND user_id = ?
        `, [conversationId, userId]);
        
        if (conversations.length === 0) {
            return res.status(404).json({ error: 'Conversation not found' });
        }
        
        // 软删除（标记为非活跃）with deadlock retry
        await executeWithRetry(async () => {
            await dbPool.execute(`
                UPDATE chat_conversations 
                SET is_active = FALSE 
                WHERE id = ?
            `, [conversationId]);
        });
        
        res.json({
            success: true,
            message: 'Conversation deleted successfully'
        });
        
    } catch (error) {
        console.error('Error deleting conversation:', error);
        res.status(500).json({ error: 'Failed to delete conversation' });
    }
});

// 清除用户所有对话
app.delete('/api/chat/conversations', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        
        await executeWithRetry(async () => {
            await dbPool.execute(`
                UPDATE chat_conversations 
                SET is_active = FALSE 
                WHERE user_id = ?
            `, [userId]);
        });
        
        res.json({
            success: true,
            message: 'All conversations cleared successfully'
        });
        
    } catch (error) {
        console.error('Error clearing conversations:', error);
        res.status(500).json({ error: 'Failed to clear conversations' });
    }
});

// 导出用户聊天历史
app.get('/api/chat/export', requireAuth, async (req, res) => {
    try {
        const userId = req.session.userId;
        
        const [conversations] = await dbPool.execute(`
            SELECT 
                c.id,
                c.title,
                c.created_at,
                c.updated_at,
                JSON_ARRAYAGG(
                    JSON_OBJECT(
                        'id', m.id,
                        'content', m.content,
                        'sender', m.sender,
                        'file_info', m.file_info,
                        'created_at', m.created_at
                    )
                ) as messages
            FROM chat_conversations c
            LEFT JOIN chat_messages m ON c.id = m.conversation_id
            WHERE c.user_id = ? AND c.is_active = TRUE
            GROUP BY c.id, c.title, c.created_at, c.updated_at
            ORDER BY c.updated_at DESC
        `, [userId]);
        
        const exportData = {
            exported_at: new Date().toISOString(),
            user_id: userId,
            conversations: conversations
        };
        
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="chat_history_${userId}_${new Date().toISOString().split('T')[0]}.json"`);
        res.json(exportData);
        
    } catch (error) {
        console.error('Error exporting chat history:', error);
        res.status(500).json({ error: 'Failed to export chat history' });
    }
});

// 9. Call createUserTables when initializing the database
async function initializeDatabase(config = null) {
    try {
        const dbConfig = config || DB_CONFIG;
            
        dbPool = mysql.createPool({
            ...dbConfig,
            waitForConnections: true,
            connectionLimit: 10,
            queueLimit: 0,
            timezone: '+00:00'
        });

        // Make dbPool globally accessible
        global.dbPool = dbPool;

        // Test connection
        const connection = await dbPool.getConnection();
        await connection.ping();
        connection.release();
        
        console.log('✅ Database connected successfully to qlik_spreadsheets');
        return true;
    } catch (error) {
        console.error('❌ Database connection failed:', error.message);
        return false;
    }
}

async function startServer() {
    try {
        console.log('🔍 Initializing database...');
        
        // Initialize database
        const dbSuccess = await initializeDatabase();
        if (!dbSuccess) {
            console.error('❌ Failed to initialize database, exiting...');
            process.exit(1);
        }
        
        // Verify contracts table
        const tableExists = await verifyContractsTable();
        if (!tableExists) {
            console.warn('⚠️ ccm_sync_table verification failed, but continuing...');
        }
        
        // Create user tables
        await createUserTables();
        
        // List all users
        setTimeout(async () => {
            try {
                await listAllUsers();
            } catch (error) {
                console.warn('Could not list users:', error.message);
            }
        }, 1000);
        
        // Start the server
        const server = app.listen(PORT, HOST, () => {
            console.log('=== Server Started Successfully ===');
            console.log(`✅ Listening on: http://${HOST}:${PORT}`);
            console.log(`📅 Started at: ${new Date().toISOString()}`);
            console.log('🛣️  Available routes:');
            console.log('   GET / (home page)');
            console.log('   GET /health (health check)');
            console.log('   GET /test (test route)'); 
            console.log('   GET /debug (debug info)');
            console.log('   GET /login.html (login page)');
            console.log('================================');
        });
        
        // Graceful shutdown
        process.on('SIGTERM', () => {
            console.log('SIGTERM received, shutting down gracefully');
            server.close(() => {
                console.log('Process terminated');
            });
        });
        
    } catch (error) {
        console.error('❌ Server startup failed:', error);
        process.exit(1);
    }
}

async function listAllUsers() {
    try {
        if (!dbPool) {
            throw new Error('Database pool not initialized');
        }
        
        const [users] = await dbPool.execute(
            'SELECT id, username, email, full_name, role, is_active, created_at FROM users ORDER BY created_at DESC'
        );
        
        console.log('📋 All users in database:');
        users.forEach(user => {
            console.log(`   - ID: ${user.id}, Username: ${user.username}, Email: ${user.email}, Role: ${user.role}, Active: ${user.is_active}`);
        });
        
        return users;
    } catch (error) {
        console.error('❌ Error listing users:', error);
        throw error;
    }
}


// Routes

// Test database connection
app.post('/api/test-db-connection', async (req, res) => {
    try {        
        if (success) {
            const tableExists = await verifyContractsTable();
            if (tableExists) {
                res.json({ 
                    success: true, 
                    message: 'Connected to qlik_spreadsheets database and ccm_sync_table verified' 
                });
            } else {
                res.status(500).json({ 
                    success: false, 
                    message: 'Database connected but ccm_sync_table not found' 
                });
            }
        } else {
            res.status(500).json({ success: false, message: 'Database connection failed' });
        }
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

// Upload and analyze contract

// Modified analyzeContract endpoint with three comparison types
app.post('/api/analyze-contract', upload.fields([
    { name: 'contract', maxCount: 1 },
    { name: 'standard', maxCount: 1 }
]), async (req, res) => {
    try {
        const { comparisonType, dbConfig } = req.body;

        const contractFile = req.files.contract?.[0];
        if (!contractFile) {
            return res.status(400).json({ error: 'Contract file is required' });
        }

        console.log(`📄 Analyzing contract: ${contractFile.originalname}`);
        console.log(`🔄 Comparison type: ${comparisonType}`);

        // Extract text from uploaded contract
        const contractText = await extractTextFromFile(contractFile.path, contractFile.mimetype);

        let comparisonData = '';
        let analysisPrompt = '';

        if (comparisonType === 'general') {
            // NEW: General AI analysis without comparison
            analysisPrompt = `
You are analyzing a contract for comprehensive feedback and potential issues.

CONTRACT TO ANALYZE:
${contractText}

Please provide a detailed analysis including:

1. **Contract Overview & Classification**:
   - Contract type and category
   - Primary vendor/counterparty identification(only in one or two words)
   - Contract value and currency (if mentioned)
   - Contract duration and key milestone dates
   - Key product or service being provided

2. **Key Terms Extraction** (Enhanced):
   - Payment terms, schedules, and amounts
   - **YOY (Year-over-Year) Increases**: Identify any annual price increases, escalation clauses, or inflation adjustments. If found, analyze if the percentage is reasonable for the industry and provide industry-standard recommendations.
   - Termination clauses and exit conditions
   - Renewal terms, notice periods, and automatic renewal provisions
   - Governing law, jurisdiction, and dispute resolution
   - Force majeure provisions and exceptions
   - Liability, indemnification, and limitation clauses
   - Intellectual property and confidentiality terms
   - Performance metrics and service level agreements

3. **Pricing & Service Analysis**:
   - **Incomplete Pricing Issues**: Identify any sections where products or services are mentioned but specific pricing is missing, unclear, or incomplete
   - Pricing structure analysis (fixed, variable, tiered, etc.)
   - Cost escalation mechanisms
   - Payment milestones and deliverable-based pricing

4. **Risk Analysis**:
   - High, medium, low risk categorization with specific justifications
   - Unusual or potentially problematic clauses
   - Missing standard protections or clauses
   - Financial risk factors (penalties, fees, unlimited liability)
   - Operational risk factors (dependencies, single points of failure)

5. **Compliance & Standards Assessment**:
   - Standard legal requirements check
   - Industry-specific compliance requirements
   - Data protection and privacy considerations
   - Regulatory compliance issues

6. **Actionable Recommendations**:
   - Specific negotiation points to improve terms
   - Risk mitigation strategies
   - Missing clauses that should be added
   - Contract management action items
   - Legal review priorities
   - Pricing clarifications needed

Please provide a JSON summary with the following structure:
\`\`\`json
{
  "contract_type": "string",
  "vendor_name": "string", 
  "estimated_value": "string",
  "currency": "string",
  "risk_level": "low|medium|high",
  "key_terms": ["array", "of", "key", "terms"],
  "yoy_increases": {
    "found": true|false,
    "percentage": "string",
    "industry_standard": "string",
    "recommendation": "string"
  },
  "incomplete_pricing_sections": ["array", "of", "sections", "with", "missing", "pricing"],
  "missing_clauses": ["array", "of", "missing", "standard", "clauses"],
  "recommendations": ["array", "of", "actionable", "recommendations"],
  "payment_terms": "string",
  "governing_law": "string",
  "termination_conditions": "string",
  "renewal_terms": "string",
  "requires_legal_review": true|false,
  "compliance_issues": ["array", "of", "compliance", "concerns"],
  "risk_factors": ["array", "of", "specific", "risk", "factors"],
  "pricing_issues": ["array", "of", "pricing", "related", "concerns"]
}
\`\`\`

Other than the summary above, I also need you to provide detailed analysis, please provide a JSON summary with the following structure:
            `;
        } else if (comparisonType === 'standard') {
            const standardFile = req.files.standard?.[0];
            if (standardFile) {
                comparisonData = await extractTextFromFile(standardFile.path, standardFile.mimetype);
                analysisPrompt = `
Analyze the following contract and compare it with the provided standard template.

CONTRACT TO ANALYZE:
${contractText}

STANDARD TEMPLATE:
${comparisonData}

Please provide a detailed analysis including:

1. **Contract Overview & Classification**:
   - Contract type and category
   - Primary vendor/counterparty identification
   - Contract value and currency (if mentioned)
   - Contract duration and key milestone dates
   - Key product or service being provided

2. **Key Terms Extraction** (Enhanced):
   - Payment terms, schedules, and amounts
   - **YOY (Year-over-Year) Increases**: Identify any annual price increases, escalation clauses, or inflation adjustments. If found, analyze if the percentage is reasonable for the industry and provide industry-standard recommendations.
   - Termination clauses and exit conditions
   - Renewal terms, notice periods, and automatic renewal provisions
   - Governing law, jurisdiction, and dispute resolution
   - Force majeure provisions and exceptions
   - Liability, indemnification, and limitation clauses
   - Intellectual property and confidentiality terms
   - Performance metrics and service level agreements

3. **Pricing & Service Analysis**:
   - **Incomplete Pricing Issues**: Identify any sections where products or services are mentioned but specific pricing is missing, unclear, or incomplete
   - Pricing structure analysis (fixed, variable, tiered, etc.)
   - Cost escalation mechanisms
   - Payment milestones and deliverable-based pricing

4. **Risk Analysis**:
   - High, medium, low risk categorization with specific justifications
   - Unusual or potentially problematic clauses
   - Missing standard protections or clauses
   - Financial risk factors (penalties, fees, unlimited liability)
   - Operational risk factors (dependencies, single points of failure)

5. **Compliance & Standards Assessment**:
   - Standard legal requirements check
   - Industry-specific compliance requirements
   - Data protection and privacy considerations
   - Regulatory compliance issues

6. **Actionable Recommendations**:
   - Specific negotiation points to improve terms
   - Risk mitigation strategies
   - Missing clauses that should be added
   - Contract management action items
   - Legal review priorities
   - Pricing clarifications needed

Please provide a JSON summary with the following structure:
\`\`\`json
{
  "contract_type": "string",
  "vendor_name": "string", 
  "estimated_value": "string",
  "currency": "string",
  "risk_level": "low|medium|high",
  "key_terms": ["array", "of", "key", "terms"],
  "yoy_increases": {
    "found": true|false,
    "percentage": "string",
    "industry_standard": "string",
    "recommendation": "string"
  },
  "incomplete_pricing_sections": ["array", "of", "sections", "with", "missing", "pricing"],
  "missing_clauses": ["array", "of", "missing", "standard", "clauses"],
  "recommendations": ["array", "of", "actionable", "recommendations"],
  "payment_terms": "string",
  "governing_law": "string",
  "termination_conditions": "string",
  "renewal_terms": "string",
  "requires_legal_review": true|false,
  "compliance_issues": ["array", "of", "compliance", "concerns"],
  "risk_factors": ["array", "of", "specific", "risk", "factors"],
  "pricing_issues": ["array", "of", "pricing", "related", "concerns"]
}
\`\`\`

Format the analysis in clear, structured sections for easy reading and review.
            `;
            }
        } else if (comparisonType === 'database') {
            // Existing database comparison logic with enhanced analysis
            if (dbConfig) {
                await initializeDatabase(JSON.parse(dbConfig));
            }

            if (dbPool) {
                // Database comparison logic (existing code)
                const [rows] = await dbPool.execute(`
                    SELECT clnum, contract_id, contract_name, vendor_name, file, start_date, end_date, spend, currency, product
                    FROM ccm_sync_table 
                    WHERE vendor_name IS NOT NULL 
                    AND vendor_name != ''
                    AND TRIM(vendor_name) != ''
                    AND file IS NOT NULL
                    AND file != ''
                    AND TRIM(file) != ''
                    ORDER BY uploaded_date DESC
                `);
                
                console.log(`📊 Found ${rows.length} contracts in database for vendor matching`);
                
                // Create client mapping from clnum to client name
                const clientMapping = {
                    4: "Alston & Bird LLP", 5: "Ruden McClosky", 6: "Dykema Gossett PLLC", 8: "Miller & Martin PLLC",
                    9: "Hogan Lovells US LLP", 10: "Cranfill, Sumner, & Hartzog, L.L.P.", 12: "Poyner & Spruill LLP",
                    13: "Warner Norcross & Judd", 14: "Olshan Frome Wolosky LLP", 15: "Cadwalader, Wickersham & Taft LLP",
                    16: "Baker & Hostetler LLP", 17: "Brown Rudnick LLP", 18: "Phillips Lytle LLP", 19: "Andrews Kurth LLP",
                    20: "Miller & Chevalier", 21: "Baker, Donelson, Bearman, Caldwell & Berkowitz PC", 22: "Jones Vargas",
                    23: "Paul, Weiss, Rifkind, Wharton & Garrison LLP", 24: "Robins Kaplan LLP", 26: "Ropes & Gray LLP",
                    27: "Royston, Rayzor, Vickery & Williams, L.L.P.", 28: "Vinson & Elkins L.L.P.", 30: "Wilson Sonsini Goodrich & Rosati",
                    31: "Stinson Leonard Street", 32: "Bank Street College of Education", 33: "Keker & Van Nest L.L.P.",
                    34: "ESL Federal Credit Union", 35: "Chamberlain, Hrdlicka, White, Williams & Martin", 36: "Meagher & Geer, P.L.L.P.",
                    37: "Farella Braun & Martel LLP", 38: "Bingham McHale LLP", 39: "Wolf Haldenstein Adler Freeman & Herz LLP",
                    40: "Nixon Peabody LLP", 41: "Gray Plant Mooty", 42: "Schiff Hardin LLP", 43: "Procopio, Cory, Hargreaves & Savitch LLP",
                    44: "Akin Gump Strauss Hauer & Feld LLP", 45: "Sterne, Kessler, Goldstein & Fox P.L.L.C.", 46: "Snell & Wilmer L.L.P.",
                    47: "Parker Poe Adams & Berstein LLP", 48: "Seward & Kissel LLP", 49: "Burns & Levinson LLP",
                    50: "Smith, Anderson, Blount, Dorsett, Mitchell & Jernigan, L.L.P", 51: "McDonough, Holland & Allen PC",
                    52: "Zelle, Hofmann, Voelbel & Mason LLP", 53: "Litchfield Cavo LLP", 54: "Margolin, Winer & Evens LLP",
                    55: "Gallaudet University", 56: "Quarles & Brady LLP", 57: "McNees Wallace & Nurick LLC", 58: "Bingham McCutchen LLP",
                    59: "McGlinchey Stafford PLLC", 60: "Carlton Fields Jorden Burt", 62: "Davis Polk & Wardwell LLP",
                    63: "Faegre & Benson LLP", 64: "Morrison & Foerster LLP", 65: "Montgomery, McCracken, Walker & Rhoads, LLP",
                    66: "Holland & Knight LLP", 67: "Rawle & Henderson LLP", 68: "Winthrop & Weinstine, P.A.",
                    69: "Lindabury, McCormick, Estabrook & Cooper, P.C.", 70: "Blake, Cassels & Graydon LLP",
                    71: "Cassels Brock & Blackwell LLP", 72: "Fasken Martineau DuMoulin LLP", 73: "Fraser Milner Casgrain LLP",
                    74: "Goodmans LLP", 75: "Gowling Lafleur Henderson LLP", 76: "Heenan Blaikie LLP", 77: "McMillan LLP",
                    78: "McCarthy Tétrault LLP", 79: "Norton Rose Fulbright Canada LLP", 80: "Torys LLP", 81: "Osler, Hoskin & Harcourt LLP",
                    82: "Stikeman Elliott LLP", 83: "O'Melveny & Myers LLP", 84: "Hirschler Fleischer", 85: "Lewis, Rice & Fingersh, L.C.",
                    87: "Stikeman Elliott LLP (WAVG)", 88: "Anderson Kill & Olick, PC", 89: "Calfee, Halter & Griswold LLP",
                    90: "Torys LLP (NY)", 91: "Miller Thomson LLP", 92: "Allen & Overy LLP", 93: "Osler, Hoskin & Harcourt LLP (New York)",
                    94: "K&L Gates LLP", 95: "Jenner & Block LLP", 96: "Genesis HealthCare Corporation 1-200", 97: "Health Plus",
                    98: "Li & Fung USA", 99: "Fisher & Phillips LLP", 100: "Irving Place Capital", 101: "Jennings, Strouss & Salmon, P.L.C.",
                    102: "Wilkinson Barker Knauer, LLP", 103: "Day Pitney LLP", 104: "Wegmans Food Markets", 105: "Kobre & Kim LLP",
                    106: "Global Brands Group", 107: "Baker Botts L.L.P.", 108: "Holy Redeemer Health System", 109: "Swiss Re Management (US) Corporation",
                    110: "Geller & Company", 111: "Miller, Canfield, Paddock & Stone", 112: "Borden Ladner Gervais", 113: "Tulane University",
                    115: "MRC Global", 116: "Reyes Holdings", 118: "Hawkins Parnell & Young LLP", 119: "McIness Cooper", 121: "Stewart McKelvey",
                    122: "Graydon Head & Ritchey LLP", 123: "ZZZZ", 124: "The Kenan Advantage Group - Staples", 125: "Mayer Brown LLP",
                    126: "U.S. Security Associates, Inc.", 127: "The Hershey Company", 128: "Norris McLaughlin & Marcus, P.A.",
                    129: "Genesis HealthCare Corporation 201-400", 130: "Genesis HealthCare Corporation 401-600", 131: "Constangy, Brooks, Smith & Prophete, LLP",
                    132: "McAfee Taft LLP", 133: "PSS Companies", 134: "Harris Beach PLLC", 135: "Montefiore Health Systems",
                    136: "GCA Services Group", 137: "Morris, Nichols, Arsht & Tunnell LLP", 138: "Kelley Drye & Warren LLP",
                    139: "Neopost USA", 140: "Chiesa Shahinian & Giantomasi PC", 141: "TZP Group", 142: "Manning Gross + Massenburg LLP (MG+M The Law Firm)",
                    143: "Beveridge & Diamond, PC", 148: "Young Conaway Stargatt & Taylor, LLP", 149: "Buckley LLP", 150: "The Kenan Advantage Group-Office Depot",
                    151: "Mount Sinai Health Systems", 153: "Zelle LLP", 154: "Sterling", 155: "Strategic Financial Solutions",
                    156: "Capital Vision", 157: "The Carpenter Health Network", 158: "Mt Sinai Health Systems Toner School",
                    159: "Mt Sinai Health Systems Reports", 160: "Commonwealth Care Alliance", 161: "Cleary Gottlieb Steen & Hamilton LLP",
                    162: "Kaufman Borgeest Ryan LLP - FedEx Pricing Audit", 163: "Simpson Thacher & Bartlett LLP", 164: "Winget, Spadafora & Schwartzberg, LLP",
                    165: "Advanced Recovery Systems, LLC", 166: "Diversified", 167: "Monotype", 168: "Skadden, Arps, Slate, Meagher & Flom LLP",
                    169: "HERRICK FEINSTEIN LLP", 170: "Armstrong Flooring", 171: "Berger & Montague P.C.", 172: "Robinson Bradshaw & Hinson PA",
                    173: "Archer & Greiner, P.C.", 174: "McCarter & English", 175: "Hospital for Special Care", 176: "Ballard Spahr",
                    177: "Ballard Spahr", 178: "Shumaker, Loop & Kendrick", 179: "Dorsey & Whitney", 180: "Munger, Tolles & Olson",
                    181: "Paul Hastings", 182: "Nelson Mullins Riley & Scarborough", 183: "Davis Wright Tremaine", 184: "Stoel Rives",
                    185: "Blank Rome", 186: "Invesco ltd", 187: "Promedica", 188: "Davis Polk", 191: "Monarch Healthcare",
                    192: "Genesis HealthCare", 193: "Big Lift LLC", 194: "Invesco", 195: "IB Goodman", 196: "Sentrilock, LLC",
                    197: "United Courier", 198: "Reliant Healthcare", 199: "Keller & Heckman", 200: "Chapman and Cutler LLP",
                    201: "Schulte Roth & Zabel LLP", 202: "Maplewood Senior Living", 203: "Food to Live", 204: "Enexia Specialty Pharmacy",
                    205: "GLDN", 206: "Precision Compounding Pharmacy and Wellness", 207: "GHC", 208: "Demo Client", 209: "MBK Senior Living",
                    210: "Calavo", 211: "Huntons Andrew Kurth", 212: "Adler Pollock & Sheehan PC", 213: "Moses & Singer LLP",
                    214: "SavaSeniorCare, LLC", 215: "Bond, Schoeneck & King", 216: "American Broadcasting Company (ABC)", 217: "Brownstein Hyatt Farber Schreck",
                    218: "Carter Ledyard & Milburn", 219: "Condon & Forsyth LLP", 220: "Cravath, Swaine & Moore", 221: "Finn Dixon & Herling",
                    222: "Foley & Lardner", 223: "Katten Muchin Rosenman", 224: "Kirkland & Ellis", 225: "Manatt, Phelps & Phillips",
                    226: "Milbank", 227: "Pace LLP", 228: "Proskauer Rose LLP", 229: "Zuckerman Spaeder", 230: "Greenberg Traurig",
                    231: "Care Initiatives", 232: "Stamford JCC", 233: "Natures Sunshine", 234: "Legacy Senior Living",
                    235: "Healthcare Services Group", 236: "Willkie Farr & Gallagher LLP", 237: "Freshfields", 238: "Shalby Advanced Technologies",
                    239: "Elara Caring", 240: "Ogletree Deakins", 241: "Ogletree Deakins benchm", 242: "C Spire", 243: "Consensus Health",
                    244: "ENT and Allergy Associates", 245: "Anderson Automotive Group", 246: "Bricker Graydon LLP", 247: "Pulmonary Exchange",
                    248: "Bria", 249: "Internal Portal", 250: "Frost Brown Todd LLP", 251: "Imagination Technologies", 252: "DocGo",
                    253: "Prospect Demo", 254: "Transitions Healthcare LLC", 255: "Crash Champions", 256: "HWG LLP", 257: "PL Development",
                    258: "Super Natural Distributors", 259: "Steptoe", 260: "Windy City", 261: "House of Cheatham", 262: "CareAbout Health",
                    263: "Sullivan & Cromwell", 265: "Baker Botts", 266: "Morrison Cohen LLP",
                    264: "Ankura Consulting Group", 268: "Small Demo", 269: "Akerman LLP"
                                };

                // Format the simple contract reference data for internal use
                comparisonData = rows.map(row => {
                    const clnumKey = parseInt(row.clnum);
                    const clientName = clientMapping[clnumKey] || `Client ${row.clnum}`;
                    
                    let fixedFileUrl = row.file;
                    if (fixedFileUrl && fixedFileUrl.includes('ccm-contracts.s3.amazonaws.com')) {
                        fixedFileUrl = fixedFileUrl.replace('ccm-contracts.s3.amazonaws.com', 'ccm-contracts.s3.us-east-1.amazonaws.com');
                    }
                    
                    return {
                        clnum: row.clnum,
                        contractId: row.contract_id,
                        clientName: clientName,
                        contractName: row.contract_name,
                        vendor: row.vendor_name,
                        file: fixedFileUrl,
                        spend: row.spend,
                        currency: row.currency,
                        product: row.product,
                        startDate: row.start_date ? formatDateFromNumber(row.start_date) : null,
                        endDate: row.end_date ? formatDateFromNumber(row.end_date) : null
                    };
                });

                analysisPrompt = `
You are analyzing a contract for potential risks, key terms, and compliance issues.

CONTRACT TO ANALYZE:
${contractText}

Please provide a detailed analysis including:

1. **Contract Overview & Classification**:
   - Contract type and category
   - Primary vendor/counterparty identification
   - Contract value and currency (if mentioned)
   - Contract duration and key milestone dates
   - Key product or service being provided

2. **Key Terms Extraction** (Enhanced):
   - Payment terms, schedules, and amounts
   - **YOY (Year-over-Year) Increases**: Identify any annual price increases, escalation clauses, or inflation adjustments. If found, analyze if the percentage is reasonable for the industry and provide industry-standard recommendations.
   - Termination clauses and exit conditions
   - Renewal terms, notice periods, and automatic renewal provisions
   - Governing law, jurisdiction, and dispute resolution
   - Force majeure provisions and exceptions
   - Liability, indemnification, and limitation clauses
   - Intellectual property and confidentiality terms
   - Performance metrics and service level agreements

3. **Pricing & Service Analysis**:
   - **Incomplete Pricing Issues**: Identify any sections where products or services are mentioned but specific pricing is missing, unclear, or incomplete
   - Pricing structure analysis (fixed, variable, tiered, etc.)
   - Cost escalation mechanisms
   - Payment milestones and deliverable-based pricing

4. **Risk Analysis**:
   - High, medium, low risk categorization with specific justifications
   - Unusual or potentially problematic clauses
   - Missing standard protections or clauses
   - Financial risk factors (penalties, fees, unlimited liability)
   - Operational risk factors (dependencies, single points of failure)

5. **Compliance & Standards Assessment**:
   - Standard legal requirements check
   - Industry-specific compliance requirements
   - Data protection and privacy considerations
   - Regulatory compliance issues

6. **Actionable Recommendations**:
   - Specific negotiation points to improve terms
   - Risk mitigation strategies
   - Missing clauses that should be added
   - Contract management action items
   - Legal review priorities
   - Pricing clarifications needed

Other than the summary above, I also need you to provide detailed analysis, please provide a JSON summary with the following structure:
\`\`\`json
{
  "contract_type": "string",
  "vendor_name": "string", 
  "estimated_value": "string",
  "currency": "string",
  "risk_level": "low|medium|high",
  "key_terms": ["array", "of", "key", "terms"],
  "yoy_increases": {
    "found": true|false,
    "percentage": "string",
    "industry_standard": "string",
    "recommendation": "string"
  },
  "incomplete_pricing_sections": ["array", "of", "sections", "with", "missing", "pricing"],
  "missing_clauses": ["array", "of", "missing", "standard", "clauses"],
  "recommendations": ["array", "of", "actionable", "recommendations"],
  "payment_terms": "string",
  "governing_law": "string",
  "termination_conditions": "string",
  "renewal_terms": "string",
  "requires_legal_review": true|false,
  "compliance_issues": ["array", "of", "compliance", "concerns"],
  "risk_factors": ["array", "of", "specific", "risk", "factors"],
  "pricing_issues": ["array", "of", "pricing", "related", "concerns"]
}
\`\`\`

Format the analysis in clear, structured sections for easy reading and review.
            `;
            } else {
                return res.status(400).json({ error: 'Database connection not established' });
            }
        }

        console.log('🤖 Sending request to OpenAI...');

        // Call OpenAI for analysis
        const analysis = await callOpenAI(analysisPrompt);

        console.log('✅ Analysis completed successfully');

        // After AI analysis, find similar contracts based on vendor name (for all comparison types)
        let similarContracts = [];
        if (dbPool) {
            try {
                // Extract vendor name from AI analysis
                const jsonMatch = analysis.match(/```json\n([\s\S]*?)\n```/);
                let contractSummary = null;
                
                if (jsonMatch) {
                    try {
                        contractSummary = JSON.parse(jsonMatch[1]);
                    } catch (parseError) {
                        console.warn('Could not parse JSON summary from analysis');
                    }
                }

                if (contractSummary && contractSummary.vendor_name) {
                    console.log(`Searching for contracts with vendor: "${contractSummary.vendor_name}"`);
                    
                    // Search database for contracts with matching vendor name
                    const vendorSearchQuery = `
                        SELECT id, clnum, contract_id, contract_name, vendor_name, filename, 
                               contract_type, start_date, end_date, spend, currency, product, file
                        FROM ccm_sync_table 
                        WHERE vendor_name IS NOT NULL 
                        AND LOWER(vendor_name) LIKE LOWER(?)
                        AND file IS NOT NULL 
                        AND file != ''
                        ORDER BY uploaded_date DESC
                        LIMIT 20
                    `;
                    
                    const [vendorContracts] = await dbPool.execute(vendorSearchQuery, [`%${contractSummary.vendor_name}%`]);
                    similarContracts = vendorContracts;
                    
                    console.log(`📋 Found ${similarContracts.length} contracts with similar vendor from database`);
                }
            } catch (error) {
                console.warn('Error finding similar contracts:', error.message);
            }
        }

        // Clean up uploaded files
        fs.unlinkSync(contractFile.path);
        if (req.files.standard?.[0]) {
            fs.unlinkSync(req.files.standard[0].path);
        }

        res.json({
            success: true,
            analysis: analysis,
            filename: contractFile.originalname,
            comparisonType: comparisonType,
            similarContracts: similarContracts // Add similar contracts to response
        });

    } catch (error) {
        console.error('❌ Analysis error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/vendors/list', async (req, res) => {
    try {
        if (!dbPool) {
            return res.status(400).json({ error: 'Database not connected' });
        }

        console.log('📋 Loading all vendors... (Request from:', req.ip, ')');
        const startTime = Date.now();

        const [contractVendors] = await dbPool.execute(`
            SELECT DISTINCT vendor_name
            FROM ccm_sync_table 
            WHERE vendor_name IS NOT NULL 
            AND vendor_name != '' 
            AND TRIM(vendor_name) != ''
        `);

        const [glVendors] = await dbPool.execute(`
            SELECT DISTINCT assigned_vendor_name as vendor_name
            FROM qtable__general_ledger_new 
            WHERE assigned_vendor_name IS NOT NULL 
            AND assigned_vendor_name != '' 
            AND TRIM(assigned_vendor_name) != ''
        `);

        const vendorMap = new Map();
        
        contractVendors.forEach(vendor => {
            const name = vendor.vendor_name.trim();
            const lowerCaseKey = name.toLowerCase();
            
            if (vendorMap.has(lowerCaseKey)) {
                const existing = vendorMap.get(lowerCaseKey);
                if (!existing.sources.includes('contract')) {
                    existing.sources.push('contract');
                }
            } else {
                vendorMap.set(lowerCaseKey, {
                    vendor_name: name, // Keep original case for display
                    sources: ['contract']
                });
            }
        });
        
        // Add GL vendors (check for case-insensitive duplicates)
        glVendors.forEach(vendor => {
            const name = vendor.vendor_name.trim();
            const lowerCaseKey = name.toLowerCase(); // Use lowercase as key for deduplication
            
            if (vendorMap.has(lowerCaseKey)) {
                const existing = vendorMap.get(lowerCaseKey);
                if (!existing.sources.includes('gl')) {
                    existing.sources.push('gl');
                }
            } else {
                vendorMap.set(lowerCaseKey, {
                    vendor_name: name, // Keep original case for display
                    sources: ['gl']
                });
            }
        });

        // Convert to array and sort by display name
        const result = Array.from(vendorMap.values()).sort((a, b) => 
            a.vendor_name.localeCompare(b.vendor_name)
        );
        
        const endTime = Date.now();
        console.log(`📋 All vendors loaded: ${result.length} unique vendors in ${endTime - startTime}ms`);
        console.log(`   - Original: Contract vendors: ${contractVendors.length}, GL vendors: ${glVendors.length}`);
        console.log(`   - Deduplicated: ${result.length} total vendors`);
        console.log(`   - Both sources: ${result.filter(v => v.sources.length === 2).length}`);
        console.log(`   - Contract only: ${result.filter(v => v.sources.includes('contract') && v.sources.length === 1).length}`);
        console.log(`   - GL only: ${result.filter(v => v.sources.includes('gl') && v.sources.length === 1).length}`);

        res.json(result);

    } catch (error) {
        console.error('Error fetching vendor list:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/contracts', async (req, res) => {
    try {
        if (!dbPool) {
            return res.status(400).json({ error: 'Database not connected' });
        }

        const { limit = 20, offset = 0, type, status, vendors, clients } = req.query;
        
        console.log('📄 /api/contracts request params:', { limit, offset, type, status, vendors, clients });
        
        let query = `
            SELECT id, clnum, contract_id, contract_name, vendor_name, filename, contract_type, 
                   start_date, end_date, status, currency, spend, contract_owner,
                   department_responsible, uploaded_date, modified_date, product, file
            FROM ccm_sync_table
        `;
        let params = [];
        let whereConditions = [];

        whereConditions.push('file IS NOT NULL');
        whereConditions.push("file != ''");

        if (type) {
            whereConditions.push('contract_type = ?');
            params.push(type);
        }

        if (status) {
            whereConditions.push('status = ?');
            params.push(status);
        }

        // FIXED: Handle multiple vendors with case-insensitive matching
        if (vendors) {
            const vendorList = vendors.split(',').filter(v => v.trim()).map(v => v.trim());
            if (vendorList.length > 0) {
                // 修复：使用case-insensitive LIKE匹配
                const vendorConditions = vendorList.map(() => 'LOWER(vendor_name) LIKE LOWER(?)').join(' OR ');
                whereConditions.push(`(${vendorConditions})`);
                vendorList.forEach(vendor => params.push(`%${vendor}%`)); // 添加%%包装
                console.log('📄 Filtering contracts by vendors (case-insensitive LIKE match):', vendorList);
            }
        }

        // Handle clients
        if (clients) {
            const clientClnums = clients.split(',').filter(id => id.trim()).map(id => parseInt(id.trim()));
            if (clientClnums.length > 0) {
                const placeholders = clientClnums.map(() => '?').join(',');
                whereConditions.push(`clnum IN (${placeholders})`);
                params.push(...clientClnums);
            }
        }

        if (whereConditions.length > 0) {
            query += ' WHERE ' + whereConditions.join(' AND ');
        }

        query += ' ORDER BY uploaded_date DESC LIMIT ? OFFSET ?';
        params.push(parseInt(limit), parseInt(offset));

        const [rows] = await dbPool.execute(query, params);
        
        // Get total count
        let countQuery = 'SELECT COUNT(*) as total FROM ccm_sync_table';
        let countParams = [];
        
        if (whereConditions.length > 0) {
            countQuery += ' WHERE ' + whereConditions.join(' AND ');
            countParams = params.slice(0, -2);
        }
        
        const [countResult] = await dbPool.execute(countQuery, countParams);
        const total = countResult[0].total;

        console.log(`📄 Found ${rows.length} contracts (total: ${total})`);
        
        res.json({ 
            contracts: rows,
            total: total,
            limit: parseInt(limit),
            offset: parseInt(offset)
        });

    } catch (error) {
        console.error('Error fetching contracts:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Search contracts in ccm_sync_table - Enhanced search endpoint
app.get('/api/contracts/search', async (req, res) => {
    try {
        if (!dbPool) {
            return res.status(400).json({ error: 'Database not connected' });
        }

        const { q, limit = 50, type, status, clients } = req.query;
        
        if (!q) {
            return res.status(400).json({ error: 'Search query is required' });
        }

        console.log(`🔍 Searching contracts for: "${q}"`);

        // FIXED: Use case-insensitive search
        let query = `SELECT id, clnum, contract_id, contract_name, vendor_name, filename, contract_type, 
                    start_date, end_date, status, uploaded_date, spend, currency, product, file
             FROM ccm_sync_table 
             WHERE LOWER(contract_name) LIKE LOWER(?) OR LOWER(vendor_name) LIKE LOWER(?) OR LOWER(filename) LIKE LOWER(?) 
                   OR LOWER(contract_type) LIKE LOWER(?) OR LOWER(product) LIKE LOWER(?)
                   AND file IS NOT NULL
                   AND file != ''`;
        
        let params = [`%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`, `%${q}%`];
        let whereConditions = [];

        whereConditions.push('file IS NOT NULL');
        whereConditions.push("file != ''");

        // Add additional filters
        if (type) {
            whereConditions.push('contract_type = ?');
            params.push(type);
        }

        if (status) {
            whereConditions.push('status = ?');
            params.push(status);
        }

        // Handle clients filter (comma-separated clnums)
        if (clients) {
            const clientClnums = clients.split(',').filter(id => id.trim()).map(id => parseInt(id.trim()));
            if (clientClnums.length > 0) {
                const placeholders = clientClnums.map(() => '?').join(',');
                whereConditions.push(`clnum IN (${placeholders})`);
                params.push(...clientClnums);
                console.log('🔍 Filtering search by clnums:', clientClnums);
            }
        }

        // Add additional WHERE conditions if any
        if (whereConditions.length > 0) {
            query += ' AND ' + whereConditions.join(' AND ');
        }

        query += ` ORDER BY 
                CASE 
                    WHEN LOWER(vendor_name) LIKE LOWER(?) THEN 1
                    WHEN LOWER(contract_name) LIKE LOWER(?) THEN 2
                    WHEN LOWER(contract_type) LIKE LOWER(?) THEN 3
                    ELSE 4
                END,
                uploaded_date DESC 
             LIMIT ?`;

        // Add priority ordering parameters
        params.push(`%${q}%`, `%${q}%`, `%${q}%`, parseInt(limit));

        console.log('🔍 Search query:', query);

        const [rows] = await dbPool.execute(query, params);

        console.log(`📋 Found ${rows.length} contracts matching search`);

        res.json({ contracts: rows });

    } catch (error) {
        console.error('Error searching contracts:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Get specific contract details from ccm_sync_table
app.get('/api/contracts/:id', async (req, res) => {
    try {
        if (!dbPool) {
            return res.status(400).json({ error: 'Database not connected' });
        }

        const { id } = req.params;
        const [rows] = await dbPool.execute(
            'SELECT * FROM ccm_sync_table WHERE id = ?',
            [id]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: 'Contract not found' });
        }

        res.json({ contract: rows[0] });

    } catch (error) {
        console.error('Error fetching contract:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Get contract statistics
app.get('/api/contracts/stats', async (req, res) => {
    try {
        if (!dbPool) {
            return res.status(400).json({ error: 'Database not connected' });
        }

        // Get various statistics
        const [totalContracts] = await dbPool.execute(
            'SELECT COUNT(*) as total FROM ccm_sync_table'
        );

        const [statusStats] = await dbPool.execute(
            'SELECT status, COUNT(*) as count FROM ccm_sync_table GROUP BY status'
        );

        const [typeStats] = await dbPool.execute(
            'SELECT contract_type, COUNT(*) as count FROM ccm_sync_table GROUP BY contract_type ORDER BY count DESC LIMIT 10'
        );

        const [vendorStats] = await dbPool.execute(
            'SELECT vendor_name, COUNT(*) as count FROM ccm_sync_table WHERE vendor_name IS NOT NULL GROUP BY vendor_name ORDER BY count DESC LIMIT 10'
        );

        const [spendStats] = await dbPool.execute(
            'SELECT SUM(spend) as total_spend, AVG(spend) as avg_spend, currency FROM ccm_sync_table WHERE spend IS NOT NULL GROUP BY currency'
        );

        res.json({
            totalContracts: totalContracts[0].total,
            statusBreakdown: statusStats,
            topContractTypes: typeStats,
            topVendors: vendorStats,
            spendAnalysis: spendStats
        });

    } catch (error) {
        console.error('Error fetching contract statistics:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Delete contract from ccm_sync_table
app.delete('/api/contracts/:id', async (req, res) => {
    try {
        if (!dbPool) {
            return res.status(400).json({ error: 'Database not connected' });
        }

        const { id } = req.params;
        const [result] = await dbPool.execute(
            'DELETE FROM ccm_sync_table WHERE id = ?',
            [id]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Contract not found' });
        }

        res.json({ success: true, message: 'Contract deleted successfully' });

    } catch (error) {
        console.error('Error deleting contract:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Download file from S3 endpoint
app.post('/api/download-file', async (req, res) => {
    try {
        const { fileUrl, fileName } = req.body;
        
        if (!fileUrl) {
            return res.status(400).json({ error: 'File URL is required' });
        }

        console.log(`📥 Downloading file: ${fileUrl}`);

        // Check if AWS credentials are configured
        if (AWS_CONFIG.accessKeyId === 'YOUR_ACCESS_KEY_ID' || !AWS_CONFIG.accessKeyId) {
            return res.status(500).json({ 
                error: 'AWS credentials not configured. Please update AWS_CONFIG in server.js' 
            });
        }

        // Extract bucket and key from S3 URL
        const urlParts = fileUrl.match(/https:\/\/([^.]+)\.s3\.([^.]+\.)?amazonaws\.com\/(.+)/);
        if (!urlParts) {
            return res.status(400).json({ error: 'Invalid S3 URL format' });
        }
        
        const bucketName = urlParts[1];
        let objectKey = urlParts[3];
        
        // Try different encodings for the object key
        const keyVariations = [
            decodeURIComponent(objectKey),  // URL decoded
            objectKey,                      // Original
            objectKey.replace(/\+/g, ' '),  // Replace + with space
            objectKey.replace(/ /g, '+')    // Replace space with +
        ];
        
        console.log(`📦 Bucket: ${bucketName}`);
        console.log(`🔑 Trying key variations:`, keyVariations);

        let s3Object = null;
        let headResult = null;
        let workingKey = null;

        // Try each key variation
        for (const key of keyVariations) {
            try {
                const params = { Bucket: bucketName, Key: key };
                headResult = await s3.headObject(params).promise();
                s3Object = await s3.getObject(params).promise();
                workingKey = key;
                console.log(`✅ Found file with key: ${key}`);
                break;
            } catch (keyError) {
                console.log(`❌ Key "${key}" failed: ${keyError.code}`);
                continue;
            }
        }

        if (!s3Object) {
            console.error('❌ All key variations failed');
            return res.status(404).json({ error: 'File not found with any key variation' });
        }
        
        // Set appropriate headers
        const contentType = headResult.ContentType || 'application/octet-stream';
        const fileExtension = workingKey.split('.').pop() || 'file';
        const downloadFileName = `${fileName.replace(/[^a-z0-9.\-_]/gi, '_')}.${fileExtension}`;
        
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${downloadFileName}"`);
        res.setHeader('Content-Length', headResult.ContentLength);
        
        // Send the file
        res.send(s3Object.Body);
        console.log(`✅ File downloaded successfully: ${downloadFileName}`);

    } catch (error) {
        console.error('File download error:', error?.message || error || 'Unknown error');
        res.status(500).json({ error: error?.message || 'Unknown download error' });
    }
});

// Preview file from S3 endpoint
app.post('/api/preview-file', async (req, res) => {
    try {
        const { fileUrl } = req.body;
        
        if (!fileUrl) {
            return res.status(400).json({ error: 'File URL is required' });
        }

        console.log(`👁️ Previewing file: ${fileUrl}`);

        // Check if AWS credentials are configured
        if (AWS_CONFIG.accessKeyId === 'YOUR_ACCESS_KEY_ID' || !AWS_CONFIG.accessKeyId) {
            return res.status(500).json({ 
                error: 'AWS credentials not configured. Please update AWS_CONFIG in server.js' 
            });
        }

        // Extract bucket and key from S3 URL
        const urlParts = fileUrl.match(/https:\/\/([^.]+)\.s3\.([^.]+\.)?amazonaws\.com\/(.+)/);
        if (!urlParts) {
            return res.status(400).json({ error: 'Invalid S3 URL format' });
        }
        
        const bucketName = urlParts[1];
        let objectKey = urlParts[3];
        
        // Try different encodings for the object key
        const keyVariations = [
            decodeURIComponent(objectKey),
            objectKey,
            objectKey.replace(/\+/g, ' '),
            objectKey.replace(/ /g, '+')
        ];

        let s3Object = null;
        let headResult = null;
        let workingKey = null;

        // Try each key variation
        for (const key of keyVariations) {
            try {
                const params = { Bucket: bucketName, Key: key };
                headResult = await s3.headObject(params).promise();
                s3Object = await s3.getObject(params).promise();
                workingKey = key;
                console.log(`✅ Found file for preview with key: ${key}`);
                break;
            } catch (keyError) {
                continue;
            }
        }

        if (!s3Object) {
            return res.status(404).json({ error: 'File not found for preview' });
        }
        
        // Set headers for inline viewing
        const contentType = headResult.ContentType || 'application/pdf';
        
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', 'inline');
        res.setHeader('Content-Length', headResult.ContentLength);
        
        // Send the file for preview
        res.send(s3Object.Body);
        console.log(`👁️ File preview served successfully`);

    } catch (error) {
        console.error('File preview error:', error?.message || error || 'Unknown error');
        res.status(500).json({ error: error?.message || 'Unknown preview error' });
    }
});

app.post('/api/compare-contracts', upload.fields([
    { name: 'newContract', maxCount: 1 },
    { name: 'uploadedContract', maxCount: 1 }
]), async (req, res) => {
    try {
        const { referenceContractUrl, referenceContractName, useUploadedContract } = req.body;

        console.log('🔍 Contract comparison request:', {
            referenceUrl: referenceContractUrl,
            referenceName: referenceContractName,
            useUploaded: useUploadedContract
        });

        let newContractText = '';
        let newContractName = '';

        // 根据请求类型获取新合同文本
        if (useUploadedContract === 'true') {
            // 使用第一个tab已上传的合同
            const uploadedContract = req.files.uploadedContract?.[0];
            if (!uploadedContract) {
                return res.status(400).json({ error: 'No uploaded contract found' });
            }
            newContractText = await extractTextFromFile(uploadedContract.path, uploadedContract.mimetype);
            newContractName = uploadedContract.originalname;
            
            // 清理临时文件
            fs.unlinkSync(uploadedContract.path);
        } else {
            // 使用新上传的合同（现有逻辑）
            const newContract = req.files.newContract?.[0];
            if (!newContract) {
                return res.status(400).json({ error: 'No new contract file provided' });
            }
            newContractText = await extractTextFromFile(newContract.path, newContract.mimetype);
            newContractName = newContract.originalname;
            
            // 清理临时文件
            fs.unlinkSync(newContract.path);
        }

        // 从S3下载参考合同
        let referenceContractText = '';
        try {
            console.log('📥 Downloading reference contract from S3...');
            
            // 修复S3 URL
            let fixedFileUrl = referenceContractUrl;
            if (fixedFileUrl.includes('ccm-contracts.s3.amazonaws.com')) {
                fixedFileUrl = fixedFileUrl.replace('ccm-contracts.s3.amazonaws.com', 'ccm-contracts.s3.us-east-1.amazonaws.com');
            }

            const urlParts = fixedFileUrl.match(/https:\/\/([^.]+)\.s3\.([^.]+\.)?amazonaws\.com\/(.+)/);
            if (!urlParts) {
                throw new Error('Invalid S3 URL format');
            }

            const bucketName = urlParts[1];
            let objectKey = urlParts[3];

            // 尝试不同的密钥编码
            const keyVariations = [
                decodeURIComponent(objectKey),
                objectKey,
                objectKey.replace(/\+/g, ' '),
                objectKey.replace(/ /g, '+')
            ];

            let s3Object = null;
            for (const key of keyVariations) {
                try {
                    const params = { Bucket: bucketName, Key: key };
                    s3Object = await s3.getObject(params).promise();
                    console.log(`✅ Reference contract downloaded with key: ${key}`);
                    break;
                } catch (keyError) {
                    continue;
                }
            }

            if (!s3Object) {
                throw new Error('Could not download reference contract from S3');
            }

            // 提取文本
            const fileName = objectKey.split('/').pop() || '';
            const fileExtension = fileName.split('.').pop()?.toLowerCase() || '';

            if (fileExtension === 'pdf') {
                const data = await pdf(s3Object.Body);
                referenceContractText = data.text;
            } else if (fileExtension === 'txt') {
                referenceContractText = s3Object.Body.toString('utf8');
            } else if (fileExtension === 'docx') {
                const tempPath = path.join(__dirname, 'temp', `temp_${Date.now()}_${fileName}`);
                const tempDir = path.dirname(tempPath);
                
                if (!fs.existsSync(tempDir)) {
                    fs.mkdirSync(tempDir, { recursive: true });
                }
                
                fs.writeFileSync(tempPath, s3Object.Body);
                const result = await mammoth.extractRawText({ path: tempPath });
                referenceContractText = result.value;
                fs.unlinkSync(tempPath);
            } else {
                throw new Error(`Unsupported file type: ${fileExtension}`);
            }

        } catch (error) {
            console.error('❌ Error downloading reference contract:', error);
            return res.status(500).json({ 
                error: 'Failed to download reference contract: ' + error.message 
            });
        }

        console.log('🤖 Starting AI comparison...');

        // 构建比较提示
        const comparisonPrompt = `
You are a legal contract comparison expert. Compare these two contracts and provide a detailed analysis in JSON format.

REFERENCE CONTRACT (Database): "${referenceContractName}"
${referenceContractText}

NEW CONTRACT (Uploaded): "${newContractName}"
${newContractText}

Please analyze and compare the contracts in the following structured JSON format:

{
  "contract_overview": {
    "Reference_Contract": {
      "name": "contract name",
      "type": "contract type",
      "vendor": "vendor name",
      "estimated_value": "value if mentioned"
    },
    "New_Contract": {
      "name": "contract name", 
      "type": "contract type",
      "vendor": "vendor name",
      "estimated_value": "value if mentioned"
    }
  },
  "key_differences": {
    "payment_terms": {
      "Reference_Contract": "payment terms summary",
      "New_Contract": "payment terms summary"
    },
    "contract_duration": {
      "Reference_Contract": "duration details",
      "New_Contract": "duration details"
    },
    "termination_clauses": {
      "Reference_Contract": "termination details",
      "New_Contract": "termination details"
    },
    "pricing_structure": {
      "Reference_Contract": "pricing details",
      "New_Contract": "pricing details"
    }
  },
  "risk_analysis": {
    "higher_risk_in_new_contract": ["list of risks that are higher in new contract"],
    "lower_risk_in_new_contract": ["list of risks that are lower in new contract"],
    "new_risks_identified": ["list of new risks in the new contract"],
    "overall_risk_assessment": "high|medium|low"
  },
  "recommendations": {
    "negotiation_points": ["list of specific points to negotiate"],
    "missing_clauses": ["list of important clauses missing in new contract"],
    "favorable_terms": ["list of terms that are better in new contract"],
    "concerns": ["list of major concerns with new contract"]
  },
  "summary": {
    "main_differences": "brief summary of main differences",
    "recommendation": "overall recommendation (approve/negotiate/reject)",
    "priority_actions": ["top 3 priority actions"]
  }
}

Provide only the JSON response without any additional text or markdown formatting.
        `;

        const analysis = await callOpenAI(comparisonPrompt);

        console.log('✅ Comparison completed successfully');

        res.json({
            success: true,
            analysis: analysis,
            referenceContract: referenceContractName,
            newContract: newContractName
        });

    } catch (error) {
        console.error('❌ Contract comparison error:', error);
        res.status(500).json({ 
            error: 'Contract comparison failed: ' + error.message 
        });
    }
});

// Update contract in ccm_sync_table
app.put('/api/contracts/:id', async (req, res) => {
    try {
        if (!dbPool) {
            return res.status(400).json({ error: 'Database not connected' });
        }

        const { id } = req.params;
        const updateData = req.body;
        
        // Build dynamic update query based on provided fields
        const allowedFields = [
            'contract_name', 'vendor_name', 'contract_type', 'start_date', 'end_date',
            'status', 'currency', 'spend', 'renewal_type', 'renewal_notice',
            'notification_email', 'contract_owner', 'contract_owner_email',
            'department_responsible', 'termination_clause', 'product',
            'renewal_term', 'vendor_contact_name', 'vendor_contact_address',
            'vendor_contact_email', 'governing_law_state', 'termination_fee',
            'force_majeure', 'payment_terms', 'watchlist'
        ];
        
        const updateFields = [];
        const values = [];
        
        for (const [key, value] of Object.entries(updateData)) {
            if (allowedFields.includes(key)) {
                updateFields.push(`${key} = ?`);
                values.push(value);
            }
        }
        
        if (updateFields.length === 0) {
            return res.status(400).json({ error: 'No valid fields to update' });
        }
        
        // Add modified_date
        updateFields.push('modified_date = ?');
        values.push(new Date().toISOString().slice(0, 19).replace('T', ' '));
        
        // Add ID for WHERE clause
        values.push(id);
        
        const query = `UPDATE ccm_sync_table SET ${updateFields.join(', ')} WHERE id = ?`;
        const [result] = await dbPool.execute(query, values);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Contract not found' });
        }

        res.json({ success: true, message: 'Contract updated successfully' });

    } catch (error) {
        console.error('Error updating contract:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/jira/test-connection', async (req, res) => {
    try {
        if (!JIRA_CONFIG.apiToken || JIRA_CONFIG.apiToken === 'your-jira-api-token') {
            return res.status(500).json({ 
                success: false, 
                message: 'Jira API token not configured' 
            });
        }

        const auth = Buffer.from(`${JIRA_CONFIG.username}:${JIRA_CONFIG.apiToken}`).toString('base64');
        
        const response = await axios.get(`${JIRA_CONFIG.baseUrl}/rest/api/3/myself`, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Accept': 'application/json'
            }
        });

        if (response.status === 200) {
            res.json({ 
                success: true, 
                message: 'Jira connection successful',
                user: response.data.displayName || response.data.emailAddress
            });
        } else {
            res.status(500).json({ 
                success: false, 
                message: 'Jira connection failed' 
            });
        }
    } catch (error) {
        console.error('Jira connection test failed:', error.message);
        res.status(500).json({ 
            success: false, 
            message: 'Jira connection failed: ' + error.message 
        });
    }
});

// 修改 /api/jira/search 端点
app.post('/api/jira/search', async (req, res) => {
    try {
        const { searchTerm, clientClnums, ticketStatus, vendors } = req.body;

        console.log('🎫 Jira search request:', { searchTerm, clientClnums, ticketStatus, vendors });

        if (!JIRA_CONFIG.apiToken || JIRA_CONFIG.apiToken === 'your-jira-api-token') {
            console.log('🎫 Jira not configured, returning empty results');
            return res.json({
                success: true,
                tickets: [],
                total: 0,
                retrieved: 0,
                projectsSearched: [],
                message: 'Jira API not configured'
            });
        }

        const auth = Buffer.from(`${JIRA_CONFIG.username}:${JIRA_CONFIG.apiToken}`).toString('base64');
        
        let jqlParts = [];
        let projectsToSearch = [...JIRA_CONFIG.projectKeys];
        
        // Map clients to projects
        if (clientClnums && clientClnums.length > 0) {
            const matchingProjectKeys = [];
            const clientClnumsAsNumbers = clientClnums.map(clnum => parseInt(clnum));
            
            Object.entries(PROJECT_MAPPING).forEach(([projectKey, projectInfo]) => {
                if (clientClnumsAsNumbers.includes(projectInfo.clnum)) {
                    matchingProjectKeys.push(projectKey);
                    console.log(`🎫 Mapped clnum ${projectInfo.clnum} to project ${projectKey}`);
                }
            });
            
            if (matchingProjectKeys.length > 0) {
                projectsToSearch = [...new Set(matchingProjectKeys)];
            }
        }
        
        const projectFilter = `project IN (${projectsToSearch.map(key => `"${key}"`).join(', ')})`;
        jqlParts.push(projectFilter);
        
        if (ticketStatus && ticketStatus.trim()) {
            const statusFilter = `status = "${ticketStatus.trim()}"`;
            jqlParts.push(statusFilter);
            console.log('🎫 Adding status filter:', statusFilter);
        }
        
        let searchConditions = [];
        if (searchTerm && searchTerm.trim()) {
            searchConditions.push(`summary ~ "${searchTerm.trim()}"`);
            searchConditions.push(`description ~ "${searchTerm.trim()}"`);
            searchConditions.push(`comment ~ "${searchTerm.trim()}"`);
        }

        if (vendors && vendors.length > 0) {
            vendors.forEach(vendor => {
                searchConditions.push(`summary ~ "${vendor}"`);
            });
            console.log('🎫 Added vendor search conditions for:', vendors);
        }
        
        if (searchConditions.length > 0) {
            jqlParts.push(`(${searchConditions.join(' OR ')})`);
        }
        
        const jql = jqlParts.join(' AND ');
        console.log('🎫 Final JQL Query:', jql);

        // 分页获取所有结果
        let allTickets = [];
        let startAt = 0;
        const maxResults = 100; // 每次请求的最大结果数
        let total = 0;
        let hasMore = true;

        try {
            while (hasMore) {
                console.log(`🎫 Fetching tickets ${startAt} to ${startAt + maxResults}...`);
                
                const requestPayload = {
                    jql: jql,
                    startAt: startAt,
                    maxResults: maxResults,
                    fields: [
                        'summary', 'status', 'priority', 'assignee', 'updated',
                        'created', 'description', 'issuetype', 'reporter', 'project'
                    ]
                };

                const searchResponse = await axios.post(
                    `${JIRA_CONFIG.baseUrl}/rest/api/3/search/jql`, 
                    requestPayload,
                    {
                        headers: {
                            'Authorization': `Basic ${auth}`,
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        timeout: 30000
                    }
                );

                const responseData = searchResponse.data;
                const issues = responseData.issues || [];
                
                // 第一次请求时设置total
                if (startAt === 0) {
                    total = responseData.total || 0;
                    console.log(`🎫 Total tickets found: ${total}`);
                }

                // 处理当前批次的tickets
                const processedTickets = issues.map(issue => ({
                    id: issue.key,
                    summary: issue.fields.summary || 'No summary',
                    status: issue.fields.status?.name || 'Unknown',
                    priority: issue.fields.priority?.name || 'Medium',
                    assignee: issue.fields.assignee?.displayName || 'Unassigned',
                    reporter: issue.fields.reporter?.displayName || 'Unknown',
                    updated: issue.fields.updated ? new Date(issue.fields.updated).toISOString().split('T')[0] : 'Unknown',
                    created: issue.fields.created ? new Date(issue.fields.created).toISOString().split('T')[0] : 'Unknown',
                    description: extractDescription(issue.fields.description),
                    issueType: issue.fields.issuetype?.name || 'Task',
                    projectKey: issue.fields.project?.key || 'Unknown',
                    projectName: issue.fields.project?.name || 'Unknown'
                }));

                allTickets = allTickets.concat(processedTickets);

                // 检查是否还有更多结果
                startAt += maxResults;
                hasMore = issues.length === maxResults && startAt < total;

                console.log(`🎫 Retrieved ${allTickets.length} of ${total} tickets so far...`);

                // 添加延迟避免API限制
                if (hasMore) {
                    await new Promise(resolve => setTimeout(resolve, 100));
                }
            }

            console.log(`🎫 Successfully retrieved all ${allTickets.length} Jira tickets`);

        } catch (jiraError) {
            console.error('🎫 Jira API Error:', jiraError.response?.data || jiraError.message);
            // 如果出错但已经获取了一些数据，返回已获取的数据
            if (allTickets.length > 0) {
                console.log(`🎫 Partial results: returning ${allTickets.length} tickets due to error`);
            } else {
                allTickets = [];
                total = 0;
            }
        }

        res.json({
            success: true,
            tickets: allTickets,
            total: total,
            retrieved: allTickets.length,
            projectsSearched: projectsToSearch,
            appliedFilters: {
                searchTerm: searchTerm || null,
                ticketStatus: ticketStatus || null,
                clientClnums: clientClnums || null,
                vendors: vendors || null
            }
        });

    } catch (error) {
        console.error('🎫 Jira search error:', error.message);
        res.status(500).json({ 
            error: 'Jira search failed: ' + error.message
        });
    }
});

// 辅助函数：提取描述文本
function extractDescription(description) {
    if (!description) return 'No description';
    
    // 如果是新格式的 Atlassian Document Format (ADF)
    if (description.content && Array.isArray(description.content)) {
        try {
            return description.content
                .map(block => {
                    if (block.content && Array.isArray(block.content)) {
                        return block.content
                            .map(item => item.text || '')
                            .join(' ');
                    }
                    return '';
                })
                .join(' ')
                .trim() || 'No description';
        } catch (e) {
            return 'Description parsing error';
        }
    }
    
    // 如果是字符串格式
    if (typeof description === 'string') {
        return description;
    }
    
    return 'No description';
}

// Create new Jira ticket
app.post('/api/jira/create-ticket', async (req, res) => {
    try {
        const { summary, description, priority = 'Medium', issueType = 'Task', projectKey = 'REQUEST' } = req.body;

        if (!JIRA_CONFIG.apiToken || JIRA_CONFIG.apiToken === 'your-jira-api-token') {
            return res.status(500).json({ 
                error: 'Jira API not configured' 
            });
        }

        if (!summary) {
            return res.status(400).json({ 
                error: 'Summary is required' 
            });
        }

        // Validate project key
        if (!JIRA_CONFIG.projectKeys.includes(projectKey)) {
            return res.status(400).json({ 
                error: `Invalid project key. Must be one of: ${JIRA_CONFIG.projectKeys.join(', ')}` 
            });
        }

        const auth = Buffer.from(`${JIRA_CONFIG.username}:${JIRA_CONFIG.apiToken}`).toString('base64');

        const ticketData = {
            fields: {
                project: {
                    key: projectKey
                },
                summary: summary,
                description: {
                    type: "doc",
                    version: 1,
                    content: [
                        {
                            type: "paragraph",
                            content: [
                                {
                                    type: "text",
                                    text: description || "Created from Contract Analysis System"
                                }
                            ]
                        }
                    ]
                },
                issuetype: {
                    name: issueType
                },
                priority: {
                    name: priority
                }
            }
        };
        console.log('🔍 projectKey =', projectKey);
        console.log('🎫 ticketData =', JSON.stringify(ticketData, null, 2));

        console.log('🎫 Creating Jira ticket:', { summary, priority, issueType, projectKey });

        const response = await axios.post(`${JIRA_CONFIG.baseUrl}/rest/api/3/issue`, ticketData, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });

        console.log('✅ Jira ticket created:', response.data.key);

        res.json({
            success: true,
            ticketId: response.data.key,
            ticketUrl: `https://ccmchase.atlassian.net/browse/${response.data.key}`,
            message: `Ticket ${response.data.key} created successfully in project ${projectKey}`,
            projectKey: projectKey,
            projectInfo: PROJECT_MAPPING[projectKey]
        });

    } catch (error) {
        console.error('Jira ticket creation error:', error.response?.data || error.message);
        res.status(500).json({ 
            error: 'Failed to create Jira ticket: ' + (error.response?.data?.errorMessages?.[0] || error.message)
        });
    }
});

app.get('/api/jira/projects', async (req, res) => {
    try {
        if (!JIRA_CONFIG.apiToken || JIRA_CONFIG.apiToken === 'your-jira-api-token') {
            return res.status(500).json({ 
                error: 'Jira API not configured' 
            });
        }

        const auth = Buffer.from(`${JIRA_CONFIG.username}:${JIRA_CONFIG.apiToken}`).toString('base64');

        // Get all configured projects
        const projectPromises = JIRA_CONFIG.projectKeys.map(async (projectKey) => {
            try {
                const response = await axios.get(`${JIRA_CONFIG.baseUrl}/rest/api/3/project/${projectKey}`, {
                    headers: {
                        'Authorization': `Basic ${auth}`,
                        'Accept': 'application/json'
                    }
                });
                
                return {
                    key: response.data.key,
                    name: response.data.name,
                    id: response.data.id,
                    companyInfo: PROJECT_MAPPING[projectKey]
                };
            } catch (error) {
                console.warn(`Could not fetch project ${projectKey}:`, error.message);
                return {
                    key: projectKey,
                    name: `${projectKey} (Not accessible)`,
                    id: null,
                    companyInfo: PROJECT_MAPPING[projectKey],
                    error: error.message
                };
            }
        });

        const projects = await Promise.all(projectPromises);

        res.json({
            success: true,
            projects: projects,
            projectMapping: PROJECT_MAPPING
        });

    } catch (error) {
        console.error('Error fetching projects:', error.message);
        res.status(500).json({ 
            error: 'Failed to fetch projects: ' + error.message
        });
    }
});

// Get Jira ticket details
app.get('/api/jira/ticket/:ticketId', async (req, res) => {
    try {
        const { ticketId } = req.params;

        if (!JIRA_CONFIG.apiToken || JIRA_CONFIG.apiToken === 'your-jira-api-token') {
            return res.status(500).json({ 
                error: 'Jira API not configured' 
            });
        }

        const auth = Buffer.from(`${JIRA_CONFIG.username}:${JIRA_CONFIG.apiToken}`).toString('base64');

        const response = await axios.get(`${JIRA_CONFIG.baseUrl}/rest/api/3/issue/${ticketId}`, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'Accept': 'application/json'
            }
        });

        const issue = response.data;
        const ticket = {
            id: issue.key,
            summary: issue.fields.summary,
            status: issue.fields.status?.name || 'Unknown',
            priority: issue.fields.priority?.name || 'Medium',
            assignee: issue.fields.assignee?.displayName || 'Unassigned',
            updated: new Date(issue.fields.updated).toISOString().split('T')[0],
            created: new Date(issue.fields.created).toISOString().split('T')[0],
            description: issue.fields.description?.content?.[0]?.content?.[0]?.text || 
                        issue.fields.description || 'No description',
            issueType: issue.fields.issuetype?.name || 'Task',
            reporter: issue.fields.reporter?.displayName || 'Unknown',
            url: `${JIRA_CONFIG.baseUrl}/browse/${issue.key}`
        };

        res.json({
            success: true,
            ticket: ticket
        });

    } catch (error) {
        console.error('Error fetching Jira ticket:', error.response?.data || error.message);
        if (error.response?.status === 404) {
            res.status(404).json({ 
                error: 'Ticket not found' 
            });
        } else {
            res.status(500).json({ 
                error: 'Failed to fetch ticket: ' + (error.response?.data?.errorMessages?.[0] || error.message)
            });
        }
    }
});

// Replace the entire /api/gl/search endpoint in server.js with this fixed version:

app.post('/api/gl/search', async (req, res) => {
    try {
        if (!dbPool) {
            return res.status(400).json({ error: 'Database not connected' });
        }

        const { searchTerm, clientClnums, vendors } = req.body;

        console.log('💰 GL search request:', { searchTerm, clientClnums, vendors });

        // 设置正确的加密模式
        await dbPool.execute('SET SESSION block_encryption_mode = ?', ['aes-256-ecb']);

        let query = `
            SELECT 
                CAST(
                    AES_DECRYPT(
                        UNHEX(clname),
                        'NZH!SP0P1gsy&UzO1o8V'
                    ) AS CHAR(255)
                ) AS client_name,
                clnum,
                assigned_vendor_name,
                SUM(amount) as amount,
                parent_company,
                YEAR(date) as year,
                COUNT(*) as record_count,
                MAX(date) as latest_date
            FROM qtable__general_ledger_new
            WHERE 1=1
        `;
        let params = [];

        // 添加搜索条件
        if (searchTerm && searchTerm.trim()) {
            query += ` AND (
                LOWER(assigned_vendor_name) LIKE LOWER(?) OR 
                LOWER(CAST(AES_DECRYPT(UNHEX(clname), 'NZH!SP0P1gsy&UzO1o8V') AS CHAR(255))) LIKE LOWER(?)
            )`;
            const searchPattern = `%${searchTerm.trim()}%`;
            params.push(searchPattern, searchPattern);
        }

        // 添加供应商过滤
        if (vendors && vendors.length > 0) {
            const vendorConditions = vendors.map(() => 'LOWER(assigned_vendor_name) LIKE LOWER(?)').join(' OR ');
            query += ` AND (${vendorConditions})`;
            vendors.forEach(vendor => params.push(`%${vendor}%`));
            console.log('💰 Adding vendor filter:', vendors);
        }

        // 添加客户过滤
        if (clientClnums && clientClnums.length > 0) {
            const clientClnumsAsNumbers = clientClnums.map(clnum => parseInt(clnum));
            const placeholders = clientClnumsAsNumbers.map(() => '?').join(',');
            query += ` AND clnum IN (${placeholders})`;
            params.push(...clientClnumsAsNumbers);
        }

        query += ` 
            GROUP BY 
                clname,
                clnum,
                assigned_vendor_name,
                YEAR(date),
                parent_company
            ORDER BY 
                YEAR(date) DESC,
                amount DESC,
                latest_date DESC
            LIMIT 200
        `;

        console.log('💰 GL Query built, executing...');

        const [rows] = await dbPool.execute(query, params);

        console.log(`💰 Found ${rows.length} aggregated GL records`);

        res.json({
            success: true,
            records: rows,
            totalFound: rows.length,
            limited: rows.length === 200 ? 'Results limited to 200 aggregated records' : null
        });

    } catch (error) {
        console.error('GL search error:', error.message);
        res.status(500).json({ 
            error: 'GL search failed: ' + error.message
        });
    }
});

// Get GL statistics
app.get('/api/gl/stats', async (req, res) => {
    try {
        if (!dbPool) {
            return res.status(400).json({ error: 'Database not connected' });
        }

        // Get various GL statistics
        const [totalRecords] = await dbPool.execute(
            'SELECT COUNT(*) as total FROM qtable__general_ledger_new'
        );

        const [topVendors] = await dbPool.execute(
            'SELECT assigned_vendor_name, COUNT(*) as count, SUM(ABS(amount)) as total_amount FROM qtable__general_ledger_new WHERE assigned_vendor_name IS NOT NULL GROUP BY assigned_vendor_name ORDER BY total_amount DESC LIMIT 10'
        );

        res.json({
            totalRecords: totalRecords[0].total,
            topVendors: topVendors,
        });

    } catch (error) {
        console.error('Error fetching GL statistics:', error.message);
        res.status(500).json({ error: error.message });
    }
});


app.post('/api/chat', async (req, res) => {
    try {
        const { message, conversationHistory = [] } = req.body;
        
        console.log('💬 OpenAI chat request:', message);
        
        // 构建对话历史
        const messages = [
            {
                role: 'system',
                content: 'You are a helpful AI assistant. You can answer questions on any topic, provide information, help with analysis, and assist with various tasks. Be conversational, helpful, and accurate.'
            },
            // 添加历史对话
            ...conversationHistory.slice(-10), // 只保留最近10条对话，避免token过多
            {
                role: 'user',
                content: message
            }
        ];

        const response = await axios.post('https://api.openai.com/v1/chat/completions', {
            model: 'o4-mini', 
            messages: messages,
            max_completion_tokens: 2000,
            stream: false
        }, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`
            }
        });

        const aiResponse = response.data.choices[0].message.content;

        res.json({
            success: true,
            response: aiResponse,
            usage: response.data.usage 
        });
        
    } catch (error) {
        console.error('OpenAI chat error:', error);
        
        let errorMessage = 'Sorry, I encountered an error. Please try again.';
        
        if (error.response?.status === 401) {
            errorMessage = 'OpenAI API key is invalid or missing.';
        } else if (error.response?.status === 429) {
            errorMessage = 'Too many requests. Please wait a moment and try again.';
        } else if (error.response?.status === 402) {
            errorMessage = 'OpenAI API quota exceeded. Please check your billing.';
        }
        
        res.status(500).json({
            success: false,
            error: errorMessage
        });
    }
});

app.post('/api/chat/stream', async (req, res) => {
    try {
        const { message, conversationHistory = [] } = req.body;
        
        console.log('💬 OpenAI streaming chat request:', message);
        
        const messages = [
            {
                role: 'system',
                content: 'You are a helpful AI assistant. You can answer questions on any topic, provide information, help with analysis, and assist with various tasks. Be conversational, helpful, and accurate.'
            },
            ...conversationHistory.slice(-10),
            {
                role: 'user',
                content: message
            }
        ];

        const response = await axios.post('https://api.openai.com/v1/chat/completions', {
            model: 'o4-mini',
            messages: messages,
            max_completion_tokens: 2000,
            stream: true
        }, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`
            },
            responseType: 'stream'
        });

        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');

        response.data.on('data', (chunk) => {
            const lines = chunk.toString().split('\n').filter(line => line.trim() !== '');
            
            for (const line of lines) {
                if (line.includes('[DONE]')) {
                    res.write('data: [DONE]\n\n');
                    res.end();
                    return;
                }
                
                if (line.startsWith('data: ')) {
                    try {
                        const data = JSON.parse(line.slice(6));
                        const content = data.choices?.[0]?.delta?.content;
                        if (content) {
                            res.write(`data: ${JSON.stringify({ content })}\n\n`);
                        }
                    } catch (e) {
                        // 忽略解析错误
                    }
                }
            }
        });

        response.data.on('end', () => {
            res.end();
        });

    } catch (error) {
        console.error('OpenAI streaming error:', error);
        res.status(500).json({
            success: false,
            error: 'Streaming chat failed: ' + error.message
        });
    }
});

function formatNumber(num) {
    if (num === null || num === undefined || isNaN(num)) {
        return 'N/A';
    }
    
    return new Intl.NumberFormat('en-US', {
        minimumFractionDigits: 2,
        maximumFractionDigits: 2
    }).format(num);
}

// 添加获取GL过滤器选项的端点
app.post('/api/gl/filter-options', async (req, res) => {
    try {
        if (!dbPool) {
            return res.status(400).json({ error: 'Database not connected' });
        }

        const { searchTerm, clientClnums, vendors } = req.body;

        console.log('📊 Getting GL filter options...');

        // 设置正确的加密模式
        await dbPool.execute('SET SESSION block_encryption_mode = ?', ['aes-256-ecb']);

        // 构建基础 WHERE 条件
        let baseWhereConditions = [];
        let baseParams = [];

        // 添加搜索条件
        if (searchTerm && searchTerm.trim()) {
            baseWhereConditions.push(`(
                LOWER(assigned_vendor_name) LIKE LOWER(?) OR 
                LOWER(CAST(AES_DECRYPT(UNHEX(clname), 'NZH!SP0P1gsy&UzO1o8V') AS CHAR(255))) LIKE LOWER(?)
            )`);
            const searchPattern = `%${searchTerm.trim()}%`;
            baseParams.push(searchPattern, searchPattern);
        }

        // 添加供应商过滤
        if (vendors && vendors.length > 0) {
            const vendorConditions = vendors.map(() => 'LOWER(assigned_vendor_name) LIKE LOWER(?)').join(' OR ');
            baseWhereConditions.push(`(${vendorConditions})`);
            vendors.forEach(vendor => baseParams.push(`%${vendor}%`));
        }

        // 添加客户过滤
        if (clientClnums && clientClnums.length > 0) {
            const clientClnumsAsNumbers = clientClnums.map(clnum => parseInt(clnum));
            const placeholders = clientClnumsAsNumbers.map(() => '?').join(',');
            baseWhereConditions.push(`clnum IN (${placeholders})`);
            baseParams.push(...clientClnumsAsNumbers);
        }

        // 创建基础 WHERE 子句
        const baseWhereClause = baseWhereConditions.length > 0 ? 
            'WHERE ' + baseWhereConditions.join(' AND ') : 
            'WHERE 1=1';

        console.log('📊 Base WHERE clause:', baseWhereClause);

        // 获取所有唯一的年份
        const yearQuery = `
            SELECT DISTINCT YEAR(date) as year 
            FROM qtable__general_ledger_new 
            ${baseWhereClause}
            AND date IS NOT NULL 
            ORDER BY year DESC
        `;

        // 获取所有唯一的客户
        const clientQuery = `
            SELECT DISTINCT
                CAST(
                    AES_DECRYPT(
                        UNHEX(clname),
                        'NZH!SP0P1gsy&UzO1o8V'
                    ) AS CHAR(255)
                ) AS client_name
            FROM qtable__general_ledger_new
            ${baseWhereClause}
            AND clname IS NOT NULL
            AND clname != ''
            ORDER BY client_name
        `;

        // 获取所有唯一的供应商
        const vendorQuery = `
            SELECT DISTINCT assigned_vendor_name 
            FROM qtable__general_ledger_new 
            ${baseWhereClause}
            AND assigned_vendor_name IS NOT NULL 
            AND assigned_vendor_name != '' 
            ORDER BY assigned_vendor_name
        `;

        // 获取所有唯一的母公司
        const parentQuery = `
            SELECT DISTINCT parent_company 
            FROM qtable__general_ledger_new 
            ${baseWhereClause}
            AND parent_company IS NOT NULL 
            AND parent_company != '' 
            ORDER BY parent_company
        `;

        // 并行执行所有查询
        const [yearResults, clientResults, vendorResults, parentResults] = await Promise.all([
            dbPool.execute(yearQuery, baseParams),
            dbPool.execute(clientQuery, baseParams),
            dbPool.execute(vendorQuery, baseParams),
            dbPool.execute(parentQuery, baseParams)
        ]);

        const filterOptions = {
            years: yearResults[0].map(row => row.year).filter(year => year !== null),
            clients: clientResults[0].map(row => row.client_name?.replace(/,?\s*(LLC|Inc|Corp|Ltd|L\.L\.C\.|L\.P\.)\.?$/i, '')).filter(Boolean),
            vendors: vendorResults[0].map(row => row.assigned_vendor_name).filter(Boolean),
            parents: parentResults[0].map(row => row.parent_company).filter(Boolean)
        };

        console.log('📊 Filter options loaded:', {
            years: filterOptions.years.length,
            clients: filterOptions.clients.length,
            vendors: filterOptions.vendors.length,
            parents: filterOptions.parents.length
        });

        res.json({
            success: true,
            filterOptions: filterOptions
        });

    } catch (error) {
        console.error('Error getting GL filter options:', error.message);
        res.status(500).json({ 
            error: 'Failed to get filter options: ' + error.message
        });
    }
});

app.get('/api/gl/test-decrypt', async (req, res) => {
    try {
        if (!dbPool) {
            return res.status(400).json({ error: 'Database not connected' });
        }

        // 设置正确的加密模式
        await dbPool.execute('SET SESSION block_encryption_mode = ?', ['aes-256-ecb']);

        const [rows] = await dbPool.execute(`
            SELECT 
                clnum,
                clname as encrypted_name,
                CAST(
                    AES_DECRYPT(
                        UNHEX(clname),
                        'NZH!SP0P1gsy&UzO1o8V'
                    ) AS CHAR(255)
                ) AS client_name,
                assigned_vendor_name,
                amount
            FROM qtable__general_ledger_new 
            WHERE clname IS NOT NULL 
              AND clname != ''
            LIMIT 5
        `);

        res.json({
            success: true,
            message: 'Decryption test successful',
            sample_data: rows,
            decryption_mode: 'aes-256-ecb'
        });

    } catch (error) {
        console.error('Decryption test error:', error.message);
        res.status(500).json({ 
            error: 'Decryption test failed: ' + error.message
        });
    }
});

// Configure multer for chatbot file uploads (more permissive than contract uploads)
const chatUpload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            const uploadDir = 'uploads/chat/';
            if (!fs.existsSync(uploadDir)) {
                fs.mkdirSync(uploadDir, { recursive: true });
            }
            cb(null, uploadDir);
        },
        filename: (req, file, cb) => {
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            cb(null, uniqueSuffix + '-' + file.originalname);
        }
    }),
    limits: {
        fileSize: 100 * 1024 * 1024 // 100MB limit for chat files
    },
    fileFilter: (req, file, cb) => {
        // Allow most common file types for chat
        const allowedTypes = [
            '.pdf', '.docx', '.txt', '.csv', '.xlsx', '.xls', 
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp',
            '.mp3', '.wav', '.mp4', '.avi', '.mov', '.wmv',
            '.zip', '.rar', '.7z', '.tar', '.gz',
            '.json', '.xml', '.html', '.css', '.js', '.py',
            '.java', '.cpp', '.c', '.h', '.md', '.rtf'
        ];
        const fileExt = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.includes(fileExt)) {
            cb(null, true);
        } else {
            cb(new Error(`File type ${fileExt} not supported. Allowed types: ${allowedTypes.join(', ')}`));
        }
    }
});

// Enhanced text extraction for chatbot (supports more file types)
async function extractTextFromChatFile(filePath, mimeType, originalName) {
    try {
        const fileExtension = path.extname(originalName).toLowerCase();
        
        if (mimeType === 'application/pdf' || fileExtension === '.pdf') {
            console.log('📄 Processing PDF file:', originalName);
            try {
                const dataBuffer = fs.readFileSync(filePath);
                const data = await pdf(dataBuffer);
                
                if (!data.text || data.text.trim().length === 0) {
                    return `📄 PDF Analysis: ${originalName}\n${'='.repeat(60)}\n\n⚠️ PDF appears to be empty or contains only images/scanned content.
        
        This could mean:
        - The PDF contains only images or scanned documents
        - The PDF is password-protected  
        - The PDF has a complex layout that prevents text extraction
        
        Suggestions:
        1. If it's a scanned document, try using OCR software first
        2. Check if the PDF is password-protected
        3. Try converting to a text-based format
        4. You can still describe what you see in the PDF and I can help based on that description.`;
                }
                
                console.log('✅ PDF text extracted successfully, length:', data.text.length);
                return `📄 PDF Analysis: ${originalName}\n${'='.repeat(60)}\n\n${data.text}\n\n💡 Analysis Tips:\n• Ask me questions about specific sections\n• Request summaries or key insights\n• I can help identify important information or patterns`;
                
            } catch (pdfError) {
                console.error('❌ PDF processing error:', pdfError);
                return `📄 PDF File: ${originalName}\n${'='.repeat(60)}\n\n❌ Error processing PDF: ${pdfError.message}
        
        Common issues and solutions:
        - **Password-protected**: Remove password protection first
        - **Corrupted file**: Try re-downloading or re-saving the PDF
        - **Scanned document**: Use OCR software to convert to searchable text
        - **Complex layout**: Try converting to a simpler format
        
        You can still describe the PDF content to me and I'll help analyze it!`;
            }
        } else if (mimeType === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' || fileExtension === '.docx') {
            const result = await mammoth.extractRawText({ path: filePath });
            return result.value;
        } else if (mimeType === 'text/plain' || fileExtension === '.txt') {
            return fs.readFileSync(filePath, 'utf8');
        } else if (fileExtension === '.csv') {
            const csvData = fs.readFileSync(filePath, 'utf8');
            return `CSV Content:\n${csvData}`;
        } else if (fileExtension === '.json') {
            const jsonData = fs.readFileSync(filePath, 'utf8');
            try {
                const parsed = JSON.parse(jsonData);
                return `JSON Content:\n${JSON.stringify(parsed, null, 2)}`;
            } catch (e) {
                return `JSON Content (raw):\n${jsonData}`;
            }
        } else if (['.xlsx', '.xls'].includes(fileExtension)) {
            // 🔥 新增：完整的Excel文件处理
            try {
                console.log('📊 Processing Excel file:', originalName);
                
                // 读取Excel工作簿
                const workbook = XLSX.readFile(filePath);
                let excelContent = `📊 Excel File Analysis: ${originalName}\n`;
                excelContent += `=`.repeat(60) + '\n\n';
                
                // 获取所有工作表
                const sheetNames = workbook.SheetNames;
                excelContent += `📋 Found ${sheetNames.length} worksheet(s): ${sheetNames.join(', ')}\n\n`;
                
                // 处理每个工作表
                sheetNames.forEach((sheetName, sheetIndex) => {
                    console.log(`Processing sheet: ${sheetName}`);
                    
                    const worksheet = workbook.Sheets[sheetName];
                    excelContent += `📄 Sheet ${sheetIndex + 1}: "${sheetName}"\n`;
                    excelContent += `-`.repeat(40) + '\n';
                    
                    // 获取工作表范围
                    if (!worksheet['!ref']) {
                        excelContent += `⚠️  Sheet appears to be empty\n\n`;
                        return;
                    }
                    
                    const range = XLSX.utils.decode_range(worksheet['!ref']);
                    const totalRows = range.e.r + 1;
                    const totalCols = range.e.c + 1;
                    
                    excelContent += `📐 Dimensions: ${totalRows} rows × ${totalCols} columns\n`;
                    
                    // 转换为JSON数组格式（每行一个数组）
                    const jsonData = XLSX.utils.sheet_to_json(worksheet, { 
                        header: 1,
                        defval: '',
                        blankrows: false
                    });
                    
                    if (jsonData.length === 0) {
                        excelContent += `⚠️  No data found in this sheet\n\n`;
                        return;
                    }
                    
                    // 分析数据类型和结构
                    const headers = jsonData[0] || [];
                    const dataRows = jsonData.slice(1);
                    
                    excelContent += `📊 Data Structure:\n`;
                    excelContent += `   • Header row: ${headers.length} columns\n`;
                    excelContent += `   • Data rows: ${dataRows.length}\n\n`;
                    
                    // 显示列信息
                    if (headers.length > 0) {
                        excelContent += `🏷️  Column Headers:\n`;
                        headers.forEach((header, index) => {
                            const columnLetter = XLSX.utils.encode_col(index);
                            const headerText = String(header || `Column${index + 1}`);
                            excelContent += `   ${columnLetter}: ${headerText}\n`;
                        });
                        excelContent += '\n';
                    }
                    
                    // 显示前几行数据作为示例
                    const sampleRows = Math.min(dataRows.length, 10);
                    if (sampleRows > 0) {
                        excelContent += `📝 Sample Data (first ${sampleRows} rows):\n`;
                        
                        for (let i = 0; i < sampleRows; i++) {
                            const row = dataRows[i] || [];
                            const rowNum = i + 2; // +2 因为第1行是表头，数据从第2行开始
                            
                            excelContent += `   Row ${rowNum}: `;
                            const cellValues = row.map((cell, cellIndex) => {
                                if (cell === null || cell === undefined || cell === '') {
                                    return '[empty]';
                                }
                                
                                // 限制单元格显示长度
                                const cellStr = String(cell);
                                return cellStr.length > 30 ? cellStr.substring(0, 30) + '...' : cellStr;
                            });
                            
                            excelContent += cellValues.join(' | ') + '\n';
                        }
                        
                        if (dataRows.length > sampleRows) {
                            excelContent += `   ... and ${dataRows.length - sampleRows} more rows\n`;
                        }
                    }
                    
                    // 数据统计信息
                    if (dataRows.length > 0) {
                        excelContent += `\n📈 Data Summary:\n`;
                        
                        // 分析每列的数据类型
                        headers.forEach((header, colIndex) => {
                            const columnData = dataRows.map(row => row[colIndex]).filter(cell => 
                                cell !== null && cell !== undefined && cell !== ''
                            );
                            
                            if (columnData.length > 0) {
                                const hasNumbers = columnData.some(cell => !isNaN(Number(cell)) && cell !== '');
                                const hasText = columnData.some(cell => isNaN(Number(cell)));
                                const nonEmptyCount = columnData.length;
                                const emptyCount = dataRows.length - nonEmptyCount;
                                
                                let dataType = 'Mixed';
                                if (hasNumbers && !hasText) dataType = 'Numeric';
                                else if (hasText && !hasNumbers) dataType = 'Text';
                                
                                excelContent += `   • ${header || `Column${colIndex + 1}`}: ${dataType} (${nonEmptyCount} filled, ${emptyCount} empty)\n`;
                            }
                        });
                    }
                    
                    excelContent += '\n';
                });
                
                // 添加使用建议
                excelContent += `💡 Analysis Tips:\n`;
                excelContent += `   • You can ask me to analyze specific columns or data patterns\n`;
                excelContent += `   • I can help create summaries, find trends, or answer questions about this data\n`;
                excelContent += `   • Try asking: "What are the main insights from this data?" or "Summarize the key findings"\n`;
                
                console.log('✅ Excel file processed successfully');
                return excelContent;
                
            } catch (xlsxError) {
                console.error('❌ Error processing Excel file:', xlsxError);
                return `[Excel file: ${originalName}] - ❌ Error reading Excel file: ${xlsxError.message}. 

            Possible issues:
            • File may be corrupted or password-protected
            • Unsupported Excel format (try saving as .xlsx)
            • File may be too large or complex

            Please try:
            1. Re-saving the file as a standard .xlsx format
            2. Ensuring the file isn't password-protected
            3. Converting to CSV if the file is very large`;
            }
        } else if (['.html', '.css', '.js', '.py', '.java', '.cpp', '.c', '.h', '.md'].includes(fileExtension)) {
            const codeData = fs.readFileSync(filePath, 'utf8');
            return `${fileExtension.substring(1).toUpperCase()} Code Content:\n${codeData}`;
        } else if (['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'].includes(fileExtension)) {
            return `[Image file: ${originalName}] - This is an image file. I can see the filename but cannot analyze image content directly. Please describe what you'd like me to help you with regarding this image.`;
        } else {
            return `[File: ${originalName}] - File type: ${fileExtension}. I can see this file but may not be able to process its contents directly. Please describe what you'd like me to help you with regarding this file.`;
        }
    } catch (error) {
        console.error('Error extracting text from chat file:', error.message);
        return `[File: ${originalName}] - I encountered an error reading this file: ${error.message}. Please try a different format or describe what you'd like me to help you with.`;
    }
}

app.post('/api/chat/upload', chatUpload.single('file'), async (req, res) => {
    try {
        const { message, conversationHistory = '[]' } = req.body;
        const uploadedFile = req.file;
        
        console.log('💬 Chat with file upload:', {
            message: message?.substring(0, 100) + '...',
            file: uploadedFile ? uploadedFile.originalname : 'none',
            fileSize: uploadedFile ? (uploadedFile.size / 1024 / 1024).toFixed(2) + 'MB' : 'N/A'
        });
        
        let messages = [];
        let isImageFile = false;
        
        if (uploadedFile) {
            const fileExtension = path.extname(uploadedFile.originalname).toLowerCase();
            const imageExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'];
            
            if (imageExtensions.includes(fileExtension)) {
                console.log('📸 Processing image file:', uploadedFile.originalname);
                isImageFile = true;
                
                // 读取图片文件并转换为 base64
                const imageBuffer = fs.readFileSync(uploadedFile.path);
                const base64Image = imageBuffer.toString('base64');
                const mimeType = uploadedFile.mimetype || `image/${fileExtension.substring(1)}`;
                
                // 解析会话历史
                let parsedHistory = [];
                try {
                    parsedHistory = JSON.parse(conversationHistory);
                } catch (e) {
                    console.warn('Could not parse conversation history');
                }
                
                // 构建支持图片的消息
                messages = [
                    {
                        role: 'system',
                        content: 'You are a helpful AI assistant with vision capabilities. When users upload images, analyze the visual content and provide detailed, helpful insights. Describe what you see, answer questions about the image, and provide relevant information or suggestions.'
                    },
                    ...parsedHistory.slice(-8), // 减少历史消息以节省 tokens
                    {
                        role: 'user',
                        content: [
                            {
                                type: 'text',
                                text: message || 'Please analyze this image and describe what you see.'
                            },
                            {
                                type: 'image_url',
                                image_url: {
                                    url: `data:${mimeType};base64,${base64Image}`
                                }
                            }
                        ]
                    }
                ];
                
                console.log('📸 Image prepared for OpenAI Vision API');
                
            } else {
                // 处理非图片文件（现有逻辑）
                console.log('📎 Processing non-image file:', uploadedFile.originalname);
                
                const fileContent = await extractTextFromChatFile(
                    uploadedFile.path, 
                    uploadedFile.mimetype, 
                    uploadedFile.originalname
                );
                
                const fileInfo = `\n\n[File uploaded: ${uploadedFile.originalname} (${(uploadedFile.size / 1024 / 1024).toFixed(2)}MB)]\n`;
                const completeMessage = `${fileInfo}File content:\n${fileContent}\n\nUser message: ${message || 'Please analyze this file.'}`;
                
                // 解析会话历史
                let parsedHistory = [];
                try {
                    parsedHistory = JSON.parse(conversationHistory);
                } catch (e) {
                    console.warn('Could not parse conversation history');
                }
                
                messages = [
                    {
                        role: 'system',
                        content: 'You are a helpful AI assistant. When users upload files, analyze the content and provide helpful insights. For code files, you can review, explain, or suggest improvements. For documents, you can summarize, answer questions, or provide analysis. Be specific and actionable in your responses.'
                    },
                    ...parsedHistory.slice(-10),
                    {
                        role: 'user',
                        content: completeMessage
                    }
                ];
            }
            
            // 清理上传的文件
            try {
                fs.unlinkSync(uploadedFile.path);
            } catch (cleanupError) {
                console.warn('Could not delete uploaded file:', cleanupError.message);
            }
        } else {
            // 没有文件的普通聊天
            let parsedHistory = [];
            try {
                parsedHistory = JSON.parse(conversationHistory);
            } catch (e) {
                console.warn('Could not parse conversation history');
            }
            
            messages = [
                {
                    role: 'system',
                    content: 'You are a helpful AI assistant. You can answer questions on any topic, provide information, help with analysis, and assist with various tasks. Be conversational, helpful, and accurate.'
                },
                ...parsedHistory.slice(-10),
                {
                    role: 'user',
                    content: message
                }
            ];
        }

        console.log('🤖 Sending to OpenAI with', messages.length, 'messages');

        // 根据是否是图片选择不同的模型
        const modelToUse = isImageFile ? 'gpt-4o-mini' : 'gpt-4o-mini';
        console.log('🤖 Using model:', modelToUse);

        const response = await axios.post('https://api.openai.com/v1/chat/completions', {
            model: modelToUse,
            messages: messages,
            max_tokens: isImageFile ? 2000 : 4000, // 图片分析通常需要更多 tokens
            stream: false
        }, {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${OPENAI_API_KEY}`
            }
        });

        const aiResponse = response.data.choices[0].message.content;

        res.json({
            success: true,
            response: aiResponse,
            fileProcessed: !!uploadedFile,
            fileName: uploadedFile?.originalname,
            fileSize: uploadedFile ? (uploadedFile.size / 1024 / 1024).toFixed(2) + 'MB' : null,
            isImage: isImageFile,
            modelUsed: modelToUse,
            usage: response.data.usage
        });
        
        console.log('✅ Chat with file completed successfully');
        
    } catch (error) {
        console.error('❌ Chat with file error:', error);
        
        // 清理文件如果出错
        if (req.file) {
            try {
                fs.unlinkSync(req.file.path);
            } catch (cleanupError) {
                console.warn('Could not delete uploaded file after error:', cleanupError.message);
            }
        }
        
        let errorMessage = 'Sorry, I encountered an error processing your request.';
        
        if (error.response?.status === 401) {
            errorMessage = 'OpenAI API key is invalid or missing.';
        } else if (error.response?.status === 429) {
            errorMessage = 'Too many requests. Please wait a moment and try again.';
        } else if (error.response?.status === 402) {
            errorMessage = 'OpenAI API quota exceeded. Please check your billing.';
        } else if (error.message.includes('File too large')) {
            errorMessage = 'File is too large. Please upload files smaller than 100MB.';
        } else if (error.message.includes('not supported')) {
            errorMessage = error.message;
        }
        
        res.status(500).json({
            success: false,
            error: errorMessage
        });
    }
});

app.post('/api/contracts/batch-search', async (req, res) => {
    try {
        const { contractIds, searchTerms, searchType = 'product' } = req.body;
        
        if (!contractIds || !Array.isArray(contractIds) || contractIds.length === 0) {
            return res.status(400).json({ error: 'Contract IDs are required' });
        }
        
        if (!searchTerms || searchTerms.trim().length === 0) {
            return res.status(400).json({ error: 'Search terms are required' });
        }
        
        console.log(`🔍 Batch search in ${contractIds.length} contracts for: "${searchTerms}"`);
        
        if (!dbPool) {
            return res.status(400).json({ error: 'Database not connected' });
        }
        
        // Get contract details from database
        const placeholders = contractIds.map(() => '?').join(',');
        const [contracts] = await dbPool.execute(
            `SELECT id, contract_id, contract_name, vendor_name, file, product, clnum 
             FROM ccm_sync_table 
             WHERE id IN (${placeholders}) AND file IS NOT NULL AND file != ''`,
            contractIds
        );
        
        if (contracts.length === 0) {
            return res.status(404).json({ error: 'No contracts found' });
        }
        
        console.log(`📄 Found ${contracts.length} contracts in database`);
        
        const searchResults = [];
        const searchTermsArray = searchTerms.toLowerCase().split(',').map(term => term.trim()).filter(term => term.length > 0);
        
        // Check AWS credentials
        if (AWS_CONFIG.accessKeyId === 'YOUR_ACCESS_KEY_ID' || !AWS_CONFIG.accessKeyId) {
            console.warn('⚠️ AWS not configured, searching in database fields only');
            
            // Search in database fields only (product, contract_name, etc.)
            for (const contract of contracts) {
                const matches = [];
                
                // Search in product field
                if (contract.product) {
                    const productLower = contract.product.toLowerCase();
                    searchTermsArray.forEach(term => {
                        if (productLower.includes(term)) {
                            matches.push({
                                field: 'product',
                                term: term,
                                context: highlightTerm(contract.product, term, 100)
                            });
                        }
                    });
                }
                
                // Search in contract name
                if (contract.contract_name) {
                    const nameLower = contract.contract_name.toLowerCase();
                    searchTermsArray.forEach(term => {
                        if (nameLower.includes(term)) {
                            matches.push({
                                field: 'contract_name',
                                term: term,
                                context: highlightTerm(contract.contract_name, term, 100)
                            });
                        }
                    });
                }
                
                const clientName = clientMapping[parseInt(contract.clnum)] || `Client ${contract.clnum}`;
                
                searchResults.push({
                    contractId: contract.id,
                    contractName: contract.contract_name,
                    vendorName: contract.vendor_name,
                    clientName: clientName,
                    fileUrl: contract.file,
                    hasFile: !!contract.file,
                    matches: matches,
                    searchMethod: 'database_only'
                });
            }
        } else {
            // Full file content search using S3
            for (const contract of contracts) {
                let fileContent = '';
                let fileSearched = false;
                
                // Try to download and extract text from S3 file
                if (contract.file) {
                    try {
                        console.log(`📥 Downloading file for contract ${contract.id}: ${contract.contract_name}`);
                        
                        // Fix S3 URL if needed
                        let fixedFileUrl = contract.file;
                        if (fixedFileUrl.includes('ccm-contracts.s3.amazonaws.com')) {
                            fixedFileUrl = fixedFileUrl.replace('ccm-contracts.s3.amazonaws.com', 'ccm-contracts.s3.us-east-1.amazonaws.com');
                        }
                        
                        // Extract bucket and key from S3 URL
                        const urlParts = fixedFileUrl.match(/https:\/\/([^.]+)\.s3\.([^.]+\.)?amazonaws\.com\/(.+)/);
                        if (urlParts) {
                            const bucketName = urlParts[1];
                            let objectKey = urlParts[3];
                            
                            // Try different encodings for the object key
                            const keyVariations = [
                                decodeURIComponent(objectKey),
                                objectKey,
                                objectKey.replace(/\+/g, ' '),
                                objectKey.replace(/ /g, '+')
                            ];
                            
                            let s3Object = null;
                            for (const key of keyVariations) {
                                try {
                                    const params = { Bucket: bucketName, Key: key };
                                    s3Object = await s3.getObject(params).promise();
                                    console.log(`✅ File downloaded successfully with key: ${key}`);
                                    break;
                                } catch (keyError) {
                                    continue;
                                }
                            }
                            
                            if (s3Object) {
                                // Extract text based on file type
                                const fileName = objectKey.split('/').pop() || '';
                                const fileExtension = fileName.split('.').pop()?.toLowerCase() || '';
                                
                                if (fileExtension === 'pdf') {
                                    try {
                                        const data = await pdf(s3Object.Body);
                                        fileContent = data.text;
                                        fileSearched = true;
                                    } catch (pdfError) {
                                        console.warn(`Could not extract text from PDF: ${pdfError.message}`);
                                    }
                                } else if (fileExtension === 'txt') {
                                    fileContent = s3Object.Body.toString('utf8');
                                    fileSearched = true;
                                } else if (fileExtension === 'docx') {
                                    try {
                                        // Save temporarily to extract text
                                        const tempPath = path.join(__dirname, 'temp', `temp_${Date.now()}_${fileName}`);
                                        const tempDir = path.dirname(tempPath);
                                        
                                        if (!fs.existsSync(tempDir)) {
                                            fs.mkdirSync(tempDir, { recursive: true });
                                        }
                                        
                                        fs.writeFileSync(tempPath, s3Object.Body);
                                        const result = await mammoth.extractRawText({ path: tempPath });
                                        fileContent = result.value;
                                        fileSearched = true;
                                        
                                        // Clean up temp file
                                        fs.unlinkSync(tempPath);
                                    } catch (docxError) {
                                        console.warn(`Could not extract text from DOCX: ${docxError.message}`);
                                    }
                                } else {
                                    console.log(`Unsupported file type for text extraction: ${fileExtension}`);
                                }
                            } else {
                                console.warn(`Could not download file: ${fixedFileUrl}`);
                            }
                        }
                    } catch (error) {
                        console.warn(`Error processing file for contract ${contract.id}: ${error.message}`);
                    }
                }
                
                // Search for terms
                const matches = [];
                
                // Search in file content if available
                if (fileContent && fileSearched) {
                    const contentLower = fileContent.toLowerCase();
                    searchTermsArray.forEach(term => {
                        const regex = new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
                        const termMatches = [...contentLower.matchAll(new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'))];
                        
                        termMatches.forEach(match => {
                            const start = Math.max(0, match.index - 50);
                            const end = Math.min(fileContent.length, match.index + term.length + 50);
                            const context = fileContent.substring(start, end);
                            
                            matches.push({
                                field: 'file_content',
                                term: term,
                                context: highlightTerm(context, term, 100),
                                position: match.index
                            });
                        });
                    });
                }
                
                // Also search in database fields as fallback
                if (contract.product) {
                    const productLower = contract.product.toLowerCase();
                    searchTermsArray.forEach(term => {
                        if (productLower.includes(term)) {
                            matches.push({
                                field: 'product',
                                term: term,
                                context: highlightTerm(contract.product, term, 100)
                            });
                        }
                    });
                }
                
                const clientName = clientMapping[parseInt(contract.clnum)] || `Client ${contract.clnum}`;
                
                searchResults.push({
                    contractId: contract.id,
                    contractName: contract.contract_name,
                    vendorName: contract.vendor_name,
                    clientName: clientName,
                    fileUrl: contract.file,
                    hasFile: !!contract.file,
                    fileSearched: fileSearched,
                    matches: matches,
                    searchMethod: fileSearched ? 'full_content' : 'database_only'
                });
            }
        }
        
        // Sort results by number of matches (most matches first)
        searchResults.sort((a, b) => b.matches.length - a.matches.length);
        
        const totalMatches = searchResults.reduce((sum, result) => sum + result.matches.length, 0);
        
        console.log(`✅ Batch search completed: ${totalMatches} total matches found`);
        
        res.json({
            success: true,
            searchTerms: searchTerms,
            contractsSearched: contracts.length,
            results: searchResults,
            totalMatches: totalMatches,
            searchMethod: searchResults[0]?.searchMethod || 'database_only'
        });
        
    } catch (error) {
        console.error('Batch search error:', error.message);
        res.status(500).json({ 
            error: 'Batch search failed: ' + error.message 
        });
    }
});

app.get('/health', (req, res) => {
    console.log('✅ Health route accessed');
    res.status(200).json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        port: process.env.PORT || 8080,
        routes: 'working'
    });
});

app.get('/test', (req, res) => {
    console.log('✅ Test route accessed');
    res.status(200).json({
        message: 'Test route is working!',
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url
    });
});

// 调试路由 - 显示所有路由
app.get('/debug', (req, res) => {
    console.log('✅ Debug route accessed');
    
    // 获取所有注册的路由
    const routes = [];
    app._router.stack.forEach(function(r){
        if (r.route && r.route.path){
            routes.push({
                method: Object.keys(r.route.methods)[0].toUpperCase(),
                path: r.route.path
            });
        }
    });
    
    res.json({
        message: 'Debug information',
        timestamp: new Date().toISOString(),
        registeredRoutes: routes,
        environment: {
            NODE_ENV: process.env.NODE_ENV,
            PORT: process.env.PORT,
            __dirname: __dirname,
            cwd: process.cwd()
        }
    });
});

app.get('/login.html', (req, res) => {
    console.log('✅ Login route accessed');
    res.send(`
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login - Debug Version</title>
            <style>
                body { 
                    font-family: Arial, sans-serif; 
                    max-width: 500px; 
                    margin: 50px auto; 
                    padding: 20px;
                    background: #f5f5f5;
                }
                .container {
                    background: white;
                    padding: 30px;
                    border-radius: 10px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                .form-group { margin: 15px 0; }
                input { 
                    width: 100%; 
                    padding: 12px; 
                    margin: 5px 0; 
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    box-sizing: border-box;
                }
                button { 
                    background: #007bff; 
                    color: white; 
                    padding: 12px 20px; 
                    border: none; 
                    border-radius: 5px; 
                    cursor: pointer;
                    width: 100%;
                }
                button:hover { background: #0056b3; }
                .links { margin: 20px 0; text-align: center; }
                .links a { margin: 0 10px; color: #007bff; text-decoration: none; }
                .status { background: #d4edda; padding: 10px; border-radius: 5px; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🚀 Login - Debug Version</h1>
                
                <div class="status">
                    <strong>Status:</strong> Server is running correctly!<br>
                    <strong>Time:</strong> ${new Date().toISOString()}<br>
                    <strong>Route:</strong> /login.html working
                </div>

                <form onsubmit="return testLogin(event)">
                    <div class="form-group">
                        <label>Username:</label>
                        <input type="text" id="username" placeholder="admin" value="admin">
                    </div>
                    <div class="form-group">
                        <label>Password:</label>
                        <input type="password" id="password" placeholder="admin123" value="admin123">
                    </div>
                    <button type="submit">Login (Test)</button>
                </form>

                <div class="links">
                    <a href="/">Home</a> |
                    <a href="/health">Health</a> |
                    <a href="/test">Test</a> |
                    <a href="/debug">Debug</a>
                </div>
            </div>

            <script>
                function testLogin(event) {
                    event.preventDefault();
                    const username = document.getElementById('username').value;
                    const password = document.getElementById('password').value;
                    
                    alert('Login test successful!\\nUsername: ' + username + '\\nThis is just a test - routes are working!');
                    return false;
                }
            </script>
        </body>
        </html>
    `);
});

// Advanced contract search endpoint
app.post('/api/contracts/advanced-search', async (req, res) => {
    try {
        if (!dbPool) {
            return res.status(400).json({ error: 'Database not connected' });
        }

        const { contractName, productName, vendorName } = req.body;
        
        console.log('🔍 Advanced contract search:', { contractName, productName, vendorName });
        
        if (!contractName && !productName && !vendorName) {
            return res.status(400).json({ error: 'At least one search criteria is required' });
        }

        let query = `
            SELECT id, clnum, contract_id, contract_name, vendor_name, filename, contract_type, 
                   start_date, end_date, status, currency, spend, contract_owner,
                   vendor_contact_name, vendor_contact_email, vendor_contact_address,
                   department_responsible, uploaded_date, modified_date, product, file
            FROM ccm_sync_table
            WHERE file IS NOT NULL AND file != ''
        `;
        let params = [];
        let conditions = [];

        // Add contract name search (partial match, case-insensitive)
        if (contractName && contractName.trim()) {
            conditions.push('LOWER(contract_name) LIKE LOWER(?)');
            params.push(`%${contractName.trim()}%`);
        }

        // Add contact name search (partial match, case-insensitive)
        if (productName && productName.trim()) {
            conditions.push('LOWER(product) LIKE LOWER(?)');
            params.push(`%${productName.trim()}%`);
        }

        // Add vendor name search (partial match, case-insensitive)
        if (vendorName && vendorName.trim()) {
            conditions.push('LOWER(vendor_name) LIKE LOWER(?)');
            params.push(`%${vendorName.trim()}%`);
        }

        // Combine conditions with AND logic
        if (conditions.length > 0) {
            query += ' AND (' + conditions.join(' AND ') + ')';
        }

        query += ' ORDER BY uploaded_date DESC LIMIT 100';

        console.log('🔍 Search query:', query);

        const [rows] = await dbPool.execute(query, params);

        console.log(`📋 Found ${rows.length} contracts matching advanced search`);

        res.json({ 
            success: true,
            contracts: rows,
            searchCriteria: {
                contractName: contractName || null,
                contactName: productName || null,
                vendorName: vendorName || null
            }
        });

    } catch (error) {
        console.error('Advanced contract search error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Enhanced search vendor endpoint for chatbot with full display functionality
app.post('/api/search-vendor-enhanced', async (req, res) => {
    try {
        const { vendorNames, dataSources, jiraSpaces } = req.body;
        
        if (!dbPool) {
            return res.status(400).json({ 
                success: false, 
                error: 'Database not connected' 
            });
        }
        
        console.log('🔍 Chatbot search request:', { vendorNames, dataSources });
        
        // Parse vendor names and data sources
        const vendors = vendorNames.split(',').map(v => v.trim()).filter(v => v);
        const sources = Array.isArray(dataSources) ? dataSources.map(s => s.toLowerCase()) : dataSources.split(',').map(s => s.trim().toLowerCase()).filter(s => s);
        
        let results = {
            contracts: [],
            jiraTickets: [],
            glRecords: []
        };
        
        // Search contracts if requested
        if (sources.includes('contract')) {
            try {
                const contractQuery = `
                    SELECT id, clnum, contract_id, contract_name, vendor_name, filename, contract_type, 
                           start_date, end_date, status, currency, spend, contract_owner,
                           department_responsible, uploaded_date, modified_date, product, file
                    FROM ccm_sync_table
                    WHERE file IS NOT NULL 
                    AND file != ''
                    AND (${vendors.map(() => 'LOWER(vendor_name) LIKE LOWER(?)').join(' OR ')})
                    ORDER BY CAST(spend AS DECIMAL(15,2)) DESC
                    LIMIT 200
                `;
                const contractParams = vendors.map(v => `%${v}%`);
                const [contractRows] = await dbPool.execute(contractQuery, contractParams);
                results.contracts = contractRows;
            } catch (error) {
                console.error('❌ Contract search error:', error);
            }
        }
        
        // Search GL records if requested  
        if (sources.includes('gl')) {
            try {
                // Set encryption mode
                await dbPool.execute('SET SESSION block_encryption_mode = ?', ['aes-256-ecb']);
                
                const glQuery = `
                    SELECT 
                        CAST(
                            AES_DECRYPT(
                                UNHEX(clname),
                                'NZH!SP0P1gsy&UzO1o8V'
                            ) AS CHAR(255)
                        ) AS client_name,
                        clnum,
                        assigned_vendor_name,
                        SUM(amount) as amount,
                        parent_company,
                        YEAR(date) as year,
                        COUNT(*) as record_count,
                        MAX(date) as latest_date
                    FROM qtable__general_ledger_new
                    WHERE 1=1
                    AND (${vendors.map(() => 'LOWER(assigned_vendor_name) LIKE LOWER(?)').join(' OR ')})
                    GROUP BY 
                        clname,
                        clnum,
                        assigned_vendor_name,
                        YEAR(date),
                        parent_company
                    ORDER BY 
                        YEAR(date) DESC,
                        amount DESC,
                        latest_date DESC
                    LIMIT 200
                `;
                const glParams = vendors.map(v => `%${v}%`);
                const [glRows] = await dbPool.execute(glQuery, glParams);
                results.glRecords = glRows;
            } catch (error) {
                console.error('❌ GL search error:', error);
            }
        }
        
        // Search Jira tickets if requested
        if (sources.includes('jira')) {
            try {
                if (!JIRA_CONFIG.apiToken || JIRA_CONFIG.apiToken === 'your-jira-api-token') {
                    console.log('🎫 Jira not configured, returning empty results');
                    results.jiraTickets = [];
                } else {
                    // Build JQL query for vendor search
                    let jqlParts = [];
                    
                    // Search in summary and comments for any of the vendor names (not description)
                    if (vendors.length > 0) {
                        const vendorQuery = vendors.map(vendor => 
                            `(summary ~ "${vendor}" OR comment ~ "${vendor}")`
                        ).join(' OR ');
                        jqlParts.push(`(${vendorQuery})`);
                    }
                    
                    const jql = jqlParts.join(' AND ');
                    console.log('🎫 Jira JQL Query for vendor search:', jql);
                    
                    // Get Jira tickets with pagination - exactly like Python code
                    let allTickets = [];
                    const maxResults = 1000;
                    let hasMore = true;
                    let requestPayload = {
                        jql: jql,
                        fields: ['summary', 'description', 'status', 'assignee', 'reporter', 'created', 'updated', 'issuetype', 'project', 'priority'],
                        maxResults: maxResults
                    };
                    
                    while (hasMore) {
                        const jiraResponse = await axios.post(
                            `${JIRA_CONFIG.baseUrl}/rest/api/3/search/jql`,
                            requestPayload,
                            {
                                headers: {
                                    'Authorization': `Basic ${Buffer.from(`${JIRA_CONFIG.username}:${JIRA_CONFIG.apiToken}`).toString('base64')}`,
                                    'Accept': 'application/json',
                                    'Content-Type': 'application/json'
                                },
                                timeout: 30000
                            }
                        );
                        
                        const data = jiraResponse.data;
                        const issues = data.issues || [];
                        
                        const processedTickets = issues.map(issue => ({
                            key: issue.key,
                            summary: issue.fields.summary || 'No summary',
                            description: (typeof issue.fields.description === 'string' ? issue.fields.description : JSON.stringify(issue.fields.description) || 'No description').substring(0, 200) + '...',
                            status: issue.fields.status?.name || 'Unknown',
                            assignee: issue.fields.assignee?.displayName || 'Unassigned',
                            reporter: issue.fields.reporter?.displayName || 'Unknown',
                            created: issue.fields.created ? new Date(issue.fields.created).toLocaleDateString() : 'Unknown',
                            updated: issue.fields.updated ? new Date(issue.fields.updated).toLocaleDateString() : 'Unknown',
                            issueType: issue.fields.issuetype?.name || 'Task',
                            projectKey: issue.fields.project?.key || 'Unknown',
                            projectName: issue.fields.project?.name || 'Unknown',
                            priority: issue.fields.priority?.name || ''
                        }));
                        
                        allTickets = allTickets.concat(processedTickets);
                        
                        // Check for next page exactly like Python code
                        const nextToken = data.nextPageToken;
                        if (nextToken) {
                            requestPayload.nextPageToken = nextToken;
                            hasMore = true;
                        } else {
                            hasMore = false;
                        }
                    }
                    
                    results.jiraTickets = allTickets;
                    console.log(`🎫 Successfully retrieved ${allTickets.length} Jira tickets for vendor search`);
                }
            } catch (error) {
                console.error('❌ Jira search error:', error);
                results.jiraTickets = [];
            }
        }
        
        // Format response for chatbot with complete HTML tables like search vendor tab
        let responseText = formatEnhancedSearchResults(results, vendors, sources);
        
        res.json({
            success: true,
            response: responseText,
            data: results
        });
        
    } catch (error) {
        console.error('❌ Vendor search error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// Enhanced helper function to format search results exactly like search vendor tab
function formatEnhancedSearchResults(results, vendors, sources) {
    let response = `**Search Results for Vendors: ${vendors.join(', ')}**\n\n`;
    
    // Add results summary
    const totalResults = (results.contracts?.length || 0) + (results.jiraTickets?.length || 0) + (results.glRecords?.length || 0);
    response += `<div style="background: #f8fafc; padding: 15px; border-radius: 8px; margin: 10px 0; border: 1px solid #e5e7eb;">`;
    response += `<h4 style="margin-top: 0; color: #374151;">Search Results Summary</h4>`;
    response += `<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px;">`;
    
    if (sources.includes('contract')) {
        response += `<div style="text-align: center;"><strong style="font-size: 1.5em; color: #3b82f6;">${results.contracts?.length || 0}</strong><br><span style="color: #6b7280;">Contracts</span></div>`;
    }
    if (sources.includes('gl')) {
        response += `<div style="text-align: center;"><strong style="font-size: 1.5em; color: #10b981;">${results.glRecords?.length || 0}</strong><br><span style="color: #6b7280;">GL Records</span></div>`;
    }
    if (sources.includes('jira')) {
        response += `<div style="text-align: center;"><strong style="font-size: 1.5em; color: #f59e0b;">${results.jiraTickets?.length || 0}</strong><br><span style="color: #6b7280;">Jira Tickets</span></div>`;
    }
    response += `<div style="text-align: center;"><strong style="font-size: 1.5em; color: #dc2626;">${totalResults}</strong><br><span style="color: #6b7280;">Total Results</span></div>`;
    response += `</div></div>\n\n`;

    // Attorney mapping - maps client names to attorney/revenue information
    const attorneyMapping = {
        "Baker Botts L.L.P.": "Total Attorney: 700",
        "Simpson Thacher & Bartlett LLP": "Total Attorney: 1200",
        "Paul Weiss": "Total Attorney: 1000",
        "Schulte Roth & Zabel LLP": "Total Attorney: 300",
        "Chapman and Cutler LLP": "Total Attorney: 200",
        "Phillips Lytle LLP": "Total Attorney: 100",
        "Ropes & Gray LLP": "Total Attorney: 1500",
        "Harris Beach PLLC": "Total Attorney: 200",
        "Morris, Nichols, Arsht & Tunnell LLP": "Total Attorney: 100",
        "Beveridge & Diamond, PC": "Total Attorney: 100",
        "Cleary Gottlieb Steen & Hamilton LLP": "Total Attorney: 1200",
        "Kaufman Borgeest Ryan LLP - FedEx Pricing Audit": "Total Attorney: 100",
        "Adler Pollock & Sheehan PC": "Total Attorney: 100",
        "Ogletree": "Total Attorney: 900",
        "Proskauer": "Total Attorney: 800",
        "Bricker Graydon LLP": "Total Attorney: 200",
        "Steptoe": "Total Attorney: 400",
        "Frost Brown Todd LLP": "Total Attorney: 600",
        "Akerman LLP": "Total Attorney: 700",
        "Cadwalader, Wickersham & Taft LLP": "Total Attorney: 400",
        "Ankura Consulting Group, LLC": "Total Revenue: $800M",
        "Crash Champions": "Total Revenue: $5B"
    };

    // Helper function to get attorney display from client name (same as search vendor tab)
    function getAttorneyDisplay(clientName) {
        if (attorneyMapping.hasOwnProperty(clientName)) {
            return attorneyMapping[clientName];
        }
        return "Corp";
    }

    // Legacy client mapping for reference (not used in display)
    const clientMapping = {
        4: "Alston & Bird LLP", 5: "Ruden McClosky", 6: "Dykema Gossett PLLC", 8: "Miller & Martin PLLC",
        9: "Hogan Lovells US LLP", 10: "Cranfill, Sumner, & Hartzog, L.L.P.", 12: "Poyner & Spruill LLP",
        13: "Warner Norcross & Judd", 14: "Olshan Frome Wolosky LLP", 15: "Cadwalader, Wickersham & Taft LLP",
        16: "Baker & Hostetler LLP", 17: "Brown Rudnick LLP", 18: "Phillips Lytle LLP", 19: "Andrews Kurth LLP",
        20: "Miller & Chevalier", 21: "Baker, Donelson, Bearman, Caldwell & Berkowitz PC", 22: "Jones Vargas",
        23: "Paul, Weiss, Rifkind, Wharton & Garrison LLP", 24: "Robins Kaplan LLP", 26: "Ropes & Gray LLP",
        27: "Royston, Rayzor, Vickery & Williams, L.L.P.", 28: "Vinson & Elkins L.L.P.", 30: "Wilson Sonsini Goodrich & Rosati",
        31: "Stinson Leonard Street", 32: "Bank Street College of Education", 33: "Keker & Van Nest L.L.P.",
        34: "ESL Federal Credit Union", 35: "Chamberlain, Hrdlicka, White, Williams & Martin", 36: "Meagher & Geer, P.L.L.P.",
        37: "Farella Braun & Martel LLP", 38: "Bingham McHale LLP", 39: "Wolf Haldenstein Adler Freeman & Herz LLP",
        40: "Nixon Peabody LLP", 41: "Gray Plant Mooty", 42: "Schiff Hardin LLP", 43: "Procopio, Cory, Hargreaves & Savitch LLP",
        44: "Akin Gump Strauss Hauer & Feld LLP", 45: "Sterne, Kessler, Goldstein & Fox P.L.L.C.", 46: "Snell & Wilmer L.L.P.",
        47: "Parker Poe Adams & Berstein LLP", 48: "Seward & Kissel LLP", 49: "Burns & Levinson LLP",
        50: "Smith, Anderson, Blount, Dorsett, Mitchell & Jernigan, L.L.P", 51: "McDonough, Holland & Allen PC",
        52: "Zelle, Hofmann, Voelbel & Mason LLP", 53: "Litchfield Cavo LLP", 54: "Margolin, Winer & Evens LLP",
        55: "Gallaudet University", 56: "Quarles & Brady LLP", 57: "McNees Wallace & Nurick LLC", 58: "Bingham McCutchen LLP",
        59: "McGlinchey Stafford PLLC", 60: "Carlton Fields Jorden Burt", 62: "Davis Polk & Wardwell LLP",
        63: "Faegre & Benson LLP", 64: "Morrison & Foerster LLP", 65: "Montgomery, McCracken, Walker & Rhoads, LLP",
        66: "Holland & Knight LLP", 67: "Rawle & Henderson LLP", 68: "Winthrop & Weinstine, P.A.",
        69: "Lindabury, McCormick, Estabrook & Cooper, P.C.", 70: "Blake, Cassels & Graydon LLP",
        71: "Cassels Brock & Blackwell LLP", 72: "Fasken Martineau DuMoulin LLP", 73: "Fraser Milner Casgrain LLP",
        74: "Goodmans LLP", 75: "Gowling Lafleur Henderson LLP", 76: "Heenan Blaikie LLP", 77: "McMillan LLP",
        78: "McCarthy Tétrault LLP", 79: "Norton Rose Fulbright Canada LLP", 80: "Torys LLP", 81: "Osler, Hoskin & Harcourt LLP",
        82: "Stikeman Elliott LLP", 83: "O'Melveny & Myers LLP", 84: "Hirschler Fleischer", 85: "Lewis, Rice & Fingersh, L.C.",
        87: "Stikeman Elliott LLP (WAVG)", 88: "Anderson Kill & Olick, PC", 89: "Calfee, Halter & Griswold LLP",
        90: "Torys LLP (NY)", 91: "Miller Thomson LLP", 92: "Allen & Overy LLP", 93: "Osler, Hoskin & Harcourt LLP (New York)",
        94: "K&L Gates LLP", 95: "Jenner & Block LLP", 96: "Genesis HealthCare Corporation 1-200", 97: "Health Plus",
        98: "Li & Fung USA", 99: "Fisher & Phillips LLP", 100: "Irving Place Capital", 101: "Jennings, Strouss & Salmon, P.L.C.",
        102: "Wilkinson Barker Knauer, LLP", 103: "Day Pitney LLP", 104: "Wegmans Food Markets", 105: "Kobre & Kim LLP",
        106: "Global Brands Group", 107: "Baker Botts L.L.P.", 108: "Holy Redeemer Health System", 109: "Swiss Re Management (US) Corporation",
        110: "Geller & Company", 111: "Miller, Canfield, Paddock & Stone", 112: "Borden Ladner Gervais", 113: "Tulane University",
        115: "MRC Global", 116: "Reyes Holdings", 118: "Hawkins Parnell & Young LLP", 119: "McIness Cooper", 121: "Stewart McKelvey",
        122: "Graydon Head & Ritchey LLP", 123: "ZZZZ", 124: "The Kenan Advantage Group - Staples", 125: "Mayer Brown LLP",
        126: "U.S. Security Associates, Inc.", 127: "The Hershey Company", 128: "Norris McLaughlin & Marcus, P.A.",
        129: "Genesis HealthCare Corporation 201-400", 130: "Genesis HealthCare Corporation 401-600", 131: "Constangy, Brooks, Smith & Prophete, LLP",
        132: "McAfee Taft LLP", 133: "PSS Companies", 134: "Harris Beach PLLC", 135: "Montefiore Health Systems",
        136: "GCA Services Group", 137: "Morris, Nichols, Arsht & Tunnell LLP", 138: "Kelley Drye & Warren LLP",
        139: "Neopost USA", 140: "Chiesa Shahinian & Giantomasi PC", 141: "TZP Group", 142: "Manning Gross + Massenburg LLP (MG+M The Law Firm)",
        143: "Beveridge & Diamond, PC", 148: "Young Conaway Stargatt & Taylor, LLP", 149: "Buckley LLP", 150: "The Kenan Advantage Group-Office Depot",
        151: "Mount Sinai Health Systems", 153: "Zelle LLP", 154: "Sterling", 155: "Strategic Financial Solutions",
        156: "Capital Vision", 157: "The Carpenter Health Network", 158: "Mt Sinai Health Systems Toner School",
        159: "Mt Sinai Health Systems Reports", 160: "Commonwealth Care Alliance", 161: "Cleary Gottlieb Steen & Hamilton LLP",
        162: "Kaufman Borgeest Ryan LLP - FedEx Pricing Audit", 163: "Simpson Thacher & Bartlett LLP", 164: "Winget, Spadafora & Schwartzberg, LLP",
        165: "Advanced Recovery Systems, LLC", 166: "Diversified", 167: "Monotype", 168: "Skadden, Arps, Slate, Meagher & Flom LLP",
        169: "HERRICK FEINSTEIN LLP", 170: "Armstrong Flooring", 171: "Berger & Montague P.C.", 172: "Robinson Bradshaw & Hinson PA",
        173: "Archer & Greiner, P.C.", 174: "McCarter & English", 175: "Hospital for Special Care", 176: "Ballard Spahr",
        177: "Ballard Spahr", 178: "Shumaker, Loop & Kendrick", 179: "Dorsey & Whitney", 180: "Munger, Tolles & Olson",
        181: "Paul Hastings", 182: "Nelson Mullins Riley & Scarborough", 183: "Davis Wright Tremaine", 184: "Stoel Rives",
        185: "Blank Rome", 186: "Invesco ltd", 187: "Promedica", 188: "Davis Polk", 191: "Monarch Healthcare",
        192: "Genesis HealthCare", 193: "Big Lift LLC", 194: "Invesco", 195: "IB Goodman", 196: "Sentrilock, LLC",
        197: "United Courier", 198: "Reliant Healthcare", 199: "Keller & Heckman", 200: "Chapman and Cutler LLP",
        201: "Schulte Roth & Zabel LLP", 202: "Maplewood Senior Living", 203: "Food to Live", 204: "Enexia Specialty Pharmacy",
        205: "GLDN", 206: "Precision Compounding Pharmacy and Wellness", 207: "GHC", 208: "Demo Client", 209: "MBK Senior Living",
        210: "Calavo", 211: "Huntons Andrew Kurth", 212: "Adler Pollock & Sheehan PC", 213: "Moses & Singer LLP",
        214: "SavaSeniorCare, LLC", 215: "Bond, Schoeneck & King", 216: "American Broadcasting Company (ABC)", 217: "Brownstein Hyatt Farber Schreck",
        218: "Carter Ledyard & Milburn", 219: "Condon & Forsyth LLP", 220: "Cravath, Swaine & Moore", 221: "Finn Dixon & Herling",
        222: "Foley & Lardner", 223: "Katten Muchin Rosenman", 224: "Kirkland & Ellis", 225: "Manatt, Phelps & Phillips",
        226: "Milbank", 227: "Pace LLP", 228: "Proskauer Rose LLP", 229: "Zuckerman Spaeder", 230: "Greenberg Traurig",
        231: "Care Initiatives", 232: "Stamford JCC", 233: "Natures Sunshine", 234: "Legacy Senior Living",
        235: "Healthcare Services Group", 236: "Willkie Farr & Gallagher LLP", 237: "Freshfields", 238: "Shalby Advanced Technologies",
        239: "Elara Caring", 240: "Ogletree Deakins", 241: "Ogletree Deakins benchm", 242: "C Spire", 243: "Consensus Health",
        244: "ENT and Allergy Associates", 245: "Anderson Automotive Group", 246: "Bricker Graydon LLP", 247: "Pulmonary Exchange",
        248: "Bria", 249: "Internal Portal", 250: "Frost Brown Todd LLP", 251: "Imagination Technologies", 252: "DocGo",
        253: "Prospect Demo", 254: "Transitions Healthcare LLC", 255: "Crash Champions", 256: "HWG LLP", 257: "PL Development",
        258: "Super Natural Distributors", 259: "Steptoe", 260: "Windy City", 261: "House of Cheatham", 262: "CareAbout Health",
        263: "Sullivan & Cromwell", 265: "Baker Botts", 266: "Morrison Cohen LLP",
        264: "Ankura Consulting Group", 268: "Small Demo", 269: "Akerman LLP"
    };

    // Contracts Table
    if (sources.includes('contract')) {
        if (results.contracts && results.contracts.length > 0) {
            response += `<div style="margin: 20px 0;">`;
            response += `<h4 style="color: #374151; margin-bottom: 15px;">Contracts (${results.contracts.length} found)</h4>`;
            response += `<div style="overflow-x: auto; border: 1px solid #e5e7eb; border-radius: 8px;">`;
            response += `<table style="width: 100%; border-collapse: collapse; font-size: 0.9em;">`;
            response += `<thead style="background: #f8fafc;"><tr>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Client</th>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Contract Name</th>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Vendor</th>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Product/Service</th>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Period</th>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Spend</th>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Actions</th>`;
            response += `</tr></thead><tbody>`;

            results.contracts.forEach((contract, index) => {
                // First map client ID to client name, then map client name to attorney info (same as search vendor tab)
                const clnumKey = parseInt(contract.clnum);
                const clientName = clientMapping[clnumKey] || `Client ${contract.clnum}`;
                const attorneyDisplay = getAttorneyDisplay(clientName);
                const spendDisplay = contract.spend
                    ? (contract.currency ? contract.currency + formatNumber(contract.spend) : '$' + formatNumber(contract.spend))
                    : '$0.00';
                
                const bgColor = index % 2 === 0 ? '#ffffff' : '#f9fafb';
                let fileUrl = contract.file;
                if (fileUrl && fileUrl.includes('ccm-contracts.s3.amazonaws.com')) {
                    fileUrl = fileUrl.replace('ccm-contracts.s3.amazonaws.com', 'ccm-contracts.s3.us-east-1.amazonaws.com');
                }

                response += `<tr style="background: ${bgColor};">`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6;"><strong>${attorneyDisplay}</strong></td>`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6;">${contract.contract_name || 'N/A'}</td>`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6;">${contract.vendor_name || 'N/A'}</td>`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6;">${contract.product || 'N/A'}</td>`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6; font-size: 0.8em;">`;
                response += `<strong>Start:</strong> ${formatDateFromNumber(contract.start_date)}<br>`;
                response += `<strong>End:</strong> ${formatDateFromNumber(contract.end_date)}</td>`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6; font-weight: 600;">${spendDisplay}</td>`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6;">`;
                
                if (fileUrl) {
                    response += `<button onclick="previewFileFromChat('${fileUrl}')" style="background: #1e3a8a; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 0.75em; margin: 1px; display: block; width: 100%;">Preview</button>`;
                    response += `<button onclick="downloadFileFromChat('${fileUrl}', '${contract.contract_name || 'contract'}')" style="background: #3b82f6; color: white; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 0.75em; margin: 1px; display: block; width: 100%;">Download</button>`;
                    response += `<button onclick="compareContractFromChat('${fileUrl}', '${contract.contract_name || 'contract'}')" style="background: #fbbf24; color: #1f2937; border: none; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 0.75em; margin: 1px; display: block; width: 100%;">Compare</button>`;
                } else {
                    response += `<span style="color: #6b7280; font-size: 0.8em;">No file</span>`;
                }
                
                response += `</td></tr>`;
            });

            response += `</tbody></table></div></div>\n\n`;
        } else {
            response += `**Contracts:** No contracts found\n\n`;
        }
    }

    // GL Records Table
    if (sources.includes('gl')) {
        if (results.glRecords && results.glRecords.length > 0) {
            response += `<div style="margin: 20px 0;">`;
            response += `<h4 style="color: #374151; margin-bottom: 15px;">GL Records (${results.glRecords.length} found)</h4>`;
            response += `<div style="overflow-x: auto; border: 1px solid #e5e7eb; border-radius: 8px;">`;
            response += `<table style="width: 100%; border-collapse: collapse; font-size: 0.9em;">`;
            response += `<thead style="background: #f8fafc;"><tr>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Client</th>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Vendor</th>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Total Amount</th>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Parent Company</th>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Year</th>`;
            response += `</tr></thead><tbody>`;

            results.glRecords.forEach((gl, index) => {
                const bgColor = index % 2 === 0 ? '#ffffff' : '#f9fafb';
                const formattedAmount = gl.amount ? formatNumber(Math.abs(gl.amount)) : '0.00';
                // Use client_name from database directly and map to attorney info for GL table
                const rawClientName = gl.client_name || gl.clname || `Client ${gl.clnum || 'Unknown'}`;
                const attorneyDisplay = getAttorneyDisplay(rawClientName);
                response += `<tr style="background: ${bgColor};">`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6;"><strong>${attorneyDisplay}</strong></td>`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6;"><strong>${gl.assigned_vendor_name || 'N/A'}</strong></td>`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6; font-weight: 600; color: ${gl.amount >= 0 ? '#059669' : '#dc2626'};">$${formattedAmount}</td>`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6;">${gl.parent_company || 'N/A'}</td>`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6;">${gl.year || 'N/A'}</td>`;
                response += `</tr>`;
            });

            response += `</tbody></table></div></div>\n\n`;
        } else {
            response += `**GL Records:** No GL records found\n\n`;
        }
    }

    // Jira Tickets Table
    if (sources.includes('jira')) {
        if (results.jiraTickets && results.jiraTickets.length > 0) {
            response += `<div style="margin: 20px 0;">`;
            response += `<h4 style="color: #374151; margin-bottom: 15px;">Jira Tickets (${results.jiraTickets.length} found)</h4>`;
            response += `<div style="overflow-x: auto; border: 1px solid #e5e7eb; border-radius: 8px;">`;
            response += `<table style="width: 100%; border-collapse: collapse; font-size: 0.9em;">`;
            response += `<thead style="background: #f8fafc;"><tr>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">ID</th>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Summary</th>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Status</th>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Priority</th>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Assignee</th>`;
            response += `<th style="padding: 12px 8px; text-align: left; border-bottom: 2px solid #e5e7eb; font-weight: 600;">Updated</th>`;
            response += `</tr></thead><tbody>`;

            results.jiraTickets.forEach((ticket, index) => {
                const bgColor = index % 2 === 0 ? '#ffffff' : '#f9fafb';
                response += `<tr style="background: ${bgColor};">`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6;"><a href="https://ccmchase.atlassian.net/browse/${ticket.key}" target="_blank" style="color: #3b82f6; text-decoration: none;">${ticket.key}</a></td>`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6;">${ticket.summary}</td>`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6;"><span style="background: #e5e7eb; color: #374151; padding: 2px 6px; border-radius: 12px; font-size: 0.8em;">${ticket.status}</span></td>`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6;"><span style="background: #fef3c7; color: #92400e; padding: 2px 6px; border-radius: 12px; font-size: 0.8em;">${ticket.priority || 'Normal'}</span></td>`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6;">${ticket.assignee || 'Unassigned'}</td>`;
                response += `<td style="padding: 10px 8px; border-bottom: 1px solid #f3f4f6;">${ticket.updated}</td>`;
                response += `</tr>`;
            });

            response += `</tbody></table></div></div>\n\n`;
        } else {
            response += `**Jira Tickets:** No tickets found\n\n`;
        }
    }
    
    return response;
}

// Helper functions for formatting
function formatNumber(num) {
    if (!num) return '0.00';
    return parseFloat(num).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function formatDateString(dateStr) {
    if (!dateStr) return 'N/A';
    try {
        const date = new Date(dateStr);
        return date.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    } catch (e) {
        return dateStr;
    }
}

function formatDateFromNumber(dateNumber) {
    if (!dateNumber) return 'N/A';
    const dateStr = dateNumber.toString();
    if (dateStr.length === 8) {
        const year = dateStr.substring(0, 4);
        const month = dateStr.substring(4, 6);
        const day = dateStr.substring(6, 8);
        return `${year}-${month}-${day}`;
    }
    return dateNumber;
}

// Contract analysis endpoint for chatbot (simplified version)
app.post('/api/analyze-contract-chatbot', async (req, res) => {
    try {
        const { contractUrl, contractName } = req.body;

        if (!contractUrl) {
            return res.status(400).json({ error: 'Contract URL is required' });
        }

        console.log('🔍 Chatbot contract analysis request:', { contractUrl, contractName });

        // Download and extract text from the contract using AWS SDK
        let contractText = '';
        try {
            console.log('📥 Downloading contract from S3...');
            
            // AWS credentials should be configured (since it works in search vendor tab)

            // Extract bucket and key from S3 URL
            console.log('🔍 Processing contract URL:', contractUrl);
            const urlParts = contractUrl.match(/https:\/\/([^.]+)\.s3\.([^.]+\.)?amazonaws\.com\/(.+)/);
            if (!urlParts) {
                console.error('❌ Invalid S3 URL format:', contractUrl);
                return res.status(400).json({ error: 'Invalid S3 URL format' });
            }
            
            const bucketName = urlParts[1];
            let objectKey = urlParts[3];
            console.log('🗂️ Extracted bucket:', bucketName, 'key:', objectKey);
            
            // Try different encodings for the object key
            const keyVariations = [
                decodeURIComponent(objectKey),
                objectKey,
                objectKey.replace(/\+/g, ' '),
                objectKey.replace(/ /g, '+')
            ];

            let s3Object = null;
            let workingKey = null;

            // Try each key variation
            for (const key of keyVariations) {
                try {
                    console.log(`🔍 Trying S3 key: "${key}"`);
                    const params = { Bucket: bucketName, Key: key };
                    s3Object = await s3.getObject(params).promise();
                    workingKey = key;
                    console.log(`✅ Found contract file with key: ${key}`);
                    break;
                } catch (keyError) {
                    console.log(`❌ Failed with key "${key}":`, keyError.message);
                    continue;
                }
            }

            if (!s3Object) {
                return res.status(404).json({ error: 'Contract file not found in S3' });
            }
            
            const buffer = s3Object.Body;
            console.log(`📄 File downloaded, size: ${buffer.length} bytes`);
            
            // Extract text based on file type
            const fileExtension = contractUrl.split('.').pop().toLowerCase();
            console.log(`🔍 Processing file type: ${fileExtension}`);
            
            if (fileExtension === 'pdf') {
                console.log('📖 Extracting text from PDF...');
                const pdfData = await pdf(buffer);
                contractText = pdfData.text;
                console.log(`📝 Extracted ${contractText.length} characters from PDF`);
            } else if (fileExtension === 'docx') {
                console.log('📖 Extracting text from DOCX...');
                const docData = await mammoth.extractRawText({ buffer: buffer });
                contractText = docData.value;
                console.log(`📝 Extracted ${contractText.length} characters from DOCX`);
            } else if (fileExtension === 'txt') {
                console.log('📖 Processing TXT file...');
                contractText = buffer.toString('utf-8');
                console.log(`📝 Extracted ${contractText.length} characters from TXT`);
            } else {
                console.error(`❌ Unsupported file format: ${fileExtension}`);
                return res.status(400).json({ error: `Unsupported file format: ${fileExtension}` });
            }
            
        } catch (s3Error) {
            console.error('❌ Failed to download contract from S3:', s3Error);
            return res.status(500).json({ error: 'Failed to download contract file. Please check the file URL.' });
        }

        if (!contractText || contractText.trim().length < 50) {
            return res.status(400).json({ error: 'Contract file appears to be empty or unreadable' });
        }

        // Generate AI analysis (same as main tab)
        let analysis = '';
        try {
            const prompt = `You are a legal contract analysis expert. Provide detailed, professional analysis of contracts in JSON format when requested, or formatted text otherwise.

Analyze this contract and provide a comprehensive legal review in JSON format with the following structure:

{
  "contract_type": "Description of contract type",
  "vendor_name": "Name of the vendor/service provider",
  "estimated_value": "Total contract value",
  "currency": "Currency code",
  "risk_level": "high/medium/low",
  "key_terms": ["List of key contract terms"],
  "yoy_increases": {
    "found": true/false,
    "percentage": "Annual increase percentage if found",
    "industry_standard": "Industry standard information",
    "recommendation": "Recommendation regarding increases"
  },
  "incomplete_pricing_sections": ["Sections with unclear pricing"],
  "missing_clauses": ["Important missing clauses"],
  "recommendations": ["Actionable recommendations"],
  "payment_terms": "Payment terms description",
  "governing_law": "Governing law if specified",
  "termination_conditions": "Termination conditions",
  "renewal_terms": "Renewal terms",
  "requires_legal_review": true/false,
  "compliance_issues": ["Compliance concerns"],
  "risk_factors": ["Key risk factors"],
  "pricing_issues": ["Pricing-related concerns"]
}

After the JSON, provide a detailed analysis covering:
1. Contract Overview & Classification
2. Key Terms Extraction
3. Pricing & Service Analysis
4. Risk Analysis
5. Compliance & Standards Assessment
6. Actionable Recommendations

Contract text: ${contractText}`;

            const response = await openai.chat.completions.create({
                model: 'gpt-4',
                messages: [
                    {
                        role: 'system',
                        content: 'You are a legal contract analysis expert. Provide detailed, professional analysis of contracts in JSON format when requested, or formatted text otherwise.'
                    },
                    {
                        role: 'user',
                        content: prompt
                    }
                ],
                max_tokens: 4000,
                temperature: 0.3
            });

            analysis = response.choices[0].message.content;
            console.log('✅ AI analysis completed');
        } catch (aiError) {
            console.warn('⚠️ AI analysis failed, falling back to basic summary:', aiError.message);
            // Fallback to basic analysis
            analysis = generateBasicContractSummary(contractText, contractName);
        }

        // Find similar contracts based on vendor name (enhanced matching)
        let similarContracts = [];
        if (dbPool) {
            try {
                // Extract vendor name from AI analysis (if available) and from contract text
                const jsonMatch = analysis.match(/```json\n([\s\S]*?)\n```/);
                let aiVendorName = null;
                
                if (jsonMatch) {
                    try {
                        const contractSummary = JSON.parse(jsonMatch[1]);
                        aiVendorName = contractSummary.vendor_name;
                    } catch (parseError) {
                        console.warn('Could not parse JSON summary from analysis');
                    }
                }
                
                // Also try text extraction as fallback
                const textVendorName = extractVendorNameFromText(contractText);
                
                // Create vendor variations for better matching
                const vendorVariations = [];
                
                if (aiVendorName) {
                    vendorVariations.push(
                        aiVendorName, // Original AI extracted name
                        aiVendorName.replace(/, dba .+$/, ''), // Remove "dba" part
                        aiVendorName.match(/dba (.+)$/)?.[1] || '', // Extract "dba" name only
                        aiVendorName.replace(/\s+(Inc\.|LLC|L\.L\.C\.|Corporation|Corp\.|Ltd\.|Limited)\b.*$/i, ''), // Remove legal entities
                        aiVendorName.split(/[,\s]+/)[0] // First word/part
                    );
                }
                
                if (textVendorName) {
                    vendorVariations.push(textVendorName);
                }
                
                // Filter out empty and very short names
                const validVariations = [...new Set(vendorVariations)].filter(v => v && v.length > 2);
                
                if (validVariations.length > 0) {
                    console.log(`🔍 Searching for contracts with vendor variations:`, validVariations);
                    
                    // Search database for contracts with matching vendor name using multiple patterns
                    const vendorSearchQuery = `
                        SELECT id, clnum, contract_id, contract_name, vendor_name, filename, 
                               contract_type, start_date, end_date, spend, currency, product, file
                        FROM ccm_sync_table 
                        WHERE vendor_name IS NOT NULL 
                        AND (${validVariations.map(() => 'LOWER(vendor_name) LIKE LOWER(?)').join(' OR ')})
                        AND file IS NOT NULL 
                        AND file != ''
                        ORDER BY uploaded_date DESC
                        LIMIT 20
                    `;
                    
                    const searchParams = validVariations.map(v => `%${v}%`);
                    const [vendorContracts] = await dbPool.execute(vendorSearchQuery, searchParams);
                    
                    // Map the contracts with proper client display (same as search contract)
                    similarContracts = vendorContracts.map(contract => {
                        const clnumKey = parseInt(contract.clnum);
                        const clientName = clientMapping[clnumKey] || `Client ${contract.clnum}`;
                        
                        console.log('🔍 Server mapping for contract:', {
                            originalClnum: contract.clnum,
                            parsedClnumKey: clnumKey,
                            mappedClientName: clientName
                        });
                        
                        // Use the same attorney mapping as search contract
                        const attorneyMapping = {
                            "Baker Botts L.L.P.": "Total Attorney: 700",
                            "Simpson Thacher & Bartlett LLP": "Total Attorney: 1200",
                            "Paul Weiss": "Total Attorney: 1000",
                            "Schulte Roth & Zabel LLP": "Total Attorney: 300",
                            "Chapman and Cutler LLP": "Total Attorney: 200",
                            "Jones Vargas": "Total Attorney: 50",
                            "Miller & Chevalier": "Total Attorney: 350",
                            "Baker, Donelson, Bearman, Caldwell & Berkowitz PC": "Total Attorney: 650",
                            "Robins Kaplan LLP": "Total Attorney: 300",
                            "Ropes & Gray LLP": "Total Attorney: 1400",
                            "Royston, Rayzor, Vickery & Williams, L.L.P.": "Total Attorney: 45",
                            "Vinson & Elkins L.L.P.": "Total Attorney: 700",
                            "Wilson Sonsini Goodrich & Rosati": "Total Attorney: 900",
                            "Stinson Leonard Street": "Total Attorney: 380",
                            "Keker & Van Nest L.L.P.": "Total Attorney: 120",
                            "Chamberlain, Hrdlicka, White, Williams & Martin": "Total Attorney: 180",
                            "Meagher & Geer, P.L.L.P.": "Total Attorney: 100",
                            "Farella Braun & Martel LLP": "Total Attorney: 150",
                            "Bingham McHale LLP": "Total Attorney: 40",
                            "Wolf Haldenstein Adler Freeman & Herz LLP": "Total Attorney: 85",
                            "Alston & Bird LLP": "Total Attorney: 800",
                            "Ruden McClosky": "Total Attorney: 200",
                            "Dykema Gossett PLLC": "Total Attorney: 400",
                            "Miller & Martin PLLC": "Total Attorney: 200",
                            "Hogan Lovells US LLP": "Total Attorney: 2500",
                            "Cranfill, Sumner, & Hartzog, L.L.P.": "Total Attorney: 150",
                            "Poyner & Spruill LLP": "Total Attorney: 200",
                            "Warner Norcross & Judd": "Total Attorney: 150",
                            "Olshan Frome Wolosky LLP": "Total Attorney: 120",
                            "Cadwalader, Wickersham & Taft LLP": "Total Attorney: 400",
                            "Baker & Hostetler LLP": "Total Attorney: 900",
                            "Brown Rudnick LLP": "Total Attorney: 250",
                            "Phillips Lytle LLP": "Total Attorney: 200",
                            "Andrews Kurth LLP": "Total Attorney: 600",
                            "Bricker Graydon LLP": "Total Attorney: 200",
                            "Steptoe": "Total Attorney: 400",
                            "Frost Brown Todd LLP": "Total Attorney: 600",
                            "Akerman LLP": "Total Attorney: 700",
                            "Ankura Consulting Group, LLC": "Total Revenue: $800M",
                            "Crash Champions": "Total Revenue: $5B"
                        };
                        
                        const attorneyDisplay = attorneyMapping.hasOwnProperty(clientName) ? attorneyMapping[clientName] : "Corp";
                        
                        console.log('🎯 Attorney mapping result:', {
                            clientName: clientName,
                            hasMapping: attorneyMapping.hasOwnProperty(clientName),
                            attorneyDisplay: attorneyDisplay
                        });
                        
                        let fixedFileUrl = contract.file;
                        if (fixedFileUrl && fixedFileUrl.includes('ccm-contracts.s3.amazonaws.com')) {
                            fixedFileUrl = fixedFileUrl.replace('ccm-contracts.s3.amazonaws.com', 'ccm-contracts.s3.us-east-1.amazonaws.com');
                        }
                        
                        return {
                            ...contract,
                            clientName: clientName,
                            attorneyDisplay: attorneyDisplay,
                            file: fixedFileUrl
                        };
                    });
                    
                    console.log(`📋 Found ${similarContracts.length} contracts with similar vendor from database`);
                } else {
                    console.log('📋 No vendor name extracted, skipping similar contracts search');
                }
            } catch (error) {
                console.warn('Error finding similar contracts:', error.message);
            }
        }

        res.json({
            success: true,
            analysis: analysis,
            contractName: contractName || 'Contract',
            contractUrl: contractUrl,
            similarContracts: similarContracts // Add similar contracts to response
        });

    } catch (error) {
        console.error('❌ Contract analysis error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message || 'Analysis failed' 
        });
    }
});

// Helper function to extract vendor name from contract text
function extractVendorNameFromText(contractText) {
    try {
        const text = contractText.toLowerCase();
        const lines = contractText.split('\n');
        
        // Look for common vendor patterns in the first 50 lines
        const searchLines = lines.slice(0, 50).join('\n').toLowerCase();
        
        // Pattern 1: "This agreement is between [Company] and [Vendor]"
        let vendorMatch = searchLines.match(/agreement.*between.*and\s+([^,.\n]+?)(?:\s*\(|,|\.|\n)/);
        if (vendorMatch) {
            const vendor = vendorMatch[1].trim();
            if (vendor.length > 2 && vendor.length < 100) {
                return vendor;
            }
        }
        
        // Pattern 2: Look for company patterns like "Inc.", "LLC", "Corp", etc.
        const companyPatterns = [
            /(\w+.*?(?:inc|llc|corp|corporation|ltd|limited|company|co\.))/gi,
            /(\w+.*?(?:technologies|systems|solutions|services|group))/gi
        ];
        
        for (const pattern of companyPatterns) {
            const matches = searchLines.match(pattern);
            if (matches && matches.length > 0) {
                // Get the most likely vendor (shortest reasonable match)
                const candidates = matches
                    .map(match => match.trim())
                    .filter(match => match.length > 5 && match.length < 50)
                    .filter(match => !match.toLowerCase().includes('client'))
                    .sort((a, b) => a.length - b.length);
                
                if (candidates.length > 0) {
                    return candidates[0];
                }
            }
        }
        
        // Pattern 3: Look for "Vendor:" or "Company:" labels
        const labelMatch = searchLines.match(/(?:vendor|company|contractor):\s*([^\n,]+)/i);
        if (labelMatch) {
            const vendor = labelMatch[1].trim();
            if (vendor.length > 2 && vendor.length < 100) {
                return vendor;
            }
        }
        
        return null;
    } catch (error) {
        console.warn('Error extracting vendor name:', error.message);
        return null;
    }
}

// Helper function for basic contract summary
function generateBasicContractSummary(contractText, contractName) {
    const text = contractText.toLowerCase();
    const words = contractText.split(/\s+/).length;
    const lines = contractText.split('\n').filter(line => line.trim().length > 0);
    
    let summary = `**Contract Analysis: ${contractName}**\n\n`;
    
    summary += `**Document Information:**\n`;
    summary += `- Word Count: ${words.toLocaleString()} words\n`;
    summary += `- Length: ${Math.round(contractText.length / 1000)}K characters\n`;
    
    // Detect contract type
    let contractType = 'General Commercial Agreement';
    if (text.includes('service agreement') || text.includes('consulting')) {
        contractType = 'Service Agreement';
    } else if (text.includes('employment') || text.includes('employee')) {
        contractType = 'Employment Contract';
    } else if (text.includes('license') || text.includes('software')) {
        contractType = 'License Agreement';
    } else if (text.includes('purchase') || text.includes('sale')) {
        contractType = 'Purchase/Sale Agreement';
    } else if (text.includes('lease') || text.includes('rental')) {
        contractType = 'Lease/Rental Agreement';
    }
    summary += `- Contract Type: ${contractType}\n\n`;
    
    summary += `**Key Information Found:**\n`;
    
    // Look for dates
    const dateRegex = /\d{1,2}\/\d{1,2}\/\d{4}|\d{4}-\d{2}-\d{2}|\b\d{1,2}\s+(january|february|march|april|may|june|july|august|september|october|november|december)\s+\d{4}/gi;
    const dates = contractText.match(dateRegex);
    if (dates && dates.length > 0) {
        summary += `- Important Dates: ${[...new Set(dates)].slice(0, 5).join(', ')}\n`;
    }
    
    // Look for monetary amounts
    const moneyRegex = /\$[\d,]+(?:\.\d{2})?/g;
    const amounts = contractText.match(moneyRegex);
    if (amounts && amounts.length > 0) {
        const uniqueAmounts = [...new Set(amounts)].slice(0, 5);
        summary += `- Monetary Values: ${uniqueAmounts.join(', ')}\n`;
    }
    
    // Look for email addresses
    const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g;
    const emails = contractText.match(emailRegex);
    if (emails && emails.length > 0) {
        summary += `- Contact Emails: ${[...new Set(emails)].slice(0, 3).join(', ')}\n`;
    }
    
    summary += `\n**Key Terms Present:**\n`;
    const terms = [];
    if (text.includes('payment') || text.includes('invoice')) terms.push('Payment provisions');
    if (text.includes('termination') || text.includes('terminate')) terms.push('Termination clauses');
    if (text.includes('liability') || text.includes('liable')) terms.push('Liability terms');
    if (text.includes('confidential') || text.includes('nda')) terms.push('Confidentiality');
    if (text.includes('intellectual property') || text.includes('copyright')) terms.push('Intellectual property');
    if (text.includes('indemnif')) terms.push('Indemnification');
    if (text.includes('dispute') || text.includes('arbitration')) terms.push('Dispute resolution');
    if (text.includes('governing law') || text.includes('jurisdiction')) terms.push('Governing law');
    
    if (terms.length > 0) {
        terms.forEach(term => {
            summary += `- ${term}\n`;
        });
    } else {
        summary += `- Standard commercial terms detected\n`;
    }
    
    summary += `\n**Quick Review Notes:**\n`;
    summary += `- This is an automated text analysis\n`;
    summary += `- For legal advice, consult with qualified counsel\n`;
    summary += `- Please verify all critical terms and dates\n`;
    summary += `- Consider having the contract professionally reviewed\n`;
    
    return summary;
}

// Search contract endpoint for chatbot
app.post('/api/search-contract', async (req, res) => {
    try {
        const { searchTerms } = req.body;
        
        if (!dbPool) {
            return res.status(400).json({ 
                success: false, 
                error: 'Database not connected' 
            });
        }
        
        console.log('🔍 Contract search request:', { searchTerms });
        
        if (!searchTerms || !searchTerms.trim()) {
            return res.status(400).json({ 
                success: false, 
                error: 'Search terms are required' 
            });
        }
        
        const searchQuery = searchTerms.trim();
        const searchTokens = searchQuery.split(' ').filter(token => token.length > 0);
        
        try {
            // Search contracts with multiple criteria
            let contractQuery = `
                SELECT id, clnum, contract_id, contract_name, vendor_name, filename, 
                       contract_type, start_date, end_date, spend, currency, product,
                       uploaded_date
                FROM ccm_sync_table 
                WHERE 1=1
            `;
            let params = [];
            let conditions = [];
            
            // Add search conditions for contract name, type, vendor, and product
            if (searchTokens.length > 0) {
                const searchConditions = [];
                searchTokens.forEach(token => {
                    searchConditions.push(
                        '(LOWER(contract_name) LIKE LOWER(?) OR ' +
                        'LOWER(contract_type) LIKE LOWER(?) OR ' +
                        'LOWER(vendor_name) LIKE LOWER(?) OR ' +
                        'LOWER(product) LIKE LOWER(?))'
                    );
                    params.push(`%${token}%`, `%${token}%`, `%${token}%`, `%${token}%`);
                });
                conditions.push('(' + searchConditions.join(' OR ') + ')');
            }
            
            if (conditions.length > 0) {
                contractQuery += ' AND ' + conditions.join(' AND ');
            }
            
            contractQuery += ' ORDER BY uploaded_date DESC LIMIT 50';
            
            const [contractRows] = await dbPool.execute(contractQuery, params);
            
            // Format response for chatbot
            let responseText = formatContractSearchResults(contractRows, searchQuery);
            
            res.json({
                success: true,
                response: responseText,
                data: contractRows
            });
            
        } catch (error) {
            console.error('❌ Contract search query error:', error);
            res.status(500).json({ 
                success: false, 
                error: 'Database search failed' 
            });
        }
        
    } catch (error) {
        console.error('❌ Contract search error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// Helper function to format contract search results for chatbot display
function formatContractSearchResults(contracts, searchQuery) {
    let response = `**Contract Search Results for: "${searchQuery}"**\n\n`;
    
    if (contracts.length === 0) {
        response += 'No contracts found matching your search criteria.';
        return response;
    }
    
    response += `**Found ${contracts.length} contract(s):**\n\n`;
    
    contracts.forEach((contract, index) => {
        response += `${index + 1}. **${contract.contract_name || 'Unnamed Contract'}**\n`;
        response += `   - Vendor: ${contract.vendor_name || 'N/A'}\n`;
        response += `   - Type: ${contract.contract_type || 'N/A'}\n`;
        response += `   - Value: ${contract.spend || 'N/A'} ${contract.currency || ''}\n`;
        response += `   - Period: ${contract.start_date || 'N/A'} to ${contract.end_date || 'N/A'}\n`;
        response += `   - Product: ${contract.product || 'N/A'}\n`;
        if (contract.filename) {
            response += `   - File: ${contract.filename}\n`;
        }
        response += `   - Uploaded: ${contract.uploaded_date || 'N/A'}\n\n`;
    });
    
    return response;
}

app.post('/api/google-search', async (req, res) => {
    try {
        const { query } = req.body;
        // 使用 Google Custom Search API 或其他搜索服务
        // 需要配置 Google API key 和 Search Engine ID
        
        res.json({
            success: true,
            results: [] // 搜索结果
        });
    } catch (error) {
        res.status(500).json({ error: 'Search failed' });
    }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


app.use(express.static(path.join(__dirname, 'public'), {
    index: 'login.html'
  }));
  

app.use((req, res) => {
    console.log('❌ 404 for path:', req.path);
    res.status(404).json({ 
        error: 'Route not found',
        path: req.path,
        method: req.method,
        timestamp: new Date().toISOString(),
        availableRoutes: ['/health', '/test', '/debug', '/api/debug/session', '/api/debug/auth', '/login.html', '/']
    });
});

// 错误处理中间件
app.use((error, req, res, next) => {
    console.error('❌ Server error:', error);
    res.status(500).json({ 
        error: 'Internal server error',
        message: error.message,
        timestamp: new Date().toISOString()
    });
});

// ========== 服务器启动 ==========

const PORT = process.env.PORT || 8080;
const HOST = '0.0.0.0';

// Database deadlock retry mechanism
async function executeWithRetry(operation, maxRetries = 3, delay = 100) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            return await operation();
        } catch (error) {
            if (error.code === 'ER_LOCK_DEADLOCK' && attempt < maxRetries) {
                console.log(`🔄 Deadlock detected, retrying... (attempt ${attempt}/${maxRetries})`);
                // Exponential backoff
                await new Promise(resolve => setTimeout(resolve, delay * Math.pow(2, attempt - 1)));
                continue;
            }
            throw error;
        }
    }
}

// Start the server
startServer();

// Error handlers
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});