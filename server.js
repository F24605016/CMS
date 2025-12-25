const mysql = require('mysql2/promise');
const express = require('express');
const cors = require('cors');
//------------------------------Hashing and Encryption Libraries------------------------------
const bcrypt = require('bcrypt'); //for password hashing
const crypto = require('crypto');   //for token generation
const moment = require('moment-timezone');
const CryptoJS = require('crypto-js'); //for data encryption/decryption. Useless in this code but may be used in future
const dotenv = require('dotenv');
const path = require("path");
const dns = require("dns");
//-------------------------HTTPS Certificates
const https = require("https"); //for HTTPS server


const fs = require("fs");
//------------------------------------------WHATS-APP
const qrcode = require("qrcode-terminal");
const { Client } = require("whatsapp-web.js");

//------------------------------------------OpenAI for chatbot
const OpenAI = require("openai");

require("dotenv").config();

//-------------------------certificates for HTTPS server
const httpsOptions = {
  key: fs.readFileSync(path.join(__dirname, "certs", "192.168.100.4+1-key.pem")),
  cert: fs.readFileSync(path.join(__dirname, "certs", "192.168.100.4+1.pem"))
};


const app = express();
const port = process.env.PORT;

app.use(cors());
app.use(express.json());


const SECRET_KEY = process.env.ENCRYPTION_SECRET; // Example key, replace with a strong key



// redirect .html URLs to extensionless (must come before static)
// Redirect /something.html -> /something, keeping query string
app.get(/^\/(.+)\.html$/, (req, res) => {
  const pageName = req.params[0];

  // Preserve query string if exists
  const query = req.originalUrl.split('?')[1];
  const redirectUrl = query ? `/${pageName}?${query}` : `/${pageName}`;

  res.redirect(301, redirectUrl);
});

// Serve public folder
app.use(express.static(path.join(__dirname, "public")));

// Default route
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Remove .html from URLs
app.get("/:page", (req, res, next) => {
  const page = req.params.page;
  res.sendFile(path.join(__dirname, "public", `${page}.html`), (err) => {
    if (err) next();
  });
});



const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'CMS',
  port: process.env.DB_PORT || 3306,
  connectionLimit: 10,
  acquireTimeout: 60000,
  timeout: 60000,
  charset: 'utf8mb4',
  timezone: '+00:00'
};

let pool;

async function initDb() {
  try {
    if (!pool) {
      pool = mysql.createPool(dbConfig);
      
      // Test connection
      const connection = await pool.getConnection();
      console.log("✅ Connected to MySQL Server (global pool)");
      connection.release();
    }
    return pool;
  } catch (err) {
    console.error("Database connection error:", err);
    throw err;
  }
}


// Health check endpoint
app.get('/health', async (req, res) => {
  try {
    const pool = await initDb();
    
    // Test the connection by executing a simple query
    const connection = await pool.getConnection();
    await connection.query('SELECT 1');
    connection.release();
    
    res.json({ 
      status: 'OK', 
      timestamp: new Date().toISOString(),
      database: 'Connected'
    });
  } catch (err) {
    res.status(500).json({ 
      status: 'ERROR',
      timestamp: new Date().toISOString(),
      database: 'Disconnected',
      error: err.message
    });
  }
});






// --------------------------OpenAI Chatbot Integration--------------------------

// OpenAI instance
const openai = new OpenAI({
  apiKey: "Add-OpenAI API key"
});

/**
 * Handles a user message and returns a reply according to MES CMS rules
 * @param {string} message
 * @returns {Promise<string>}
 */
async function generateCMSReply(message) {
  try {
    const instructions = `
Instructions
You are the assistant for a web-based Complaint Management System named MES CMS.
Respond strictly according to the rules and the system data.
Core Rules
1.	Answer only with information relevant to MES CMS.
2.	If the user asks anything outside the CMS, tell them to ask CMS-related questions only.
3.	Keep replies short.
4.	The user is a complete layman and does not know anything about development & coding stuff and he is a user not a developer also he is not allowed to change any setting in the browser.
5.	If unsure whether the question is CMS-related, assume it is.
6.	If the user ask something that is he cannot find:
  o	Use something like Contact the admin when the action normally requires admin access or if its an issue that requires coding then reply to contact the developers to resolve the issue.
  o	Otherwise give the simplest correct fix. Or tell them to contact the devs.
7.	Do not provide any code snippets, technical jargon, or development-related explanations.

System Data
Dashboard
•	All users must have dashboard access.
•	Without it, they get redirected to login.
Complaints
•	All Complaints: view complaints, edit status, change skillman, view details.
•	Launch Complaint: create a new complaint.
•	Delay Complaints: lists complaints delayed past expected time.
Nature
•	Manages complaint natures, categories, and types.
•	Users can add new natures (e.g., AC, Geyser, Electric, etc.).
•	Each nature allows selecting categories such as B&R-1, B&R-2, E&M-1, E&M-2.
•	Each nature also contains types, which are user-defined sub-problems
(e.g., For AC: fan issue, capacitor damage, etc.).
•	Do not invent categories or subdivisions beyond what’s provided.
Users
•	All Users: view all customers.
•	Colonies: view colony name, number, buildings; add/update colonies; search available.
•	Skillman: view all skillmen; update name, designation, subdivision, status.
Reporting
•	Daily Complaints: graphs and complaint stats.
•	Complaints Report: view/print; sector report allows filters for colony, building, category, nature, status, priority (deferred, immediate, urgent, routine), and date range; CSV export and print.
•	Sub-Division Report: choose subdivision + date range.
•	Summary Report: yearly summary with generate + print.
•	Skillman Report: overview of all skillmen; CSV export; individual skillman report button per record.
•	Rating Report: completed complaints with ratings and reviews.
Admin Page
•	Admin-only.
•	Add logins, manage permissions or different pages, remove access.
•	Anyone with access to this page is an admin.
Extra Info
• There is a problem with printing logic/code that we are working on and if asked about print is having issue then reply to contact the developers.
• Admins only gives or remove access of any user to any page(not a certain functionality) nothing else is under admins control.
Bonus
• If the user asks for a joke, tell a light-hearted, non-offensive joke related to complaint management or customer service.
• If the user asks for tips on using the CMS, provide 2-3 brief tips to enhance their experience.
• If the user seems frustrated, respond empathetically and offer assistance related to CMS features.
• If user ask questions about you or your capabilities then reply that you are an AI assistant designed to help with MES CMS related queries only and do not provide any extra information about yourself.
• If the user asks about security, privacy, or data protection, reassure them that MES CMS follows best practices to safeguard user information and maintain confidentiality.
• If user ask something that feels like a reference to one chat then reply something like i cannot remember past messages each response is independent of each other.
`;

    const completion = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        { role: "system", content: instructions },
        { role: "user", content: message }
      ]
    });

    return completion.choices?.[0]?.message?.content || "No reply available";
  } catch (err) {
    console.error("OpenAI error:", err);
    return "Error: Could not get response. Please try again.";
  }
}

// API endpoint
app.post("/chat", async (req, res) => {
  console.log("Chat request received");
  const { message } = req.body;
  if (!message) {
    return res.status(400).json({ error: "No message provided" });
  }

  const reply = await generateCMSReply(message);
  res.json({ reply });
});






// --- WhatsApp client and state ---
let client = new Client();
let qrTimeout;
let isAuthenticated = false;
let isInitializing = false;
let qrGenerated = false;

// Attach listeners immediately
client.on("qr", (qr) => {
    // Don't generate new QR if we already have one active
    if (qrGenerated) {
        console.log("🔄 QR already generated, waiting for scan...");
        return;
    }
    
    console.log("📱 Scan this QR code to log in:");
    qrcode.generate(qr, { small: true });
    qrGenerated = true;
    isInitializing = true;

    // Stop QR after 1 minute only if not authenticated
    clearTimeout(qrTimeout);
    qrTimeout = setTimeout(() => {
        if (!isAuthenticated) {
            console.log("⏹️ QR expired after 1 minute. Destroying client...");
            qrGenerated = false;
            isInitializing = false;
            client.destroy().catch(console.error);
        }
    }, 60000);
});

client.on("authenticated", () => {
    isAuthenticated = true;
    isInitializing = false;
    qrGenerated = false;
    console.log("✅ Authenticated with WhatsApp");
    clearTimeout(qrTimeout);
});

client.on("ready", () => {
    isAuthenticated = true;
    isInitializing = false;
    qrGenerated = false;
    console.log("🤖 WhatsApp client is ready!");
    clearTimeout(qrTimeout);
});

client.on("disconnected", (reason) => {
    console.log("⚠️ WhatsApp disconnected:", reason);
    isAuthenticated = false;
    isInitializing = false;
    qrGenerated = false;
    clearTimeout(qrTimeout);
});

client.on("auth_failure", () => {
    console.log("❌ Authentication failed");
    isAuthenticated = false;
    isInitializing = false;
    qrGenerated = false;
    clearTimeout(qrTimeout);
});

// --- Express Endpoints ---

// 1️⃣ Generate QR / Initialize
app.get("/whatsapp-login", (req, res) => {
    dns.resolve("google.com", async (err) => {
        if (err) return res.status(500).send("❌ No internet connection.");

        if (isAuthenticated) {
            return res.send("✅ Already authenticated with WhatsApp.");
        }

        if (isInitializing) {
            if (qrGenerated) {
                return res.send("⏳ QR code already generated. Please scan it within 1 minute.");
            } else {
                return res.send("⏳ WhatsApp client is initializing...");
            }
        }

        // Initialize client only when API is called
        try {
            isInitializing = true;
            await client.initialize();
            return res.send("QR generated. Scan it from console within 1 minute.");
        } catch (error) {
            console.error("❌ Error initializing client:", error);
            isInitializing = false;
            qrGenerated = false;
            return res.status(500).send("Error initializing WhatsApp client.");
        }
    });
});



async function initializeWhatsApp() {
    return new Promise((resolve, reject) => {
        dns.resolve("google.com", async (err) => {
            if (err) {
                resolve("❌ No internet connection.");
                return;
            }

            if (isAuthenticated) {
                resolve("✅ Already authenticated with WhatsApp.");
                return;
            }

            if (isInitializing) {
                if (qrGenerated) {
                    resolve("⏳ QR code already generated. Please scan it within 1 minute.");
                } else {
                    resolve("⏳ WhatsApp client is initializing...");
                }
                return;
            }

            // Initialize client
            try {
                isInitializing = true;
                await client.initialize();
                resolve("QR generated. Scan it from console within 1 minute.");
            } catch (error) {
                console.error("❌ Error initializing client:", error);
                isInitializing = false;
                qrGenerated = false;
                resolve("Error initializing WhatsApp client.");
            }
        });
    });
}





// 4️⃣ Get current WhatsApp state
app.get("/whatsapp-state", (req, res) => {
    res.json({
        authenticated: isAuthenticated,
        initializing: isInitializing,
        qrGenerated: qrGenerated,
        clientState: client.state,
        hasQrTimeout: !!qrTimeout,
        availableMethods: {
            getInfo: typeof client.getInfo === 'function',
            getWWebVersion: typeof client.getWWebVersion === 'function',
            info: !!client.info,
            wid: !!client.wid,
            me: !!client.me
        }
    });
});

// 5️⃣ Debug endpoint to check client methods
app.get("/whatsapp-debug", (req, res) => {
    const clientMethods = Object.getOwnPropertyNames(Object.getPrototypeOf(client));
    const clientProperties = Object.keys(client);
    
    res.json({
        clientType: client.constructor.name,
        methods: clientMethods.filter(m => typeof client[m] === 'function'),
        properties: clientProperties,
        state: client.state
    });
});

// --- Graceful shutdown ---
async function shutdown() {
    console.log("\n⏹️ Shutting down server...");
    clearTimeout(qrTimeout);
    
    if (client) {
        try {
            await client.destroy();
            console.log("✅ WhatsApp client destroyed before exit.");
        } catch (err) {
            console.error("❌ Failed to destroy client:", err.message);
        }
    }
    process.exit(0);
}

// Function to check internet connectivity
function checkInternet(cb) {
  dns.lookup("google.com", (err) => {
    cb(!err);
  });
}

app.get("/whatsapp-status", async (req, res) => {
  checkInternet(async (connected) => {
    if (!connected) {
      return res.status(503).json({ status: "error", message: "No internet connectivity" });
    }

    try {
      const state = await client.getState(); // <-- Real-time client state check

      if (!state || state !== "CONNECTED" || !isAuthenticated) {
        return res.status(400).json({
          status: "error",
          message: "WhatsApp client not connected or logged out from device",
          state,
          isAuthenticated
        });
      }

      res.json({
        status: "success",
        message: "WhatsApp client connected and ready",
        state,
        isAuthenticated
      });
    } catch (error) {
      // getState() throws when client is not initialized or disconnected
      return res.status(400).json({
        status: "error",
        message: "WhatsApp client not available or disconnected",
        error: error.message
      });
    }
  });
});


process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);


initializeWhatsApp();






async function checkAccess(token, page, pool) {
    
    try {
        // Step 1: Compare raw token with tokens in Users table
        const userQuery = `
            SELECT id, is_active 
            FROM Users 
            WHERE token = ?
        `;
        
        const [userRows] = await pool.execute(userQuery, [token]);
        
        // If no user found with this token
        if (userRows.length === 0) {
            return {
                status: 'error',
                message: 'Unauthorized access: Invalid token'
            };
        }
        
        const user = userRows[0];
        
        // Step 2: Check if user is active
        if (user.is_active !== 'Active') {
            return {
                status: 'error',
                message: 'Unauthorized access: User account is inactive'
            };
        }
        
        // Step 3: Check if user has access to the requested page
        const accessQuery = `
            SELECT ua.id 
            FROM UserAccess ua
            WHERE ua.user_id = ? AND ua.page = ?
        `;
        
        const [accessRows] = await pool.execute(accessQuery, [user.id, page]);
        
        // If no access found for this user and page
        if (accessRows.length === 0) {
            return {
                status: 'error',
                message: 'Unauthorized access: No permission for this page'
            };
        }
        
        // All checks passed - user is authorized
        return {
            status: 'success',
            message: 'Access granted',
            userId: user.id
        };
        
    } catch (error) {
        console.error('Database error:', error);
        return {
            status: 'error',
            message: 'Internal server error'
        };
    } 
}



async function executeQuery(query, params = []) {
  try {
    const pool = await initDb();
    
    // For MySQL, we use execute() for prepared statements with parameters
    if (params && params.length > 0) {
      const [rows] = await pool.execute(query, params);
      return { recordset: rows, rowsAffected: [rows.affectedRows || 0] };
    } else {
      // For queries without parameters
      const [rows] = await pool.query(query);
      return { recordset: rows, rowsAffected: [rows.affectedRows || 0] };
    }
  } catch (error) {
    console.error("Query execution error:", error);
    throw error;
  }
}










app.get('/api/pages', async (req, res) => {
  const pageAccess = 'admin-panel';
  
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  
  try {
    const pool = await initDb();
    
    // Check access - this already validates token and permissions
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: accessiblity.message });
    } 

    // No need for redundant token check - proceed directly to fetch pages
    const result = await executeQuery('SELECT page as id, page as name FROM Pages');
    res.json(result.recordset);
    
  } catch(error) {
    console.error('Error: ' + error);
    
    if (error.code === 'ER_ACCESS_DENIED_ERROR' || error.code === 'ECONNREFUSED') {
      return res.status(500).json({ error: 'Database connection failed' });
    }
    
    res.status(500).json({ error: 'Internal server error' });
  }
});



app.get('/api/users', async (req, res) => {
  
  const pageAccess = 'admin-panel';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let pool; // Declare pool here so it's accessible throughout the function

  try {
    pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    } 
  } catch(error){
    console.error("Error: "+error);
    return res.status(500).json({ error: 'Authentication failed' });
  }

  try {
    // Main users query - using array parameters
    const usersResult = await executeQuery(`
      SELECT 
        id, 
        name as username, 
        receiver as role, 
        COALESCE(is_active, 'Active') as status
      FROM Users
    `);
    
    // Get access permissions for each user
    const usersWithPermissions = await Promise.all(
      usersResult.recordset.map(async (user) => {
        // Using array parameters for the permission query
        const permissionsResult = await executeQuery(
          'SELECT page FROM UserAccess WHERE user_id = ?',
          [user.id]  // Array parameter instead of object
        );
        
        const accessPermissions = permissionsResult.recordset.map(item => item.page);
        
        return {
          id: user.id,
          username: user.username,
          role: user.role,
          status: user.status,
          accessPermissions: accessPermissions
        };
      })
    );
    
    res.json(usersWithPermissions);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});



app.get('/api/users/:id', async (req, res) => {
  const pageAccess = 'admin-panel';
  
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  
  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table (redundant - can be removed)
    const [tokenCheck] = await pool.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
  } catch(error) {
    console.error('Error: ' + error);
    return res.status(500).json({ error: 'Authentication failed' });
  }

  try {
    const { id } = req.params;
    
    // Get user details - using array parameter
    const userResult = await executeQuery(
      `SELECT 
        id, 
        name as username, 
        receiver as role, 
        COALESCE(is_active, 'Active') as status 
       FROM Users WHERE id = ?`,
      [id]  // Changed from { id } to [id]
    );
    
    if (userResult.recordset.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Get user permissions - using array parameter
    const permissionsResult = await executeQuery(
      'SELECT page FROM UserAccess WHERE user_id = ?',
      [id]  // Changed from { id } to [id]
    );
    
    const user = userResult.recordset[0];
    const accessPermissions = permissionsResult.recordset.map(item => item.page);
    
    res.json({
      id: user.id,
      username: user.username,
      role: user.role,
      status: user.status,
      accessPermissions: accessPermissions
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});



app.post('/api/users', async (req, res) => {
  const pageAccess = 'admin-panel';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let pool; // Declare pool here so it's accessible throughout the function

  try {
    pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table (redundant - can be removed)
    const [tokenCheck] = await pool.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
  } catch(error) {
    console.error('Error: ' + error);
    return res.status(500).json({ error: 'Internal server error during token validation' });
  }

  let connection;
  try {
    const { id, username, password, role, status, accessPermissions } = req.body;
    
    // Validate required fields
    if (!id || !username || !password) {
      return res.status(400).json({ error: 'ID, username, and password are required' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Start transaction - get a connection from the pool
    connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      // Insert user
      await connection.execute(`
        INSERT INTO Users (id, name, password, receiver, is_active)
        VALUES (?, ?, ?, ?, ?)
      `, [id, username, hashedPassword, role, status || 'Active']);
      
      // Insert access permissions
      if (accessPermissions && accessPermissions.length > 0) {
        for (const page of accessPermissions) {
          await connection.execute(`
            INSERT INTO UserAccess (user_id, page)
            VALUES (?, ?)
          `, [id, page]);
        }
      }
      
      await connection.commit();
      res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
      await connection.rollback();
      throw error;
    }
  } catch (error) {
    console.error('Error creating user:', error);
    
    // MySQL error code for duplicate entry
    if (error.code === 'ER_DUP_ENTRY' || error.errno === 1062) {
      res.status(400).json({ error: 'User ID already exists' });
    } else {
      res.status(500).json({ error: 'Failed to create user' });
    }
  } finally {
    // Always release the connection back to the pool
    if (connection) {
      connection.release();
    }
  }
});



app.put('/api/users/:id', async (req, res) => {
  const page = 'admin-panel';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let pool; // Declare pool at the function level

  try {
    pool = await initDb();
    const accessiblity = await checkAccess(token, page, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table (redundant - can be removed)
    const [tokenCheck] = await pool.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
  } catch(error) {
    console.error('Error: ' + error);
    return res.status(500).json({ error: 'Internal server error during token validation' });
  }

  let connection;
  try {
    const { id } = req.params;
    const { username, password, role, status, accessPermissions } = req.body;
    
    // Validate required fields
    if (!username) {
      return res.status(400).json({ error: 'Username is required' });
    }
    
    // Start transaction - get a connection from the pool
    connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      // Update user
      let query, params;
      
      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        query = `
          UPDATE Users 
          SET name = ?, password = ?, receiver = ?, is_active = ?
          WHERE id = ?
        `;
        params = [username, hashedPassword, role, status || 'Active', id];
      } else {
        query = `
          UPDATE Users 
          SET name = ?, receiver = ?, is_active = ?
          WHERE id = ?
        `;
        params = [username, role, status || 'Active', id];
      }
      
      await connection.execute(query, params);
      
      // Update access permissions
      // First, remove existing permissions
      await connection.execute(
        'DELETE FROM UserAccess WHERE user_id = ?',
        [id]
      );
      
      // Then add new permissions
      if (accessPermissions && accessPermissions.length > 0) {
        for (const page of accessPermissions) {
          await connection.execute(
            'INSERT INTO UserAccess (user_id, page) VALUES (?, ?)',
            [id, page]
          );
        }
      }
      
      await connection.commit();
      res.json({ message: 'User updated successfully' });
    } catch (error) {
      await connection.rollback();
      throw error;
    }
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: 'Failed to update user' });
  } finally {
    // Always release the connection back to the pool
    if (connection) {
      connection.release();
    }
  }
});



app.delete('/api/users/:id', async (req, res) => {
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let pool; // Declare pool at the function level

  try {
    pool = await initDb();

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
  } catch(error) {
    console.error('Error: ' + error);
    return res.status(500).json({ error: 'Internal server error during token validation' });
  }

  let connection;
  try {
    const { id } = req.params;
    
    // Optional: Prevent users from deleting themselves
    const [currentUser] = await pool.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );
    
    if (currentUser.length > 0 && currentUser[0].id === id) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }
    
    // Start transaction
    connection = await pool.getConnection();
    await connection.beginTransaction();
    
    try {
      // First delete user permissions
      await connection.execute(
        'DELETE FROM UserAccess WHERE user_id = ?',
        [id]
      );
      
      // Then delete the user
      const [result] = await connection.execute(
        'DELETE FROM Users WHERE id = ?',
        [id]
      );
      
      // Check if any user was actually deleted
      if (result.affectedRows === 0) {
        await connection.rollback();
        return res.status(404).json({ error: 'User not found' });
      }
      
      await connection.commit();
      res.json({ message: 'User deleted successfully' });
    } catch (error) {
      await connection.rollback();
      throw error;
    }
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  } finally {
    // Always release the connection back to the pool
    if (connection) {
      connection.release();
    }
  }
});



app.get('/api/allowed-pages', async (req, res) => {
  try {
    // Get token from Authorization header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ success: false, message: 'Access token required' });
    }
    
    // Use global database connection pool
    const pool = await initDb();
    
    // Query to get user ID from token
    const userQuery = `
      SELECT id 
      FROM Users 
      WHERE token = ? AND is_active = 'Active'
    `;
    
    const [userRows] = await pool.execute(userQuery, [token]);
    
    if (userRows.length === 0) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
    
    // Get user ID from result
    const userId = userRows[0].id;
    
    // Query to get all allowed pages for the user
    const pagesQuery = `
      SELECT p.page 
      FROM Pages p
      INNER JOIN UserAccess ua ON p.page = ua.page
      WHERE ua.user_id = ?
      ORDER BY p.page
    `;
    
    const [pageRows] = await pool.execute(pagesQuery, [userId]);
    
    // Extract page names from result
    const userAllowedPages = pageRows.map(row => row.page);
    
    // Define the page structure
    const pagesWithType = {
      "dashboard": ["dashboard"],
      "complaints": [
        "launch-complaints",
        "all-complaints",
        "delay-complaints",
        "natures"
      ],
      "users": [
        "all-users",
        "colonies",
        "skillman"
      ],
      "reporting": [
        "daily-report",
        "complaints-report",
        "skillman-report",
        "rating-report"
      ],
      "admin": [
        "admin-panel"
      ]
    };
    
    // Prepare response object
    const responseData = {
      // All individual pages the user has access to
      allowedPages: userAllowedPages,
      
      // Navigation items for header and hamburger menu
      navigationItems: {}
    };
    
    // For each category, find the first page the user has access to
    for (const [category, pages] of Object.entries(pagesWithType)) {
      // Find the first page in this category that the user has access to
      const accessiblePage = pages.find(page => userAllowedPages.includes(page));
      
      if (accessiblePage) {
        // Add the first accessible page for this category
        responseData.navigationItems[category] = accessiblePage;
      }
    }
    
    res.json({
      success: true,
      ...responseData
    });
    
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
  // REMOVED the finally block - don't close the connection!
});




client.on('message', async (message) => {
    try {
        // Ignore messages sent by ourselves
        if (message.fromMe) return;

        const senderNumber = message.from.replace('@c.us', '');
        console.log(`Message received from: ${senderNumber}`);

        // Normalize the incoming WhatsApp number to match database format
        const normalizedSenderNumber = normalizeToLocalFormat(senderNumber);
        console.log(`Normalized sender number: ${normalizedSenderNumber}`);

        // Check if sender is a customer
        let pool = await initDb();
        let connection;
        
        try {
            connection = await pool.getConnection();

            // Check if this phone number belongs to a customer (compare with normalized number)
            const customerQuery = `
                SELECT c.customer_id, c.full_name 
                FROM Customers c 
                WHERE c.phone_number = ?
            `;

            const [customerRows] = await connection.execute(customerQuery, [normalizedSenderNumber]);

            if (customerRows.length === 0) {
                console.log(`Number ${normalizedSenderNumber} is not a registered customer`);
                console.log(`Original WhatsApp number: ${senderNumber}`);
                return; // Not a customer, ignore message
            }

            const customer = customerRows[0];
            const messageBody = message.body.trim();

            console.log(`Processing message from customer: ${customer.full_name}, Message: ${messageBody}`);

            // Check if this is a reply to our message
            if (message.hasQuotedMsg) {
                const quotedMsg = await message.getQuotedMessage();
                
                // Check if the quoted message is from us and contains a review request
                if (quotedMsg.fromMe && (quotedMsg.body.includes('rating') || quotedMsg.body.includes('rate'))) {
                    // Extract complaint ID from quoted message
                    const complaintIdMatch = quotedMsg.body.match(/#(HT\d+-\d+)/) || quotedMsg.body.match(/#(\w+-\d+)/);
                    if (complaintIdMatch) {
                        const complaintId = complaintIdMatch[1];
                        console.log(`Found complaint ID in reply: ${complaintId}`);
                        await processRatingReview(connection, normalizedSenderNumber, messageBody, complaintId, customer);
                        return;
                    }
                }
            }

            // If not a reply, check if message starts with rating digit (0-5)
            const ratingMatch = messageBody.match(/^([0-5])\s*(.*)$/);
            if (ratingMatch) {
                console.log(`Rating message detected: ${messageBody}`);
                
                // Find awaiting feedback for this customer
                const awaitingFeedbackQuery = `
                    SELECT cf.complaint_id 
                    FROM ComplaintFeedback cf
                    INNER JOIN Complaints c ON cf.complaint_id = c.complaint_id
                    INNER JOIN Customers cust ON c.customer_id = cust.customer_id
                    WHERE cust.phone_number = ? 
                    AND cf.status = 'awaiting'
                    ORDER BY cf.created_at DESC
                `;

                const [feedbackRows] = await connection.execute(awaitingFeedbackQuery, [normalizedSenderNumber]);

                if (feedbackRows.length > 0) {
                    const complaintId = feedbackRows[0].complaint_id;
                    console.log(`Found awaiting feedback for complaint: ${complaintId}`);
                    await processRatingReview(connection, normalizedSenderNumber, messageBody, complaintId, customer);
                } else {
                    console.log(`No awaiting feedback found for customer ${normalizedSenderNumber}`);
                    await sendMessage(senderNumber, "Thank you for your message. We don't have any pending review requests for you.");
                }
            } else {
                await sendMessage(senderNumber, "Please send your rating as a single digit from 0 to 5.");
                console.log(`Message doesn't start with rating digit (0-5): ${messageBody}`);
            }

        } catch (error) {
            console.error('Error processing message:', error);
        } finally {
            if (connection) {
                connection.release(); // Release connection back to pool
            }
        }

    } catch (error) {
        console.error('Error in message handler:', error);
    }
});



async function processRatingReview(connection, phoneNumber, messageBody, complaintId, customer) {
    // Trim the message and get the first character
    const trimmedMessage = messageBody.trim();
    const rating = parseInt(trimmedMessage, 10);

    // Check if rating is a valid number between 0 and 5
    if (isNaN(rating) || rating < 0 || rating > 5) {
        console.log(`Invalid rating from ${phoneNumber}: ${messageBody}`);
        await sendMessage(formatPhoneNumber(phoneNumber), "Please send your rating as a single digit from 0 to 5.");
        return;
    }

    // Check if already reviewed
    const statusCheckQuery = `
        SELECT status 
        FROM ComplaintFeedback
        WHERE complaint_id = ?
    `;
    const [statusRows] = await connection.execute(statusCheckQuery, [complaintId]);

    if (statusRows.length > 0 && statusRows[0].status === 'reviewed') {
        console.log(`Complaint ${complaintId} already reviewed by ${phoneNumber}`);
        await sendMessage(formatPhoneNumber(phoneNumber), "Your rating has already been processed. You cannot submit another rating for this complaint.");
        return;
    }

    console.log(`Processing rating: ${rating} for complaint: ${complaintId}`);

    // Validate complaint exists and belongs to this customer
    const complaintCheckQuery = `
        SELECT c.complaint_id 
        FROM Complaints c
        INNER JOIN Customers cust ON c.customer_id = cust.customer_id
        WHERE c.complaint_id = ? 
        AND cust.phone_number = ?
    `;
    const [complaintRows] = await connection.execute(complaintCheckQuery, [complaintId, phoneNumber]);

    if (complaintRows.length === 0) {
        console.log(`Complaint ${complaintId} not found for customer ${phoneNumber}`);
        await sendMessage(formatPhoneNumber(phoneNumber), "We couldn't find the complaint you're trying to rate. Please contact support.");
        return;
    }

    // Update the feedback record
    const updateQuery = `
        UPDATE ComplaintFeedback 
        SET rating = ?, 
            review = '[Not available]', 
            status = 'reviewed',
            created_at = NOW()
        WHERE complaint_id = ? 
        AND status = 'awaiting'
    `;
    const [updateResult] = await connection.execute(updateQuery, [rating, complaintId]);

    console.log(`Rating received - Complaint: ${complaintId}, Rating: ${rating}`);
    console.log(`Rows affected: ${updateResult.affectedRows}`);

    // Send confirmation message
    const confirmationMessage = `Thank you, ${customer.full_name}!\n\nYour rating of ${rating} stars has been recorded for complaint #${complaintId}.\n\nWe appreciate your feedback!`;
    await sendMessage(formatPhoneNumber(phoneNumber), confirmationMessage);
}






function normalizeToLocalFormat(phoneNumber) {
    let digitsOnly = phoneNumber.replace(/\D/g, '');
    
    // If number is in international format (92XXXXXXXXX), convert to local (0XXXXXXXXXX)
    if (digitsOnly.startsWith('92') && digitsOnly.length === 12) {
        return '0' + digitsOnly.substring(2);
    }
    else if (digitsOnly.startsWith('92') && digitsOnly.length > 12) {
        return '0' + digitsOnly.substring(2, 13);
    }
    
    // If already in local format or other format, return as is (up to 11 digits)
    return digitsOnly.length > 11 ? digitsOnly.substring(0, 11) : digitsOnly;
}





// Helper function to send messages (convert back to international format for WhatsApp)
async function sendMessage(phoneNumber, text) {
    try {
        const formattedNumber = formatPhoneNumber(phoneNumber);
        const chatId = `${formattedNumber}@c.us`;
        await client.sendMessage(chatId, text);
        console.log(`Confirmation sent to: ${formattedNumber}`);
    } catch (error) {
        console.error('Error sending confirmation message:', error);
    }
}

// Phone number formatting function for WhatsApp (local to international)
function formatPhoneNumberForWhatsApp(phoneNumber) {
    let digitsOnly = phoneNumber.replace(/\D/g, '');
    
    // Convert local format to international
    if (digitsOnly.startsWith('0') && digitsOnly.length === 11) {
        return '92' + digitsOnly.substring(1);
    }
    else if (digitsOnly.startsWith('0') && digitsOnly.length > 11) {
        return '92' + digitsOnly.substring(1, 12);
    }
    else if (!digitsOnly.startsWith('92') && digitsOnly.length === 10) {
        return '92' + digitsOnly;
    }
    
    // If already in international format or other, return as is
    return digitsOnly.length > 12 ? digitsOnly.substring(0, 12) : digitsOnly;
}






app.post('/api/encrypt-id', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();

    // Step 1: Verify token exists in Users table
    const [rows] = await pool.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
  } catch (error) {
    console.error('Error: ' + error);
    return res.status(500).json({ error: 'Internal server error during token validation' });
  }

  try {
    const { complaint_id } = req.body;

    if (!complaint_id) {
      return res.status(400).json({
        success: false,
        message: 'Complaint ID is required'
      });
    }

    // Encrypt the complaint ID
    const encryptedId = CryptoJS.AES.encrypt(
      complaint_id.toString(),
      SECRET_KEY
    ).toString();

    // URL-safe encoding
    const urlSafeEncryptedId = encryptedId
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    res.json({
      success: true,
      encrypted_id: urlSafeEncryptedId,
      message: 'ID encrypted successfully'
    });

  } catch (error) {
    console.error('Encryption error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during encryption'
    });
  }
});



// Optional: Decryption endpoint (if needed elsewhere in your application)
app.post('/api/decrypt-id', async (req, res) => {
  const pageAccess = 'all-complaints';
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let pool;

  try {
    pool = await initDb();

    // Verify token exists in Users table
    const [tokenRows] = await pool.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenRows.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
  } catch (error) {
    console.error('Error: ' + error);
    return res.status(500).json({ error: 'Internal server error during token validation' });
  }

  try {
    const { encrypted_id } = req.body;

    if (!encrypted_id) {
      return res.status(400).json({
        success: false,
        message: 'Encrypted ID is required'
      });
    }

    // Convert URL-safe format back to standard Base64
    const standardEncryptedId = encrypted_id
      .replace(/-/g, '+')
      .replace(/_/g, '/');

    // Decrypt the ID
    const bytes = CryptoJS.AES.decrypt(standardEncryptedId, SECRET_KEY);
    const decryptedId = bytes.toString(CryptoJS.enc.Utf8);

    if (!decryptedId) {
      return res.status(400).json({
        success: false,
        message: 'Invalid encrypted ID provided'
      });
    }

    // Check if complaint exists
    const [resultRows] = await pool.execute(
      'SELECT COUNT(*) as count FROM Complaints WHERE complaint_id = ?',
      [decryptedId]
    );

    const complaintExists = resultRows[0].count > 0;

    if (!complaintExists) {
      return res.status(404).json({
        success: false,
        message: 'Complaint not found in the database'
      });
    }

    res.json({
      success: true,
      decrypted_id: decryptedId,
      message: 'ID decrypted successfully and validated'
    });

  } catch (error) {
    console.error('Decryption error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during decryption'
    });
  }
});







// Endpoint for complaint details
app.get('/data', async (req, res) => {
  const pageAccess = 'all-complaints';
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Verify token exists in Users table
    const [tokenRows] = await pool.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenRows.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
  } catch (error) {
    console.error('Error: ' + error);
    return res.status(500).json({ error: 'Internal server error during token validation' });
  }

  const { complaintId } = req.query;

  if (!complaintId) {
    return res.status(400).json({ error: 'complaintId query parameter is required' });
  }


  try {
    const query = `
      SELECT 
        comp.customer_id,
        cust.full_name as customer_name,
        cust.phone_number as customer_phone,
        s.id as skillman_id,
        s.name as skillman_name,
        s.phoneNumber as skillman_contact,
        u.id as user_id,
        u.name as user_account,
        u.receiver as user_name,
        comp.launched_at as initiate_time,
        comp.assigned_at as assign_time,
        comp.completed_at as completion_time,
        cf.rating,
        cf.review,
        CONCAT('GE DP ', '➜ ', col.Name, ' ➜ ', l.building_number) as location,
        CONCAT(comp.nature, ' ➜ ', comp.type) as nature_type, -- Add this line
        comp.status,
        comp.priority
      FROM Complaints comp
      INNER JOIN Customers cust ON comp.customer_id = cust.customer_id
      INNER JOIN Location l ON comp.location_id = l.location_id
      INNER JOIN Colonies col ON l.colony_number = col.ColonyNumber
      LEFT JOIN Skillmen s ON comp.skillman_id = s.id
      LEFT JOIN Users u ON comp.receiver_id = u.id
      LEFT JOIN ComplaintFeedback cf ON comp.complaint_id = cf.complaint_id
      WHERE comp.complaint_id = ?
    `;

    const pool = await initDb();
    const [rows] = await pool.execute(query, [complaintId]);

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Complaint not found' });
    }

    const formattedData = rows.map(item => ({
      customerId: item.customer_id,
      customerName: item.customer_name,
      customerPhone: item.customer_phone,
      skillmanId: item.skillman_id,
      skillmanName: item.skillman_name,
      skillmanContact: item.skillman_contact,
      userId: item.user_id,
      userAccount: item.user_account,
      userName: item.user_name,
      initiateTime: item.initiate_time,
      assignTime: item.assign_time,
      completionTime: item.completion_time,
      rating: item.rating,
      review: item.review,
      location: item.location,
      natureType: item.nature_type, // Add this property
      status: item.status,
      priority: item.priority
    }));

    res.json(formattedData);

  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});




// Complaints data endpoint for a customer's history
app.get('/api/users-history', async (req, res) => {
  const pageAccess = 'all-complaints';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let connection; // Changed from pool to connection for MySQL

  try {
    connection = await initDb(); // Use initDb() - ensure this returns MySQL connection
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
  } catch(error) {
    console.error('Error: ' + error);
    return res.status(500).json({ error: 'Internal server error during token validation' });
  }

  try {
    // Get complaintId from query parameter (required)
    const complaintId = req.query.complaintId;
    
    if (!complaintId) {
      return res.status(400).json({ error: 'complaintId parameter is required' });
    }
    
    // First, get the customer ID from the provided complaint ID
    const customerQuery = `
      SELECT customer_id 
      FROM Complaints 
      WHERE complaint_id = ?
    `;
    
    const [customerResult] = await connection.execute(customerQuery, [complaintId]);
    
    if (customerResult.length === 0) {
      return res.status(404).json({ error: 'Complaint not found' });
    }
    
    const customerId = customerResult[0].customer_id;
    
    // Now get all complaints for this customer except the provided one
    let queryString = `
      SELECT 
        c.complaint_id as id,
        DATE_FORMAT(c.launched_at, '%Y-%m-%d') as date,
        CONCAT(col.Name, ', ', l.building_number) as location,
        c.nature,
        c.type as natureType,
        COALESCE(s.name, 'Not Assigned') as skillman,
        c.status
      FROM Complaints c
      LEFT JOIN Location l ON c.location_id = l.location_id
      LEFT JOIN Colonies col ON l.colony_number = col.ColonyNumber
      LEFT JOIN Skillmen s ON c.skillman_id = s.id
      WHERE c.customer_id = ?
      AND c.complaint_id != ?
      ORDER BY c.launched_at DESC
    `;
    
    // Execute query using the existing connection
    const [results] = await connection.execute(queryString, [customerId, complaintId]);
    
    // Send the results as JSON
    res.json(results);
    
  } catch (error) {
    console.error('Database query error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
  // REMOVED the finally block - don't close the connection!
});



// Retrieve Helper skillmen for complaint details
app.get('/api/helpers', async (req, res) => {
  const pageAccess = 'all-complaints';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let connection; // Changed from pool to connection for MySQL

  try {
    connection = await initDb(); // Use initDb() - ensure this returns MySQL connection
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
  } catch(error) {
    console.error('Error: ' + error);
    return res.status(500).json({ error: 'Internal server error during token validation' });
  }

  const { complaintId } = req.query;

  // Validate complaintId parameter
  if (!complaintId) {
    console.log("ID not found");
    return res.status(400).json({
      success: false,
      message: 'complaintId parameter is required'
    });
  }

  try {
    // Query to get all skillmen assigned to the specific complaint
    const query = `
      SELECT 
        s.id,
        s.name,
        s.phoneNumber as phone,
        s.designation,
        s.subdivision,
        s.status
      FROM Skillmen s
      INNER JOIN ComplaintsHelpers ch ON s.id = ch.skillman_id
      WHERE ch.complaint_id = ?
      ORDER BY s.name
    `;
    
    // Execute the query using the existing connection
    const [results] = await connection.execute(query, [complaintId]);
    
    // Format the response
    const helpers = results.map(helper => ({
      id: helper.id,
      name: helper.name,
      phone: helper.phone,
      designation: helper.designation,
      subdivision: helper.subdivision,
      status: helper.status
    }));
    
    // Return the helpers data
    res.json(helpers);
    
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve helper data',
      error: error.message
    });
  }
  // REMOVED the connection closing - don't close the connection!
});




// Whatsapp API to send reviewing request
app.post('/api/send-reviewing-request', async (req, res) => {
  const page = 'all-complaints';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let connection; // Changed from pool to connection for MySQL

  try {
    connection = await initDb(); // Use initDb() - ensure this returns MySQL connection
    const accessiblity = await checkAccess(token, page, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }
    

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
  } catch(error) {
    console.error('Error: ' + error);
    return res.status(500).json({ error: 'Internal server error during token validation' });
  }

  const { phoneNumber, complaintId } = req.body;

  if (!phoneNumber || !complaintId) {
    return res.status(400).json({ message: 'Phone number and complaint ID are required' });
  }

  // Check if WhatsApp client is ready
  if (!client || !client.info) {
    console.error('WhatsApp client is not ready');
    return res.status(503).json({ 
      message: 'WhatsApp service is currently unavailable. Please try again later.' 
    });
  }

  try {
    // Check if complaint exists and get details
    const complaintQuery = `
      SELECT c.complaint_id, c.status, c.skillman_id, s.name as skillman_name,
            cust.phone_number, cust.full_name
      FROM Complaints c
      LEFT JOIN Skillmen s ON c.skillman_id = s.id
      INNER JOIN Customers cust ON c.customer_id = cust.customer_id
      WHERE c.complaint_id = ?
    `;

    const [complaintResult] = await connection.execute(complaintQuery, [complaintId]);

    if (complaintResult.length === 0) {
      return res.status(404).json({ message: 'Complaint not found' });
    }

    const complaint = complaintResult[0];
    const customerName = complaint.full_name;
    const skillmanName = complaint.skillman_name || 'our technician';

    // Check if complaint is completed - if not, return error to frontend
    if (complaint.status !== 'Completed') {
      return res.status(400).json({ 
        message: 'Complaint has not been completed yet',
        complaintStatus: complaint.status
      });
    }

    // Check if feedback already exists and is reviewed
    const existingFeedbackQuery = `
      SELECT feedback_id, status, rating 
      FROM ComplaintFeedback 
      WHERE complaint_id = ? AND status = 'reviewed'
    `;

    const [existingFeedbackResult] = await connection.execute(existingFeedbackQuery, [complaintId]);

    // If complaint has already been reviewed, return error
    if (existingFeedbackResult.length > 0) {
      const feedback = existingFeedbackResult[0];
      return res.status(400).json({ 
        message: 'This complaint has already been reviewed',
        complaintStatus: complaint.status,
        existingRating: feedback.rating,
        feedbackStatus: feedback.status
      });
    }

    // Check for existing ComplaintFeedback records for this customer
    const customerFeedbackQuery = `
      SELECT cf.feedback_id, cf.status 
      FROM ComplaintFeedback cf
      INNER JOIN Complaints c ON cf.complaint_id = c.complaint_id
      INNER JOIN Customers cust ON c.customer_id = cust.customer_id
      WHERE cust.phone_number = ? AND cf.status = 'awaiting'
    `;

    const [customerFeedbackResult] = await connection.execute(customerFeedbackQuery, [phoneNumber]);

    // Update any existing 'awaiting' records for this customer to 'not_reviewed'
    if (customerFeedbackResult.length > 0) {
      await connection.execute(`
        UPDATE ComplaintFeedback cf
        INNER JOIN Complaints c ON cf.complaint_id = c.complaint_id
        INNER JOIN Customers cust ON c.customer_id = cust.customer_id
        SET cf.status = 'not_reviewed'
        WHERE cust.phone_number = ? AND cf.status = 'awaiting'
      `, [phoneNumber]);
    }

    // Check if feedback record already exists for this complaint (but not reviewed)
    const feedbackQuery = `
      SELECT feedback_id, status 
      FROM ComplaintFeedback 
      WHERE complaint_id = ? AND status != 'reviewed'
    `;

    const [feedbackResult] = await connection.execute(feedbackQuery, [complaintId]);

    let feedbackExists = feedbackResult.length > 0;

    // Create or update feedback record
    if (feedbackExists) {
      // Update existing record to 'awaiting'
      await connection.execute(`
        UPDATE ComplaintFeedback 
        SET status = 'awaiting', created_at = NOW()
        WHERE complaint_id = ?
      `, [complaintId]);
    } else {
      // Create new feedback record
      await connection.execute(`
        INSERT INTO ComplaintFeedback (complaint_id, status)
        VALUES (?, 'awaiting')
      `, [complaintId]);
    }

    // Prepare WhatsApp message
    let message = `Dear User,\n\n`;
    message += `Your complaint #${complaintId} has been successfully resolved!\n\n`;
    message += `Please rate ${skillmanName}'s service:\n`;
    message += `0️⃣ - Not resolved\n`;
    message += `1️⃣ - Poor\n`;
    message += `2️⃣ - Fair\n`;
    message += `3️⃣ - Good\n`;
    message += `4️⃣ - Very Good\n`;
    message += `5️⃣ - Excellent\n\n`;
    message += `To provide your rating, reply with a number (0–5)`;

    // Format phone number
    let digitsOnly = phoneNumber.replace(/\D/g, '');
    
    // Convert to international format for Pakistan numbers
    let internationalNumber;
    
    if (digitsOnly.startsWith('92') && digitsOnly.length === 12) {
      internationalNumber = digitsOnly;
    } else if (digitsOnly.startsWith('92') && digitsOnly.length > 12) {
      internationalNumber = digitsOnly.substring(0, 12);
    } else if (digitsOnly.startsWith('3') && digitsOnly.length === 10) {
      internationalNumber = '92' + digitsOnly;
    } else if (digitsOnly.startsWith('03') && digitsOnly.length === 11) {
      internationalNumber = '92' + digitsOnly.substring(1);
    } else if (digitsOnly.startsWith('0') && digitsOnly.length === 11) {
      internationalNumber = '92' + digitsOnly.substring(1);
    } else if (digitsOnly.length === 9 || digitsOnly.length === 10) {
      internationalNumber = '92' + digitsOnly;
    } else {
      internationalNumber = digitsOnly.length > 12 ? digitsOnly.substring(0, 12) : digitsOnly;
      console.warn(`Unknown phone number format: ${phoneNumber}, using: ${internationalNumber}`);
    }
    
    const whatsappId = `${internationalNumber}@c.us`;

    // Send WhatsApp message
    await client.sendMessage(whatsappId, message);
    
    console.log(`WhatsApp review request sent to ${internationalNumber} for complaint ${complaintId}`);

    res.json({ 
      message: 'Review request sent successfully',
      complaintStatus: complaint.status,
      feedbackUpdated: !feedbackExists
    });

  } catch (error) {
    console.error('Error in send-reviewing-request:', error);
    
    // Handle specific WhatsApp errors
    if (error.message.includes('Evaluation failed') || error.message.includes('not found')) {
      return res.status(503).json({ 
        message: 'WhatsApp service temporarily unavailable. Please try again later.',
        error: 'WhatsApp client error'
      });
    }
    
    res.status(500).json({ 
      message: 'Internal server error', 
      error: error.message 
    });
  }
  // REMOVED the finally block - don't close the connection!
});








//APIs for login

// 🔐 Generate a random token (256-bit = 64 hex chars)
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}



// 📌 Login route
app.post('/login', async (req, res) => {
  const { id, password } = req.body;

  if (!id || !password) {
    return res.status(400).json({ error: 'ID and password are required' });
  }

  let connection;
  try {
    connection = await initDb(); // Use initDb() - ensure this returns MySQL connection

    // Fetch user
    const [results] = await connection.execute(
      'SELECT * FROM Users WHERE id = ?',
      [id]
    );

    const user = results[0];

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if user is active
    if (user.is_active !== 'Active') {
      return res.status(401).json({ error: 'Account is deactivated. Please contact administrator.' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    console.log(`User ${user.name} logged in successfully`);

    // Generate and store token
    const token = generateToken();
    await connection.execute(
      'UPDATE Users SET token = ? WHERE id = ?',
      [token, id]
    );

    // Return user info along with token (excluding password)
    return res.status(200).json({
      token,
      user: {
        id: user.id,
        name: user.name,
        role: user.receiver,
        status: user.is_active
      }
    });

  } catch (err) {
    console.error('❌ Login error:', err.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
  // REMOVED the finally block - don't close the connection!
});




// Token verification endpoint
app.post('/verify-token', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  try {
    // Use global connection instead of creating new connection
    const connection = await initDb();
    console.log('Connected to database using global connection');

    // Use parameterized query for security
    const [results] = await connection.execute(
      'SELECT id, name, receiver as role, is_active as status FROM Users WHERE token = ?',
      [token]
    );

    if (results.length > 0) {
      const user = results[0];
      
      // Check if user account is active
      if (user.status !== 'Active') {
        console.log('User account is deactivated:', user.name);
        return res.status(401).json({ 
          success: false, 
          message: 'Account deactivated. Please contact administrator.' 
        });
      }
      
      console.log('Token verified for user:', user.name);
      return res.json({ 
        success: true, 
        user: {
          id: user.id,
          name: user.name,
          role: user.role,
          status: user.status
        }
      });
    } else {
      console.log('Invalid or expired token');
      return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
  // REMOVED the finally block - don't close the connection!
});





// Token verification endpoint with sending receiver name and access control
app.post('/verify-token-get-receiver', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  const { page_name: requestedPage } = req.body;

  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  if (!requestedPage) {
    console.log('No page name provided');
    return res.status(400).json({ success: false, message: 'Page name is required' });
  }

  try {
    // Use global connection instead of creating new connection
    const connection = await initDb();
    console.log('Connected to database using global connection');

    // Check if user exists with this token and is active - using parameterized query
    const [userResults] = await connection.execute(
      'SELECT id, name, receiver, is_active FROM Users WHERE token = ?',
      [token]
    );

    if (userResults.length === 0) {
      console.log('Invalid or expired token');
      return res.status(401).json({ success: false, message: 'Invalid or expired token' });
    }

    const user = userResults[0];
    
    // Check if user is active
    if (user.is_active !== 'Active') {
      console.log('User account is inactive:', user.id);
      return res.status(401).json({ success: false, message: 'Account is inactive' });
    }

    // Check if user has access to the requested page - using parameterized query
    const [accessResults] = await connection.execute(
      'SELECT ua.id FROM UserAccess ua INNER JOIN Users u ON ua.user_id = u.id WHERE ua.user_id = ? AND ua.page = ? AND u.is_active = ?',
      [user.id, requestedPage, 'Active']
    );

    if (accessResults.length === 0) {
      console.log('User does not have access to this page:', user.id, requestedPage);
      return res.status(403).json({ success: false, message: 'Access denied to this page' });
    }

    console.log('Token verified for user:', user.name);
    
    return res.json({ 
      success: true, 
      user: {
        id: user.id,
        name: user.name,
        role: user.receiver,
        status: user.is_active
      },
      receiver: {
        name: user.receiver || 'Administrator' // Fallback to 'Administrator' if receiver is null
      }
    });
  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
  // REMOVED the finally block - don't close the connection!
});





// Logout functionality
app.post('/logout', async (req, res) => {
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }
  const token = authHeader.split(' ')[1];

  try {
    // Use global connection instead of creating new connection
    const connection = await initDb();

    // Use parameterized query to prevent SQL injection
    const [result] = await connection.execute(
      'UPDATE Users SET token = NULL WHERE token = ?',
      [token]
    );

    if (result.affectedRows > 0) {
      console.log('User logged out successfully');
      return res.json({ success: true, message: 'Logged out successfully' });
    } else {
      console.log('Invalid token, no user updated');
      return res.status(400).json({ success: false, message: 'Invalid token' });
    }

  } catch (err) {
    console.error('Error during logout:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
  // REMOVED the finally block - don't close the connection!
});






app.get('/api/count-based-on-priority', async (req, res) => {
  const pageAccess = 'all-complaints';
  // Verify Authorization header exists

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let connection; // Changed from pool to connection for MySQL
  
  try {
    connection = await initDb(); // Use initDb() - ensure this returns MySQL connection
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }
    
    // Verify token validity
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    // Query to get counts by priority
    const [results] = await connection.execute(`
      SELECT 
        priority,
        COUNT(*) as count
      FROM Complaints
      GROUP BY priority
    `);

    // Format the results
    const counts = {
      immediate: 0,
      urgent: 0,
      routine: 0,
      deferred: 0
    };

    results.forEach(row => {
      const priority = row.priority ? row.priority.toLowerCase() : '';
      if (counts.hasOwnProperty(priority)) {
        counts[priority] = row.count;
      }
    });

    res.json({
      success: true,
      counts: counts
    });

  } catch (error) {
    console.error('Error fetching priority counts:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
  // REMOVED the finally block - don't close the connection!
});







// API endpoint to get address data
app.get('/api/addresses', async (req, res) => {
  const pageAccess = 'launch-complaints';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const connection = await initDb(); // mysql2/promise connection
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    // Step 2: Query to get location data with user information
    const query = `
      SELECT 
        IFNULL(u.full_name, 'Vacant') AS customer,
        l.building_number AS buildingNo,
        c.Name AS colony,
        l.building_type AS apartment
      FROM Location l
      LEFT JOIN Accomodation a ON l.location_id = a.location_id
      LEFT JOIN Customers u ON a.user_id = u.customer_id
      LEFT JOIN Colonies c ON l.colony_number = c.ColonyNumber
      ORDER BY l.location_id
    `;

    const [results] = await connection.execute(query);

    res.json(results);
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Failed to fetch address data' });
  }
});







// API endpoint to get colonies
app.get('/api/get-colonies-for-launch-complaints', async (req, res) => {
  const pageAccess = 'launch-complaints';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let connection; // Changed from pool to connection for MySQL
  
  try {
    connection = await initDb(); // Use initDb() - ensure this returns MySQL connection
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const query = `
      SELECT 
        ColonyNumber AS id,
        Name AS name
      FROM Colonies
      ORDER BY Name
    `;
    
    // Execute the query using the existing connection
    const [results] = await connection.execute(query);
    res.json(results);
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Failed to fetch colonies' });
  }
  // REMOVED the finally block - don't close the connection!
});

// API endpoint to get apartment/building types
app.get('/api/apartment-types', async (req, res) => {
  const pageAccess = 'launch-complaints';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let connection; // Changed from pool to connection for MySQL
  
  try {
    connection = await initDb(); // Use initDb() - ensure this returns MySQL connection
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const query = `
      SELECT 
        building_type AS id,
        building_type AS name
      FROM TypeOfBuilding
      ORDER BY building_type
    `;
    
    // Execute the query using the existing connection
    const [results] = await connection.execute(query);
    res.json(results);
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Failed to fetch apartment types' });
  }
  // REMOVED the finally block - don't close the connection!
});




app.post('/api/customers', async (req, res) => {
  const pageAccess = 'launch-complaints';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let connection; // Changed from pool to connection for MySQL
  
  try {
    connection = await initDb(); // Use initDb() - ensure this returns MySQL connection
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const { name, email, phone } = req.body;
    
    // Basic validation
    if (!name || !phone) {
      return res.status(400).json({ 
        success: false, 
        message: 'Name and phone are required fields' 
      });
    }

    // Validate phone number format
    const phoneRegex = /^[0-9+]{10,15}$/;
    if (!phoneRegex.test(phone)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid phone number format' 
      });
    }
    
    // Check if customer already exists
    const [checkResult] = await connection.execute(
      'SELECT COUNT(*) AS count FROM Customers WHERE phone_number = ?',
      [phone]
    );
    
    if (checkResult[0].count > 0) {
      return res.status(409).json({ // Use 409 Conflict for duplicate resources
        success: false, 
        message: 'Customer with this phone number already exists' 
      });
    }
    
    // Insert new customer and get the inserted ID (MySQL approach)
    const [insertResult] = await connection.execute(
      'INSERT INTO Customers (full_name, phone_number, email) VALUES (?, ?, ?)',
      [name, phone, email || null]
    );
    
    // Get the inserted customer data
    const [newCustomer] = await connection.execute(
      'SELECT customer_id, full_name, phone_number, email FROM Customers WHERE customer_id = ?',
      [insertResult.insertId]
    );
    
    res.status(201).json({ // Use 201 Created for successful resource creation
      success: true, 
      message: 'Customer saved successfully',
      customer: newCustomer[0]
    });
  } catch (error) {
    console.error('Error saving customer:', error);
    
    // Handle specific database errors
    if (error.code === 'ER_DUP_ENTRY') { // MySQL unique constraint violation
      return res.status(409).json({ 
        success: false, 
        message: 'Customer with this phone number already exists' 
      });
    }
    
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
  // No need to close the connection - connection manages itself
});










// Get all customers (for testing)
app.get('/api/customers', async (req, res) => {
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let connection; // Changed from pool to connection for MySQL
  
  try {
    connection = await initDb(); // Use initDb() - ensure this returns MySQL connection

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    // Use specific column selection instead of SELECT * for security
    const [results] = await connection.execute(`
      SELECT 
        customer_id,
        full_name,
        phone_number,
        email,
        created_at
      FROM Customers 
      ORDER BY customer_id DESC
    `);
    
    res.json(results);
  } catch (error) {
    console.error('Error fetching customers:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
  // No need to close the connection - connection manages itself
});





// GET /api/categories - Returns concatenated categories
app.get('/api/categories', async (req, res) => {
  const pageAccess = 'launch-complaints';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let connection; // Changed from pool to connection for MySQL
  
  try {
    connection = await initDb(); // Use initDb() - ensure this returns MySQL connection
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    // MySQL compatible query - ROW_NUMBER and CONCAT work the same in MySQL
    const [results] = await connection.execute(`
      SELECT 
        ROW_NUMBER() OVER (ORDER BY CONCAT(c.subdivision_name, '->', c.nature_name)) AS id,
        CONCAT(c.subdivision_name, '->', c.nature_name) AS name,
        c.subdivision_name,
        c.nature_name
      FROM Category c
      ORDER BY CONCAT(c.subdivision_name, '->', c.nature_name)
    `);

    res.json(results);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
  // No need to close the connection - connection manages itself
});








// GET /api/categories/:categoryId/types - Returns types for a category
app.get('/api/categories/:categoryId/types', async (req, res) => {
  const pageAccess = 'launch-complaints';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const connection = await initDb(); // Changed to connection
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    // First get the category details using MySQL approach
    const [categoryResults] = await connection.execute(`
      SELECT subdivision_name, nature_name
      FROM (
        SELECT 
          ROW_NUMBER() OVER (ORDER BY CONCAT(subdivision_name, '->', nature_name)) AS row_num,
          subdivision_name,
          nature_name
        FROM Category
      ) AS OrderedCategories
      WHERE row_num = ?
    `, [req.params.categoryId]);

    if (categoryResults.length === 0) {
      return res.status(404).json({ error: 'Category not found' });
    }

    const category = categoryResults[0];

    // Now get the types for this nature_name
    const [typesResults] = await connection.execute(`
      SELECT 
        ROW_NUMBER() OVER (ORDER BY type) AS id,
        type AS name
      FROM NatureTypes
      WHERE nature_name = ?
      ORDER BY type
    `, [category.nature_name]);

    res.json(typesResults);
  } catch (error) {
    console.error('Error fetching category types:', error);
    res.status(500).json({ error: 'Failed to fetch category types' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});









app.get('/api/customers/search', async (req, res) => {
  const pageAccess = 'launch-complaints';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  
  try {
    const connection = await initDb(); // mysql2/promise connection
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    // Step 2: Proceed with search if token is valid
    const search = req.query.q;

    if (!search) {
      return res.status(400).json({ error: 'Search term is required' });
    }

    // Step 3: Find user by name or phone
    const [userResults] = await connection.execute(
      `SELECT * 
       FROM Customers 
       WHERE full_name LIKE ? OR phone_number LIKE ?
       LIMIT 1`,
      [`%${search}%`, `%${search}%`]
    );

    if (userResults.length === 0) {
      return res.json({ exists: false });
    }

    const user = userResults[0];

    // Step 4: Find user's locations with all required fields
    const [locationResults] = await connection.execute(
      `SELECT 
        l.location_id AS id,
        l.building_number,
        c.Name AS colony_name,
        l.building_type AS apartment_type,
        u.full_name AS customer_name,
        u.phone_number AS customer_phone
      FROM Accomodation a
      JOIN Location l ON a.location_id = l.location_id
      JOIN Colonies c ON l.colony_number = c.ColonyNumber
      JOIN Customers u ON a.user_id = u.customer_id
      WHERE a.user_id = ?`,
      [user.customer_id]
    );

    const locations = locationResults.map(loc => ({
      id: loc.id,
      label: `Customer: ${loc.customer_name}, Phone: ${loc.customer_phone}, Building: ${loc.building_number}, Colony: ${loc.colony_name}`,
      buildingNo: loc.building_number,
      colony: loc.colony_name,
      apartment: loc.apartment_type
    }));

    return res.json({
      exists: true,
      customer: {
        id: user.customer_id,
        name: user.full_name,
        phone: user.phone_number,
        email: user.email
      },
      locations
    });

  } catch (err) {
    console.error('Search error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});










app.post('/api/assign-location', async (req, res) => {
  const pageAccess = 'launch-complaints';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let connection;

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );
    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    console.log('\n=== STARTING LOCATION ASSIGNMENT ===');
    console.log('Request body:', JSON.stringify(req.body, null, 2));

    if (!req.body) throw new Error('Request body is empty');

    const apartment = req.body.apartment || req.body.apartmentType;
    const { customer, type, buildingNo, colony } = req.body;
    const area = req.body.area;
    const residentialStatus = req.body.residentialStatus;

    if (!customer || !buildingNo || !colony || !apartment) {
      throw new Error('Customer, buildingNo, colony, and apartment are required');
    }

    if (type === 'new' && (!area || !residentialStatus)) {
      throw new Error('Area and residentialStatus are required for new buildings');
    }

    // Start transaction
    connection = await pool.getConnection();
    await connection.beginTransaction();
    console.log('Database transaction started');

    // 1. Find user
    const [userResult] = await connection.execute(
      `SELECT customer_id, full_name, phone_number 
       FROM Customers 
       WHERE full_name LIKE ? OR phone_number LIKE ? 
       LIMIT 1`,
      [`%${customer}%`, `%${customer}%`]
    );
    if (userResult.length === 0) throw new Error(`Customer not found: ${customer}`);
    const user = userResult[0];

    // 2. Find colony
    let colonyNumber;
    if (/^\d+$/.test(colony)) {
      const [colonyCheck] = await connection.execute(
        `SELECT Name FROM Colonies WHERE ColonyNumber = ?`,
        [colony]
      );
      if (colonyCheck.length === 0) throw new Error(`Colony number not found: ${colony}`);
      colonyNumber = colony;
    } else {
      const [colonyResult] = await connection.execute(
        `SELECT ColonyNumber FROM Colonies WHERE Name = ?`,
        [colony]
      );
      if (colonyResult.length === 0) throw new Error(`Colony not found: ${colony}`);
      colonyNumber = colonyResult[0].ColonyNumber;
    }

    // 3. Find or create location
    let locationId;
    const [locationResult] = await connection.execute(
      `SELECT location_id 
       FROM Location 
       WHERE building_number = ? 
         AND colony_number = ? 
         AND building_type = ?`,
      [buildingNo, colonyNumber, apartment]
    );

    if (locationResult.length > 0) {
      locationId = locationResult[0].location_id;
    } else if (type === 'new') {
      const [locationInsert] = await connection.execute(
        `INSERT INTO Location (building_number, building_type, resdl, colony_number, area) 
         VALUES (?, ?, ?, ?, ?)`,
        [buildingNo, apartment, residentialStatus, colonyNumber, area]
      );
      locationId = locationInsert.insertId;
    } else {
      throw new Error(`Location not found: ${buildingNo}, ${colony}, ${apartment}`);
    }

    // 4. Update or insert accommodation
    const [accommodationCheck] = await connection.execute(
      `SELECT user_id FROM Accomodation WHERE location_id = ?`,
      [locationId]
    );

    if (accommodationCheck.length > 0) {
      await connection.execute(
        `UPDATE Accomodation SET user_id = ? WHERE location_id = ?`,
        [user.customer_id, locationId]
      );
    } else {
      await connection.execute(
        `INSERT INTO Accomodation (user_id, location_id) VALUES (?, ?)`,
        [user.customer_id, locationId]
      );
    }

    // 5. Fetch all user locations
    const [allLocations] = await connection.execute(
      `SELECT 
         l.location_id AS id,
         l.building_number,
         c.Name AS colony_name,
         l.building_type AS apartment_type,
         u.full_name AS customer_name,
         u.phone_number AS customer_phone,
         l.area,
         l.resdl AS residential_status
       FROM Accomodation a
       JOIN Location l ON a.location_id = l.location_id
       JOIN Colonies c ON l.colony_number = c.ColonyNumber
       JOIN Customers u ON a.user_id = u.customer_id
       WHERE a.user_id = ?
       ORDER BY l.location_id DESC`,
      [user.customer_id]
    );

    const locations = allLocations.map(loc => ({
      id: loc.id,
      label: `Customer: ${loc.customer_name}, Phone: ${loc.customer_phone}, Building: ${loc.building_number}, Colony: ${loc.colony_name}`,
      buildingNo: loc.building_number,
      colony: loc.colony_name,
      apartment: loc.apartment_type,
      area: loc.area,
      residentialStatus: loc.residential_status
    }));

    await connection.commit();

    res.json({ success: true, locations });
  } catch (error) {
    console.error('\n=== LOCATION ASSIGNMENT FAILED ===');
    console.error(error);

    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error('Rollback failed:', rollbackError);
      }
    }

    res.status(error.status || 500).json({
      success: false,
      error: error.message
    });
  } finally {
    if (connection) connection.release();
  }
});









// API Routes for Skillmen
app.get('/api/skillmen', async (req, res) => {
  const pageAccess = 'launch-complaints';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const connection = await initDb(); // Changed to connection
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const [results] = await connection.execute(`
      SELECT 
        id, 
        name, 
        phoneNumber, 
        designation, 
        subdivision AS area
      FROM Skillmen
      ORDER BY name
    `);
    
    res.json(results);
  } catch (err) {
    console.error('Error fetching skillmen:', err);
    res.status(500).json({ error: 'Failed to fetch skillmen' });
  }
});






// Additional API for getting skillmen by area (optional)// Not in use but might be useful later
app.get('/api/skillmen/area/:area', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const connection = await initDb(); // Assuming initDb returns a MySQL connection/pool

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const { area } = req.params;
    
    const [result] = await connection.execute(
      `SELECT 
        id, 
        name, 
        phoneNumber, 
        designation, 
        subdivision AS area
      FROM Skillmen
      WHERE status = 'Active' AND subdivision = ? 
      ORDER BY name`,
      [area]
    );
    
    res.json(result);
  } catch (err) {
    console.error('Error fetching skillmen by area:', err);
    res.status(500).json({ error: 'Failed to fetch skillmen by area' });
  }
}); 






// Additional API for getting skillmen by designation (optional) // Not in use but might be useful later
app.get('/api/skillmen/designation/:designation', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
 
  try {
    const connection = await initDb();

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const { designation } = req.params;
    
    const [result] = await connection.execute(
      `SELECT 
        id, 
        name, 
        phoneNumber, 
        designation, 
        subdivision AS area
      FROM Skillmen
      WHERE status = 'Active' AND designation = ?
      ORDER BY name`,
      [designation]
    );
    
    res.json(result);
  } catch (err) {
    console.error('Error fetching skillmen by designation:', err);
    res.status(500).json({ error: 'Failed to fetch skillmen by designation' });
  }
});









// Get all natures with their categories and types
app.get('/api/natures', async (req, res) => {
  const pageAccess = 'natures';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let pool;

  try {
    pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );
    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    // Step 2: Fetch natures with categories and types
    const [naturesResult] = await pool.execute(`
      SELECT 
        n.name AS id,
        n.name,
        IFNULL((
          SELECT GROUP_CONCAT(DISTINCT s.name SEPARATOR ', ') 
          FROM Category c
          JOIN Subdivision s ON c.subdivision_name = s.name
          WHERE c.nature_name = n.name
        ), '') AS categories,
        IFNULL((
          SELECT GROUP_CONCAT(DISTINCT nt.type SEPARATOR ', ') 
          FROM NatureTypes nt
          WHERE nt.nature_name = n.name
        ), '') AS types
      FROM Natures n
    `);

    const natures = naturesResult.map(row => ({
      id: row.id,
      name: row.name,
      categories: row.categories
        ? row.categories.split(', ').filter(Boolean)
        : [],
      types: row.types
        ? row.types.split(', ').filter(Boolean)
        : []
    }));

    res.json(natures);
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    //if (connection) connection.release();
  }
});





// Create a new nature
app.post('/createNewNatures', async (req, res) => {
  const pageAccess = 'natures';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  const { name } = req.body;
  
  if (!name) {
    return res.status(400).json({ message: 'Nature name is required' });
  }

  let connection;
  try {
    connection = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    await connection.execute(
      'INSERT INTO Natures (name) VALUES (?)',
      [name]
    );
    
    res.json({ 
      message: 'Nature created successfully',
      id: name
    });
  } catch (err) {
    handleDatabaseError(err, res);
  } finally {
    if (connection) {
      connection.release();
    }
  }
});









// Update a nature (name and categories)
app.put('/updateNature/:name', async (req, res) => {
  const pageAccess = 'natures';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  const oldName = decodeURIComponent(req.params.name);
  const { name: newName, categories } = req.body;

  if (!newName) {
    return res.status(400).json({ message: 'Nature name is required' });
  }

  let pool, connection;

  try {
    pool = await initDb();                 // reuse global pool
    connection = await pool.getConnection(); // get a connection from the pool

    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    await connection.beginTransaction();

    if (newName !== oldName) {
      await connection.execute(
        'UPDATE Natures SET name = ? WHERE name = ?',
        [newName, oldName]
      );
    }

    if (Array.isArray(categories) && categories.length >= 0) {
      const uniqueCategories = [...new Set(categories)];

      await connection.execute(
        'DELETE FROM Category WHERE nature_name = ?',
        [newName]
      );

      for (const category of uniqueCategories) {
        const [subdivisionCheck] = await connection.execute(
          'SELECT 1 FROM Subdivision WHERE name = ?',
          [category]
        );

        if (subdivisionCheck.length > 0) {
          await connection.execute(
            'INSERT INTO Category (nature_name, subdivision_name) VALUES (?, ?)',
            [newName, category]
          );
        }
      }
    }

    await connection.commit();
    res.json({ 
      message: 'Nature updated successfully',
      id: newName
    });

  } catch (err) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error('Rollback failed:', rollbackError);
      }
    }
    console.error(err);
    res.status(500).json({ error: 'Database error', details: err.message });

  } finally {
    if (connection) {
      connection.release(); // release connection back to the pool
    }
  }
});







// Delete a nature
app.delete('/deleteNature/:name', async (req, res) => {
  const pageAccess = 'natures';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  const name = decodeURIComponent(req.params.name);

  let connection;
  try {
    connection = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    await connection.execute(
      'DELETE FROM Natures WHERE name = ?',
      [name]
    );
    
    res.json({ message: 'Nature deleted successfully' });
  } catch (err) {
    handleDatabaseError(err, res);
  } finally {
    if (connection) {
      connection.release();
    }
  }
});






// Add a type to a nature
app.post('/addNatureType/:name/types', async (req, res) => {
  const pageAccess = 'natures';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  const natureName = decodeURIComponent(req.params.name);
  const { type } = req.body;

  if (!type) {
    return res.status(400).json({ message: 'Type is required' });
  }

  try {
    const connection = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    // Check if nature exists
    const [natureCheck] = await connection.execute(
      'SELECT 1 FROM Natures WHERE name = ?',
      [natureName]
    );
    
    if (natureCheck.length === 0) {
      return res.status(404).json({ message: 'Nature not found' });
    }
    
    // Check if type already exists
    const [typeCheck] = await connection.execute(
      'SELECT 1 FROM NatureTypes WHERE nature_name = ? AND type = ?',
      [natureName, type]
    );
    
    if (typeCheck.length > 0) {
      return res.status(409).json({ message: 'Type already exists for this nature' });
    }
    
    // Insert new type
    await connection.execute(
      'INSERT INTO NatureTypes (nature_name, type) VALUES (?, ?)',
      [natureName, type]
    );
    
    res.json({ message: 'Type added successfully' });
  } catch (err) {
    handleDatabaseError(err, res);
  }
});








// Remove a type from a nature
app.delete('/deleteNatureType/:name/types/:type', async (req, res) => {
  const pageAccess = 'natures';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  const natureName = decodeURIComponent(req.params.name);
  const type = req.params.type;

  try {
    const connection = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
    
    // Check if type exists
    const [typeCheck] = await connection.execute(
      'SELECT 1 FROM NatureTypes WHERE nature_name = ? AND type = ?',
      [natureName, type]
    );
    
    if (typeCheck.length === 0) {
      return res.status(404).json({ message: 'Type not found for this nature' });
    }
    
    // Delete the type
    await connection.execute(
      'DELETE FROM NatureTypes WHERE nature_name = ? AND type = ?',
      [natureName, type]
    );
    
    res.json({ message: 'Type removed successfully' });
  } catch (err) {
    handleDatabaseError(err, res);
  }
});







// Get all available subdivisions (categories)
app.get('/subdivisions', async (req, res) => {
  const pageAccess = 'natures';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
   
  try {
    const connection = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const [result] = await connection.execute('SELECT name FROM Subdivision');
    res.json(result.map(row => row.name));
  } catch (err) {
    handleDatabaseError(err, res);
  }
});





// Skillmen Endpoints
app.get('/skillmen', async (req, res) => {
  const pageAccess = 'skillman';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  
  try {
    const connection = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const { page = 1, limit = 10, search = '' } = req.query;
    const offset = (page - 1) * limit;

    let query = `
      SELECT s.*, d.name AS designation_name 
      FROM Skillmen s
      JOIN Designation d ON s.designation = d.name
    `;

    let countQuery = 'SELECT COUNT(*) AS total FROM Skillmen s';
    let whereClause = '';

    if (search) {
      whereClause = `
        WHERE s.name LIKE CONCAT('%', ?, '%')
        OR s.phoneNumber LIKE CONCAT('%', ?, '%')
        OR s.email LIKE CONCAT('%', ?, '%')
        OR s.designation LIKE CONCAT('%', ?, '%')
        OR s.subdivision LIKE CONCAT('%', ?, '%')
      `;
    }

    query += whereClause + `
      ORDER BY s.id
      LIMIT ? OFFSET ?
    `;

    countQuery += whereClause;

    // Execute main query
    let result;
    if (search) {
      [result] = await connection.execute(
        query,
        [search, search, search, search, search, parseInt(limit), offset]
      );
    } else {
      [result] = await connection.execute(
        query,
        [parseInt(limit), offset]
      );
    }

    // Execute count query
    let countResult;
    if (search) {
      [countResult] = await connection.execute(
        countQuery,
        [search, search, search, search, search]
      );
    } else {
      [countResult] = await connection.execute(countQuery);
    }

    res.json({
      skillmen: result,
      total: countResult[0].total
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});







app.post('/skillmen', async (req, res) => {
  const pageAccess = 'skillman';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  
  try {
    const connection = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const { name, phone, email, designation, subdivision, status } = req.body;
    
    const [result] = await connection.execute(
      `INSERT INTO Skillmen (name, phoneNumber, email, designation, subdivision, status)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [name, phone, email, designation, subdivision, status]
    );

    // Get the inserted record
    const [insertedRecord] = await connection.execute(
      'SELECT * FROM Skillmen WHERE id = ?',
      [result.insertId]
    );

    res.status(201).json(insertedRecord[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});







app.put('/skillmen/:id', async (req, res) => {
  const pageAccess = 'skillman';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
 
  try {
    const connection = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const { id } = req.params;
    const { name, phone, email, designation, subdivision, status } = req.body;
    
    // Update the record
    await connection.execute(
      `UPDATE Skillmen SET
        name = ?,
        phoneNumber = ?,
        email = ?,
        designation = ?,
        subdivision = ?,
        status = ?
      WHERE id = ?`,
      [name, phone, email, designation, subdivision, status, id]
    );

    // Get the updated record
    const [result] = await connection.execute(
      'SELECT * FROM Skillmen WHERE id = ?',
      [id]
    );

    if (result.length === 0) {
      return res.status(404).json({ error: 'Skillman not found' });
    }

    res.json(result[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});







// Designation Endpoints
app.get('/designations', async (req, res) => {
  const pageAccess = 'skillman';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  
  try {
    const pool = await initDb(); // Make sure this returns a MySQL connection pool
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const [result] = await pool.query('SELECT * FROM Designation');
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});








app.post('/designations', async (req, res) => {
  const pageAccess = 'skillman';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  
  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const { name } = req.body;
    
    // MySQL doesn't have OUTPUT clause, so we use separate queries
    const [result] = await pool.query('INSERT INTO Designation (name) VALUES (?)', [name]);
    
    // Get the inserted record using LAST_INSERT_ID()
    const [insertedRecord] = await pool.query('SELECT * FROM Designation WHERE id = ?', [result.insertId]);

    res.status(201).json(insertedRecord[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});








app.put('/designations/:oldName', async (req, res) => { 
  const pageAccess = 'skillman';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  
  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const { oldName } = req.params;
    const { name: newName } = req.body;

    // First check if the new name already exists
    const [checkResult] = await pool.query('SELECT name FROM Designation WHERE name = ?', [newName]);

    if (checkResult.length > 0) {
      return res.status(400).json({ error: 'Designation with this name already exists' });
    }

    // Update the designation
    const [result] = await pool.query(
      'UPDATE Designation SET name = ? WHERE name = ?',
      [newName, oldName]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Designation not found' });
    }

    res.json({ message: 'Designation updated successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});








// Update all designation endpoints to use name instead of id
app.delete('/designations/:name', async (req, res) => {
  const pageAccess = 'skillman';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  
  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const { name } = req.params;

    // Check if any skillmen are using this designation
    const [checkResult] = await pool.query(
      'SELECT COUNT(*) AS skillmenCount FROM Skillmen WHERE designation = ?', 
      [name]
    );

    if (checkResult[0].skillmenCount > 0) {
      return res.status(400).json({ 
        error: `Cannot delete designation "${name}" - it is being used by ${checkResult[0].skillmenCount} skillmen` 
      });
    }

    const [deleteResult] = await pool.query(
      'DELETE FROM Designation WHERE name = ?', 
      [name]
    );

    if (deleteResult.affectedRows === 0) {
      return res.status(404).json({ error: `Designation "${name}" not found` });
    }

    res.json({ message: `Designation "${name}" deleted successfully` });
  } catch (err) {
    console.error('Error deleting designation:', err);
    res.status(500).json({ error: err.message });
  }
});








// GET: Load all users
app.get('/getUsers', async (req, res) => {
  const pageAccess = 'all-users'; 
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
 
  try {
    const pool = await initDb();

    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    console.log('[GET] Connected to MySQL for users');

    const [result] = await pool.query(`
      SELECT 
        customer_id AS id,
        full_name AS name,
        phone_number AS phone,
        email AS email
      FROM Customers
    `);

    console.log(`[GET] Users fetched: ${result.length}`);
    res.json(result);
  } catch (error) {
    console.error('[GET] Error fetching users:', error.message);
    res.status(500).json({ 
      message: 'Error fetching users',
      error: error.message
    });
  }
});







// GET: Load all colonies
app.get('/getColonies', async (req, res) => {
  const pageAccess = 'colonies';
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
 
  try {
    const pool = await initDb();

    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    console.log('[GET] Connected to MySQL');

    const [result] = await pool.query(`
      SELECT 
          c.Name AS name,
          c.ColonyNumber AS colonyNumber,
          COUNT(l.colony_number) AS buildings
      FROM Colonies c
      LEFT JOIN Location l
          ON c.ColonyNumber = l.colony_number
      GROUP BY c.Name, c.ColonyNumber
    `);

    console.log('[GET] Colonies fetched:', result.length);
    res.json(result);
  } catch (error) {
    console.error('[GET] Error fetching colonies:', error.message);
    res.status(500).json({ message: 'Error fetching colonies' });
  }
});






// POST: Add new colony
app.post('/addColony', async (req, res) => {
  const pageAccess = 'colonies';
  const { name, colonyNumber } = req.body;
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  try {
    const pool = await initDb();
    const token = authHeader.split(' ')[1];

    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    if (!name || !colonyNumber) {
      return res.status(400).json({ message: 'Name and ColonyNumber are required' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    await pool.query(
      'INSERT INTO Colonies (Name, ColonyNumber) VALUES (?, ?)',
      [name, colonyNumber]
    );

    console.log(`[POST] Colony added: ${name} (${colonyNumber})`);
    res.json({ message: 'Colony added successfully' });
  } catch (error) {
    console.error('[POST] Error adding colony:', error.message);
    
    // Handle duplicate entry error specifically
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ message: 'Colony with this number already exists' });
    }
    
    res.status(500).json({ message: 'Error adding colony' });
  }
});








// PUT: Edit a colony
app.put('/editColony', async (req, res) => {
  const pageAccess = 'colonies';
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const { previous, new: updated } = req.body;
  if (!previous || !updated) {
    return res.status(400).json({ message: 'Missing previous or new colony data' });
  }

  try {
    const pool = await initDb();
    const token = authHeader.split(' ')[1];

    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const [result] = await pool.query(
      `UPDATE Colonies
       SET Name = ?, ColonyNumber = ?
       WHERE ColonyNumber = ?`,
      [updated.name, updated.colonyNumber, previous.colonyNumber]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Colony not found' });
    }

    console.log(`[PUT] Colony updated: ${previous.colonyNumber} → ${updated.colonyNumber}`);
    res.json({ message: 'Colony updated successfully' });
  } catch (error) {
    console.error('[PUT] Error updating colony:', error.message);
    
    // Handle duplicate entry error
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ message: 'Colony with this number already exists' });
    }
    
    res.status(500).json({ message: 'Error updating colony' });
  }
});







// Generate Complaint ID based on category and current month/year
async function generateComplaintId(category, pool) {
  const now = new Date();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const year = String(now.getFullYear()).slice(-2);
  
  // Map category to code
  const categoryCodes = {
    'E&M-I': '1',
    'E&M-II': '2',
    'B&R-I': '3',
    'B&R-II': '4',
    'B&R-III': '5',
    'F&S-I': '6'
  };
  
  const categoryCode = categoryCodes[category] || '0';
  
  // Get count of existing complaints for this month+category
  const [result] = await pool.query(`
    SELECT COUNT(*) AS complaintCount 
    FROM Complaints
    WHERE MONTH(launched_at) = ?
      AND YEAR(launched_at) = ?
  `, [now.getMonth() + 1, now.getFullYear()]);

  const newNumber = (result[0].complaintCount || 0) + 1;
  return `HT${month}${year}${categoryCode}-${newNumber}`;
}







// Function to send WhatsApp message to customer
async function sendWhatsAppMessageToCustomer(customerId, complaintId, skillmanName, pool) {
  try {
    // Check if WhatsApp client is ready
    if (!client || !client.info) {
      console.error('WhatsApp client is not ready');
      return;
    }
    
    // Get customer details from database
    const [customerResult] = await pool.query(
      'SELECT full_name, phone_number FROM Customers WHERE customer_id = ?',
      [customerId]
    );
    
    if (customerResult.length === 0) {
      console.error('Customer not found for ID:', customerId);
      return;
    }
    
    const customer = customerResult[0];
    let phoneNumber = customer.phone_number;
    const customerName = customer.full_name;
    
    // Normalize phone number - remove all non-digit characters
    let digitsOnly = phoneNumber.replace(/\D/g, '');
    
    // Convert to international format for Pakistan numbers
    let internationalNumber;
    
    if (digitsOnly.startsWith('92') && digitsOnly.length === 12) {
      // Already in international format: 923001234567
      internationalNumber = digitsOnly;
    } else if (digitsOnly.startsWith('92') && digitsOnly.length > 12) {
      // International format with extra digits, take first 12
      internationalNumber = digitsOnly.substring(0, 12);
    } else if (digitsOnly.startsWith('3') && digitsOnly.length === 10) {
      // Local format without zero: 3001234567 -> 923001234567
      internationalNumber = '92' + digitsOnly;
    } else if (digitsOnly.startsWith('03') && digitsOnly.length === 11) {
      // Local format with zero: 03001234567 -> 923001234567
      internationalNumber = '92' + digitsOnly.substring(1);
    } else if (digitsOnly.startsWith('0') && digitsOnly.length === 11) {
      // Other local formats starting with 0
      internationalNumber = '92' + digitsOnly.substring(1);
    } else if (digitsOnly.length === 9 || digitsOnly.length === 10) {
      // Assume it's a local number without country code
      internationalNumber = '92' + digitsOnly;
    } else {
      // Unknown format, try to use as is but limit to 12 digits
      internationalNumber = digitsOnly.length > 12 ? digitsOnly.substring(0, 12) : digitsOnly;
      console.warn(`Unknown phone number format: ${phoneNumber}, using: ${internationalNumber}`);
    }
    
    const whatsappId = `${internationalNumber}@c.us`;
    
    // Create appropriate message based on whether skillman is assigned
    let message;
    if (skillmanName && skillmanName !== "will be assigned shortly") {
      message = `Dear User, 
      Your complaint (ID: ${complaintId}) 
Has been launched successfully. ✅
Our skillman ${skillmanName} is on the way to solve your problem.👨🏻‍🔧
        `;
    } else {
      message = `Dear User, 
      Your complaint (ID: ${complaintId})
Has been launched successfully.✅
We will assign a skillman to your problem shortly and keep you updated.👍🏻
        `;
    }
    
    // Send WhatsApp message using the direct method
    await client.sendMessage(whatsappId, message);
    
    console.log(`WhatsApp message sent to ${phoneNumber} (international: ${internationalNumber})`);
  } catch (error) {
    console.error('Error sending WhatsApp message:', error.message);
    // Don't throw error to avoid affecting the main complaint creation flow
  }
}









// POST endpoint for creating complaints
app.post('/complaints', async (req, res) => {
  const pageAccess = 'launch-complaints';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Verify token
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const {
      customerId,
      locationId,
      category,
      categoryType,
      description,
      priority,
      receiver,
      primarySkillmanId,
      helperSkillmenIds = []
    } = req.body;

    const [categoryName, nature] = category.name.includes('->')
      ? category.name.split('->')
      : [category.name, ''];

    let status;
    if (priority === 'deferred') {
      status = 'Deferred';
    } else {
      status = (primarySkillmanId || helperSkillmenIds.length > 0)
        ? 'In-Progress'
        : 'Un-Assigned';
    }

    const complaintId = await generateComplaintId(categoryName, pool);
    const launchedAt = new Date();

    // Insert main complaint
    await pool.query(`
      INSERT INTO Complaints (
        complaint_id, customer_id, location_id, nature, category, 
        type, description, priority, launched_at, receiver_id, 
        skillman_id, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?)
    `, [
      complaintId, customerId, locationId, nature.trim(), categoryName.trim(),
      categoryType.name, description, priority, receiver.id,
      primarySkillmanId || null, status
    ]);

    // Insert helpers if any
    if (helperSkillmenIds.length > 0) {
      for (const helperId of helperSkillmenIds) {
        await pool.query(`
          INSERT INTO ComplaintsHelpers (complaint_id, skillman_id)
          VALUES (?, ?)
        `, [complaintId, helperId]);
      }
    }

    const assignedSkillmen = [];
    if (primarySkillmanId) assignedSkillmen.push(primarySkillmanId);
    assignedSkillmen.push(...helperSkillmenIds);

    // Update skillmen status if not deferred
    if (assignedSkillmen.length > 0) {
      for (const skillmanId of assignedSkillmen) {
        await pool.query(`
          UPDATE Skillmen 
          SET status = 'In-Progress' 
          WHERE id = ?
        `, [skillmanId]);
      }
    }

    // Get skillman name for WhatsApp message
    let skillmanName = "will be assigned shortly";
    if (primarySkillmanId) {
      const [skillmanResult] = await pool.query(
        'SELECT name FROM Skillmen WHERE id = ?',
        [primarySkillmanId]
      );

      if (skillmanResult.length > 0) {
        skillmanName = skillmanResult[0].name;
      }
    }

    // Send WhatsApp message (non-blocking)
    sendWhatsAppMessageToCustomer(customerId, complaintId, skillmanName, pool)
      .catch(error => console.error('Error in sending WhatsApp message:', error));

    res.status(201).json({
      success: true,
      message: 'Complaint created successfully',
      complaintId,
      status,
      launchedAt: launchedAt.toISOString()
    });

  } catch (error) {
    console.error('Error creating complaint:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create complaint',
      error: error.message
    });
  }
});











app.get('/api/customers/:customerId/complaints', async (req, res) => {
  const pageAccess = 'launch-complaints';
  let connection;
  
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized - No token provided' });
    }

    const token = authHeader.split(' ')[1];
    const { customerId } = req.params;

    if (!customerId || isNaN(parseInt(customerId))) {
      return res.status(400).json({ error: 'Valid customer ID is required' });
    }

    // Initialize MySQL connection (you'll need to create this function)
    connection = await initDb();
    
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Verify token validity
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const query = `
      SELECT 
        c.complaint_id as id,
        DATE(c.launched_at) as date,
        CONCAT(loc.building_number, ', ', col.Name) as location,
        c.nature,
        c.type as natureType,
        s.name as skillman,
        c.status
      FROM Complaints c
      LEFT JOIN Location loc ON c.location_id = loc.location_id
      LEFT JOIN Colonies col ON loc.colony_number = col.ColonyNumber
      LEFT JOIN Skillmen s ON c.skillman_id = s.id
      WHERE c.customer_id = ?
      ORDER BY c.launched_at DESC
    `;

    const [result] = await connection.execute(query, [parseInt(customerId)]);

    res.json(result);
  } catch (error) {
    console.error('Error fetching customer complaints:', error);
    res.status(500).json({ error: 'Failed to fetch complaint history' });
  } finally {
    // Always close the connection
    if (connection) {
      //await connection.end();
    }
  }
});








// Complaints endpoint with pagination
app.get('/api/complaints', async (req, res) => {
  const pageAccess = 'all-complaints';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }


  const token = authHeader.split(' ')[1];
  let connection;

  try {
    connection = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Verify token
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const {
      page = 1,
      pageSize = 10,
      receiver,
      receiverId,
      colony,
      category,
      status,
      search
    } = req.query;

    const offset = (page - 1) * pageSize;

    // Dynamic filters
    const filters = [];
    const params = [];
    
    if (receiver) {
      if (isNaN(receiver)) {
        filters.push(`u.name LIKE CONCAT('%', ?, '%')`);
        params.push(receiver);
      } else {
        filters.push(`u.id = ?`);
        params.push(receiver);
      }
    }
    if (receiverId) {
      filters.push(`u.id = ?`);
      params.push(receiverId);
    }
    if (colony) {
      filters.push(`loc.colony_number = ?`);
      params.push(colony);
    }
    if (category) {
      filters.push(`c.category = ?`);
      params.push(category);
    }
    if (status) {
      filters.push(`c.status = ?`);
      params.push(status);
    }
    if (search) {
      filters.push(`(
        c.complaint_id LIKE CONCAT('%', ?, '%') OR
        cust.full_name LIKE CONCAT('%', ?, '%') OR
        c.description LIKE CONCAT('%', ?, '%') OR
        loc.building_number LIKE CONCAT('%', ?, '%') OR
        c.category LIKE CONCAT('%', ?, '%') OR
        c.type LIKE CONCAT('%', ?, '%') OR
        s.name LIKE CONCAT('%', ?, '%') OR
        u.name LIKE CONCAT('%', ?, '%') OR
        loc.colony_number LIKE CONCAT('%', ?, '%')
      )`);
      // Add search parameter 9 times for each placeholder
      for (let i = 0; i < 9; i++) {
        params.push(search);
      }
    }
    const whereClause = filters.length ? `WHERE ${filters.join(' AND ')}` : '';

    // Main query
    const query = `
      SELECT 
        c.complaint_id,
        c.nature,
        c.category,
        c.type,
        c.description,
        c.priority,
        DATE_FORMAT(c.launched_at, '%Y-%m-%d %H:%i:%s') AS launched_at,
        DATE_FORMAT(c.completed_at, '%Y-%m-%d %H:%i:%s') AS completed_at,
        c.status,
        cust.full_name AS customer_name,
        cust.phone_number AS customer_phone,
        cust.email AS customer_email,
        loc.building_number AS location_building_number,
        loc.building_type AS location_building_type,
        loc.resdl AS location_resdl,
        loc.colony_number AS location_colony_number,
        col.Name AS location_colony_name,
        loc.area AS location_area,
        u.name AS receiver_name,
        u.id AS receiver_id,
        s.name AS skillman_name
      FROM Complaints c
      LEFT JOIN Customers cust ON c.customer_id = cust.customer_id
      LEFT JOIN Location loc ON c.location_id = loc.location_id
      LEFT JOIN Colonies col ON loc.colony_number = col.ColonyNumber
      LEFT JOIN Users u ON c.receiver_id = u.id
      LEFT JOIN Skillmen s ON c.skillman_id = s.id
      ${whereClause}
      ORDER BY c.launched_at DESC
      LIMIT ? OFFSET ?
    `;

    // Add pagination parameters
    const queryParams = [...params, parseInt(pageSize), offset];

    const [result] = await connection.execute(query, queryParams);

    // Count query
    const countQuery = `
      SELECT COUNT(*) AS total
      FROM Complaints c
      LEFT JOIN Customers cust ON c.customer_id = cust.customer_id
      LEFT JOIN Location loc ON c.location_id = loc.location_id
      LEFT JOIN Colonies col ON loc.colony_number = col.ColonyNumber
      LEFT JOIN Users u ON c.receiver_id = u.id
      LEFT JOIN Skillmen s ON c.skillman_id = s.id
      ${whereClause}
    `;

    const [countResult] = await connection.execute(countQuery, params);
    const total = countResult[0].total;

    res.json({
      success: true,
      data: result,
      pagination: {
        total,
        page: parseInt(page),
        pageSize: parseInt(pageSize),
        totalPages: Math.ceil(total / pageSize)
      }
    });
  } catch (err) {
    console.error('Error fetching complaints:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch complaints',
      error: err.message
    });
  } finally {
    if (connection) {
      //await connection.end();
    }
  }
});







app.get('/api/get-colonies-for-all-complaints', async (req, res) => {
  const pageAccess = 'all-complaints';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let connection; // Declare connection at function level
  
  try {
    connection = await initDb(); // Get MySQL connection
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const query = `
      SELECT 
        ColonyNumber AS id,
        Name AS name
      FROM Colonies
      ORDER BY Name
    `;
    
    // Execute the query using the existing connection
    const [result] = await connection.execute(query);
    res.json(result);
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ error: 'Failed to fetch colonies' });
  } finally {
    // Close the MySQL connection in finally block
    if (connection) {
      //await connection.end();
    }
  }
});








// API endpoint to update complaint status
app.post('/api/complaints/update-status', async (req, res) => {
  const pageAccess = 'all-complaints';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let connection;
  
  try {
    connection = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Verify token
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
    
    const { complaint_id, status } = req.body;

    if (!complaint_id || !status) {
      return res.status(400).json({
        success: false,
        message: 'complaint_id and status are required'
      });
    }

    const validStatuses = ['In-Progress', 'Completed', 'Deferred', 'Un-Assigned', 'SNA'];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid status value'
      });
    }

    // Complaint + helpers
    const [checkResult] = await connection.execute(
      `SELECT c.complaint_id, c.skillman_id, ch.skillman_id AS helper_id
       FROM Complaints c
       LEFT JOIN ComplaintsHelpers ch ON c.complaint_id = ch.complaint_id
       WHERE c.complaint_id = ?`,
      [complaint_id]
    );

    if (checkResult.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Complaint not found'
      });
    }

    const skillmanId = checkResult[0].skillman_id;
    const helperIds = checkResult.map(r => r.helper_id).filter(id => id !== null);

    // Update complaint status (+ completed_at if needed)
    if (status === 'Completed') {
      await connection.execute(
        `UPDATE Complaints
         SET status = ?, completed_at = NOW()
         WHERE complaint_id = ?`,
        [status, complaint_id]
      );
    } else {
      await connection.execute(
        `UPDATE Complaints
         SET status = ?
         WHERE complaint_id = ?`,
        [status, complaint_id]
      );
    }

    // Free skillmen if needed
    if (['Completed'].includes(status)) {

if (skillmanId) {
  // Check if there are any complaints not completed for this skillman
  const [complaints] = await connection.execute(
    `SELECT COUNT(*) AS count
     FROM Complaints
     WHERE skillman_id = ? AND status != 'Completed'`,
    [skillmanId]
  );


  // Only update status if no pending complaints exist
  if (complaints[0].count === 0) {
    await connection.execute(
      `UPDATE Skillmen
       SET status = 'Active'
       WHERE id = ?`,
      [skillmanId]
    );
  }
}

      
if (helperIds.length > 0) {
  // Create placeholders for IN clause
  const placeholders = helperIds.map(() => '?').join(',');

  // Check if any helper has complaints not completed
  const [pendingComplaints] = await connection.execute(
    `SELECT DISTINCT skillman_id
     FROM Complaints
     WHERE skillman_id IN (${placeholders}) AND status != 'Completed'`,
    helperIds
  );

  // Extract IDs of helpers with pending complaints
  const pendingIds = pendingComplaints.map(row => row.skillman_id);

  // Filter out helpers that have pending complaints
  const updatableIds = helperIds.filter(id => !pendingIds.includes(id));

  // Update only those with no pending complaints
  if (updatableIds.length > 0) {
    const activePlaceholders = updatableIds.map(() => '?').join(',');
    await connection.execute(
      `UPDATE Skillmen
       SET status = 'Active'
       WHERE id IN (${activePlaceholders})`,
      updatableIds
    );
  }
}

    }
    
    // WhatsApp call (non-blocking)
    sendWhatsappToCustomerForStatusUpdate(complaint_id, connection)
      .catch(err => console.error('Error sending WhatsApp status update:', err));

    res.json({
      success: true,
      message: `Complaint status updated to ${status} successfully`
    });

  } catch (error) {
    console.error('Error updating complaint status:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  } finally {
    if (connection) {
      connection.release();
    }
  }
});









async function sendWhatsappToCustomerForStatusUpdate(complaintId, connection) {
    try {
        // Check if client is available and ready - more comprehensive check
        if (!client || typeof client.sendMessage !== 'function' || !client.info || !client.pupPage) {
            console.log('WhatsApp client not available, skipping message sending');
            return { success: false, message: 'WhatsApp client not available' };
        }

        // Additional check to see if client is actually connected and authenticated
        if (client.pupPage && client.pupPage.isClosed()) {
            console.log('WhatsApp client page is closed, skipping message sending');
            return { success: false, message: 'WhatsApp client not connected' };
        }

        // Query to get customer phone number, complaint status, and skillman name
        const query = `
            SELECT c.phone_number, comp.status, comp.complaint_id, s.name as skillman_name
            FROM Complaints comp
            INNER JOIN Customers c ON comp.customer_id = c.customer_id
            LEFT JOIN Skillmen s ON comp.skillman_id = s.id
            WHERE comp.complaint_id = ?
        `;

        const [result] = await connection.execute(query, [complaintId]);
        
        if (result.length === 0) {
            console.error(`Complaint with ID ${complaintId} not found`);
            return { success: false, message: 'Complaint not found' };
        }

        const { phone_number, status, complaint_id, skillman_name } = result[0];
        
        // Format the phone number using the existing function
        const formattedPhoneNumber = formatPhoneNumber(phone_number);
        
        // Create the message based on status
        let message = '';
        
        switch (status) {
            case 'Completed':
                message = `Your complaint #${complaint_id} has been marked resolved.\n Thank you for your patience!\nWe will send you a reviewing request shortly.`;
                break;
                
            case 'Deferred':
                message = `Your complaint #${complaint_id} has been rescheduled. We will notify you of the new timing shortly.`;
                break;
                
            case 'SNA':
                //message = `Due to technical issues, your complaint #${complaint_id} will be rescheduled. We apologize for the inconvenience.`;
                message = `Your complaint #${complaint_id} has been rescheduled. We apologize for the inconvenience.`;
                break;
                
            case 'In-Progress':
                const skillmanInfo = skillman_name ? ` Our technician ${skillman_name} is on the way.` : '';
                message = `Your complaint #${complaint_id} is now in progress.`+'\n'+`${skillmanInfo} `+'\n'+`Thank you for your patience!`;
                break;
                
            default:
                console.error(`Unknown status: ${status}`);
                return { success: false, message: `Unknown status: ${status}` };
        }

        // Send the WhatsApp message using the existing client
        const chatId = `${formattedPhoneNumber}@c.us`;
        
        // Final check before sending
        if (!client.sendMessage || typeof client.sendMessage !== 'function') {
            console.error('WhatsApp client sendMessage function not available');
            return { success: false, message: 'WhatsApp client not ready' };
        }

        // Send the message with error handling
        try {
            await client.sendMessage(chatId, message);
            console.log(`WhatsApp message sent successfully to ${formattedPhoneNumber} for complaint ${complaint_id}`);
            return { success: true, message: 'Message sent successfully' };
        } catch (sendError) {
            console.error('Error sending WhatsApp message:', sendError);
            return { success: false, message: 'Failed to send message' };
        }
        
    } catch (error) {
        console.error('Error in sendWhatsappToCustomerForStatusUpdate:', error);
        // Don't throw the error, just return a failure response
        return { success: false, message: error.message };
    }
}

function formatPhoneNumber(phoneNumber) {
    let digitsOnly = phoneNumber.replace(/\D/g, '');
    
    // Convert local format to international
    if (digitsOnly.startsWith('0') && digitsOnly.length === 11) {
        return '92' + digitsOnly.substring(1);
    }
    else if (digitsOnly.startsWith('0') && digitsOnly.length > 11) {
        return '92' + digitsOnly.substring(1, 12);
    }
    else if (!digitsOnly.startsWith('92') && digitsOnly.length === 10) {
        return '92' + digitsOnly;
    }
    
    // If already in international format or other, return as is
    return digitsOnly.length > 12 ? digitsOnly.substring(0, 12) : digitsOnly;
}








app.get('/api/complaints/:complaintId/previous-skillman', async (req, res) => {
  const pageAccess = 'all-complaints';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  const { complaintId } = req.params;
  let connection;

  try {
    connection = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, connection);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Verify token
    const [tokenCheck] = await connection.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    // Get the skillman_id for this complaint
    const [complaintResult] = await connection.execute(
      `SELECT skillman_id 
       FROM Complaints 
       WHERE complaint_id = ?`,
      [complaintId]
    );

    if (complaintResult.length === 0) {
      return res.status(404).json({ success: false, message: 'Complaint not found' });
    }

    const skillmanId = complaintResult[0].skillman_id;

    if (!skillmanId) {
      return res.json({ success: true, skillman: null });
    }

    // Fetch skillman details
    const [skillmanResult] = await connection.execute(
      `SELECT 
         id, 
         name, 
         phoneNumber AS phone, 
         designation, 
         subdivision AS area
       FROM Skillmen
       WHERE id = ?`,
      [skillmanId]
    );

    if (skillmanResult.length === 0) {
      return res.json({ success: true, skillman: null });
    }

    res.json({ success: true, skillman: skillmanResult });
  } catch (err) {
    console.error('Error fetching previous skillman:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch previous skillman' });
  } finally {
    if (connection) {
      //await connection.end();
    }
  }
});









// Function to send WhatsApp message when skillman is assigned/changed
async function sendSkillmanAssignmentMessage(customerId, complaintId, skillmanName, isReassignment, pool) {
  try {
    // Check if WhatsApp client is ready
    if (!client || !client.info) {
      console.error('WhatsApp client is not ready');
      return;
    }
    
    // Get customer details from database
    const [customerResult] = await pool.execute(
      'SELECT full_name, phone_number FROM Customers WHERE customer_id = ?',
      [customerId]
    );
    
    if (customerResult.length === 0) {
      console.error('Customer not found for ID:', customerId);
      return;
    }
    
    const customer = customerResult[0];
    let phoneNumber = customer.phone_number;
    const customerName = customer.full_name;
    
    // Normalize phone number - remove all non-digit characters
    let digitsOnly = phoneNumber.replace(/\D/g, '');
    
    // Convert to international format for Pakistan numbers
    let internationalNumber;
    
    if (digitsOnly.startsWith('92') && digitsOnly.length === 12) {
      // Already in international format: 923001234567
      internationalNumber = digitsOnly;
    } else if (digitsOnly.startsWith('92') && digitsOnly.length > 12) {
      // International format with extra digits, take first 12
      internationalNumber = digitsOnly.substring(0, 12);
    } else if (digitsOnly.startsWith('3') && digitsOnly.length === 10) {
      // Local format without zero: 3001234567 -> 923001234567
      internationalNumber = '92' + digitsOnly;
    } else if (digitsOnly.startsWith('03') && digitsOnly.length === 11) {
      // Local format with zero: 03001234567 -> 923001234567
      internationalNumber = '92' + digitsOnly.substring(1);
    } else if (digitsOnly.startsWith('0') && digitsOnly.length === 11) {
      // Other local formats starting with 0
      internationalNumber = '92' + digitsOnly.substring(1);
    } else if (digitsOnly.length === 9 || digitsOnly.length === 10) {
      // Assume it's a local number without country code
      internationalNumber = '92' + digitsOnly;
    } else {
      // Unknown format, try to use as is but limit to 12 digits
      internationalNumber = digitsOnly.length > 12 ? digitsOnly.substring(0, 12) : digitsOnly;
      console.warn(`Unknown phone number format: ${phoneNumber}, using: ${internationalNumber}`);
    }
    
    const whatsappId = `${internationalNumber}@c.us`;
    
    // Create appropriate message based on whether it's a new assignment or reassignment
    let message;
    if (isReassignment) {
      message = `Dear User, 
      Your complaint (ID: ${complaintId}) 
Has been reassigned to our new skillman ${skillmanName}.👨🏻‍🔧
And is on the way to solve your problem.`;
    } else {
      message = `Dear User, 
      Your complaint (ID: ${complaintId}) 
Has been assigned to our skillman ${skillmanName}.👨🏻‍🔧 
And is on the way to solve your problem.`;
    }
    
    // Send WhatsApp message using the direct method
    await client.sendMessage(whatsappId, message);
    
    console.log(`WhatsApp assignment message sent to ${phoneNumber} (international: ${internationalNumber})`);
  } catch (error) {
    console.error('Error sending WhatsApp assignment message:', error.message);
    // Don't throw error to avoid affecting the main assignment flow
  }
}












app.post('/api/complaints/assign-skillman', async (req, res) => {
  const pageAccess = 'all-complaints';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  const { complaintId, skillmanId } = req.body;

  if (!complaintId || !skillmanId) {
    return res.status(400).json({ success: false, message: 'complaintId and skillmanId are required' });
  }

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists
    const [tokenCheck] = await pool.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    // 1. Get previous skillman + customer
    const [prevResult] = await pool.execute(
      `SELECT skillman_id, customer_id 
       FROM Complaints 
       WHERE complaint_id = ?`,
      [complaintId]
    );

    if (prevResult.length === 0) {
      return res.status(404).json({ success: false, message: 'Complaint not found' });
    }

    const prevSkillmanId = prevResult[0].skillman_id;
    const customerId = prevResult[0].customer_id;

    // 2. Reset previous skillman status if needed
if (prevSkillmanId && prevSkillmanId !== skillmanId) {
  // Check if there are any complaints not completed for this previous skillman
  const [complaints] = await pool.execute(
    `SELECT COUNT(*) AS count
     FROM Complaints
     WHERE skillman_id = ? AND status != 'Completed'`,
    [prevSkillmanId]
  );

  // Only update status if no pending complaints exist
  if (complaints[0].count === 0) {
    await pool.execute(
      `UPDATE Skillmen
       SET status = 'Active'
       WHERE id = ?`,
      [prevSkillmanId]
    );
  }
}


    // 3. Get new skillman name
    const [skillmanResult] = await pool.execute(
      'SELECT name FROM Skillmen WHERE id = ?',
      [skillmanId]
    );

    if (skillmanResult.length === 0) {
      return res.status(404).json({ success: false, message: 'Skillman not found' });
    }

    const skillmanName = skillmanResult[0].name;

    // 4. Update complaint assignment
    const [result] = await pool.execute(
      `UPDATE Complaints
       SET skillman_id = ?
       WHERE complaint_id = ?`,
      [skillmanId, complaintId]
    );

    // 5. Update new skillman status
    await pool.execute(
      `UPDATE Skillmen
       SET status = 'In-Progress'
       WHERE id = ?`,
      [skillmanId]
    );

    // 6. Notify customer on WhatsApp
    const isReassignment = prevSkillmanId !== null && prevSkillmanId !== skillmanId;
    sendSkillmanAssignmentMessage(customerId, complaintId, skillmanName, isReassignment, pool)
      .catch(error => console.error('Error in sending WhatsApp assignment message:', error));

    if (result.affectedRows > 0) {
      res.json({ success: true, message: 'Skillman assigned successfully' });
    } else {
      res.status(404).json({ success: false, message: 'Complaint not found or not updated' });
    }
  } catch (error) {
    console.error('Error assigning skillman:', error);
    res.status(500).json({ success: false, message: 'Failed to assign skillman' });
  }
});










// APIs to retrieve complaints based on priority
app.post('/api/complaints-by-priority', async (req, res) => {
  const pageAccess = 'all-complaints';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const { page = 1, pageSize = 10, priority } = req.query;
    const offset = (page - 1) * pageSize;

    if (!priority) {
      return res.status(400).json({ success: false, message: 'Priority is required' });
    }

    const query = `
      SELECT 
        c.complaint_id,
        c.nature,
        c.category,
        c.type,
        c.description,
        c.priority,
        c.launched_at,
        c.status,
        cust.full_name AS customer_name,
        cust.phone_number AS customer_phone,
        cust.email AS customer_email,
        loc.building_number AS location_building_number,
        loc.building_type AS location_building_type,
        loc.resdl AS location_resdl,
        loc.colony_number AS location_colony_number,
        col.Name AS location_colony_name,
        loc.area AS location_area,
        u.name AS receiver_name,
        s.name AS skillman_name
      FROM Complaints c
      LEFT JOIN Customers cust ON c.customer_id = cust.customer_id
      LEFT JOIN Location loc ON c.location_id = loc.location_id
      LEFT JOIN Colonies col ON loc.colony_number = col.ColonyNumber
      LEFT JOIN Users u ON c.receiver_id = u.id
      LEFT JOIN Skillmen s ON c.skillman_id = s.id
      WHERE c.priority = ?
      ORDER BY c.launched_at DESC
      LIMIT ? OFFSET ?
    `;

    const [result] = await pool.execute(query, [priority, parseInt(pageSize), offset]);

    // Count query
    const countQuery = `SELECT COUNT(*) AS total FROM Complaints WHERE priority = ?`;
    const [countResult] = await pool.execute(countQuery, [priority]);
    const total = countResult[0].total;

    res.json({
      success: true,
      data: result,
      pagination: {
        total,
        page: parseInt(page),
        pageSize: parseInt(pageSize),
        totalPages: Math.ceil(total / pageSize)
      }
    });
  } catch (err) {
    console.error('Error fetching complaints by priority:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch complaints',
      error: err.message
    });
  }
});







//Complaints based on status
app.post('/api/complaints-by-status', async (req, res) => {
  const pageAccess = 'all-complaints';
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    const [tokenCheck] = await pool.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const { page = 1, pageSize = 10, status } = req.query;
    const offset = (page - 1) * pageSize;

    if (!status) {
      return res.status(400).json({ success: false, message: 'Status is required' });
    }

    let query, params;
    if (status === 'all') {
      query = `
        SELECT 
          c.complaint_id,
          c.nature,
          c.category,
          c.type,
          c.description,
          c.priority,
          c.launched_at,
          c.status,
          cust.full_name AS customer_name,
          cust.phone_number AS customer_phone,
          cust.email AS customer_email,
          loc.building_number AS location_building_number,
          loc.building_type AS location_building_type,
          loc.resdl AS location_resdl,
          loc.colony_number AS location_colony_number,
          col.Name AS location_colony_name,
          loc.area AS location_area,
          u.name AS receiver_name,
          s.name AS skillman_name
        FROM Complaints c
        LEFT JOIN Customers cust ON c.customer_id = cust.customer_id
        LEFT JOIN Location loc ON c.location_id = loc.location_id
        LEFT JOIN Colonies col ON loc.colony_number = col.ColonyNumber
        LEFT JOIN Users u ON c.receiver_id = u.id
        LEFT JOIN Skillmen s ON c.skillman_id = s.id
        ORDER BY c.launched_at DESC
        LIMIT ? OFFSET ?
      `;
      params = [parseInt(pageSize), offset];
    } else if(status === 'In-Progress') {
      query = `
        SELECT 
          c.complaint_id,
          c.nature,
          c.category,
          c.type,
          c.description,
          c.priority,
          c.launched_at,
          c.status,
          cust.full_name AS customer_name,
          cust.phone_number AS customer_phone,
          cust.email AS customer_email,
          loc.building_number AS location_building_number,
          loc.building_type AS location_building_type,
          loc.resdl AS location_resdl,
          loc.colony_number AS location_colony_number,
          col.Name AS location_colony_name,
          loc.area AS location_area,
          u.name AS receiver_name,
          s.name AS skillman_name
        FROM Complaints c
        LEFT JOIN Customers cust ON c.customer_id = cust.customer_id
        LEFT JOIN Location loc ON c.location_id = loc.location_id
        LEFT JOIN Colonies col ON loc.colony_number = col.ColonyNumber
        LEFT JOIN Users u ON c.receiver_id = u.id
        LEFT JOIN Skillmen s ON c.skillman_id = s.id
        WHERE c.status IN ('In-Progress', 'Deferred', 'SNA')
        ORDER BY c.launched_at DESC
        LIMIT ? OFFSET ?
      `;
      params = [parseInt(pageSize), offset];
    } else {
      query = `
        SELECT 
          c.complaint_id,
          c.nature,
          c.category,
          c.type,
          c.description,
          c.priority,
          c.launched_at,
          c.status,
          cust.full_name AS customer_name,
          cust.phone_number AS customer_phone,
          cust.email AS customer_email,
          loc.building_number AS location_building_number,
          loc.building_type AS location_building_type,
          loc.resdl AS location_resdl,
          loc.colony_number AS location_colony_number,
          col.Name AS location_colony_name,
          loc.area AS location_area,
          u.name AS receiver_name,
          s.name AS skillman_name
        FROM Complaints c
        LEFT JOIN Customers cust ON c.customer_id = cust.customer_id
        LEFT JOIN Location loc ON c.location_id = loc.location_id
        LEFT JOIN Colonies col ON loc.colony_number = col.ColonyNumber
        LEFT JOIN Users u ON c.receiver_id = u.id
        LEFT JOIN Skillmen s ON c.skillman_id = s.id
        WHERE c.status = ?
        ORDER BY c.launched_at DESC
        LIMIT ? OFFSET ?
      `;
      params = [status, parseInt(pageSize), offset];
    }

    const [result] = await pool.execute(query, params);

    // Count total complaints
    let countQuery, countParams;
    if (status === 'all') {
      countQuery = `SELECT COUNT(*) AS total FROM Complaints`;
      countParams = [];
    } else {
      countQuery = `SELECT COUNT(*) AS total FROM Complaints WHERE status = ?`;
      countParams = [status];
    }
    const [countResult] = await pool.execute(countQuery, countParams);
    const total = countResult[0].total;

    res.json({
      success: true,
      data: result,
      pagination: {
        total,
        page: parseInt(page),
        pageSize: parseInt(pageSize),
        totalPages: Math.ceil(total / pageSize)
      }
    });

  } catch (err) {
    console.error('Error fetching complaints by status:', err);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch complaints',
      error: err.message
    });
  }
});











app.get('/api/receivers', async (req, res) => {
  // Verify Authorization header exists
  const pageAccess = 'all-complaints';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.execute(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({
        error: 'Unauthorized - Invalid token. Please login again.'
      });
    }

    // Query distinct receiver names from Users
    const [result] = await pool.execute(`
      SELECT DISTINCT id, name
      FROM Users
      ORDER BY name
    `);

    res.json(result);
  } catch (error) {
    console.error('Error fetching receivers:', error);
    res.status(500).json({ error: 'Failed to fetch receivers' });
  }
});








// API for delay complaints
app.post('/api/delay-complaints', async (req, res) => {
  const pageAccess = 'delay-complaints';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Verify token
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res.status(401).json({
        error: 'Unauthorized - Invalid token. Please login again.'
      });
    }

    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.max(Math.min(parseInt(req.query.limit) || 10, 100), 1);
    const search = req.query.search || '';
    const offset = (page - 1) * limit;

    let baseQuery = `
      SELECT 
        c.complaint_id,
        DATE_FORMAT(c.launched_at, '%Y-%m-%d') AS date,
        CONCAT(c.nature, ' / ', c.type) AS category,
        l.building_number AS building,
        col.Name AS colony,
        u.name AS launched_by,
        s.name AS skillman,
        c.priority AS type,
        c.status,
        CASE 
          WHEN c.priority = 'Immediate' THEN 
            ROUND(TIMESTAMPDIFF(MINUTE, DATE_ADD(c.launched_at, INTERVAL 2 HOUR), 
              CASE WHEN c.status = 'Completed' THEN c.completed_at ELSE NOW() END) / 60.0, 1)
          WHEN c.priority = 'Urgent' THEN 
            ROUND(TIMESTAMPDIFF(MINUTE, DATE_ADD(c.launched_at, INTERVAL 6 HOUR), 
              CASE WHEN c.status = 'Completed' THEN c.completed_at ELSE NOW() END) / 60.0, 1)
          WHEN c.priority = 'Routine' THEN 
            ROUND(TIMESTAMPDIFF(MINUTE, DATE_ADD(c.launched_at, INTERVAL 24 HOUR), 
              CASE WHEN c.status = 'Completed' THEN c.completed_at ELSE NOW() END) / 60.0, 1)
        END AS delay_time_hours,
        c.launched_at
      FROM Complaints c
      LEFT JOIN Location l ON c.location_id = l.location_id
      LEFT JOIN Colonies col ON l.colony_number = col.ColonyNumber
      LEFT JOIN Users u ON c.receiver_id = u.id
      LEFT JOIN Skillmen s ON c.skillman_id = s.id
      WHERE c.status IN ('Completed', 'In-Progress')
        AND c.status != 'Deferred'
        AND (
          (c.priority = 'Immediate' AND TIMESTAMPDIFF(MINUTE, DATE_ADD(c.launched_at, INTERVAL 2 HOUR), 
            CASE WHEN c.status = 'Completed' THEN c.completed_at ELSE NOW() END) > 0)
          OR
          (c.priority = 'Urgent' AND TIMESTAMPDIFF(MINUTE, DATE_ADD(c.launched_at, INTERVAL 6 HOUR), 
            CASE WHEN c.status = 'Completed' THEN c.completed_at ELSE NOW() END) > 0)
          OR
          (c.priority = 'Routine' AND TIMESTAMPDIFF(MINUTE, DATE_ADD(c.launched_at, INTERVAL 24 HOUR), 
            CASE WHEN c.status = 'Completed' THEN c.completed_at ELSE NOW() END) > 0)
        )
    `;

    let queryParams = [];

    if (search) {
      const safeSearch = `%${search.replace(/'/g, "''")}%`;
      baseQuery += `
        AND (
          c.complaint_id LIKE ? OR
          CONCAT(c.nature, ' / ', c.type) LIKE ? OR
          l.building_number LIKE ? OR
          col.Name LIKE ? OR
          u.name LIKE ? OR
          s.name LIKE ? OR
          c.priority LIKE ? OR
          c.status LIKE ?
        )
      `;
      // Add the search parameter 8 times for each LIKE condition
      queryParams = Array(8).fill(safeSearch);
    }

    // Count total
    const countQuery = `
      SELECT COUNT(*) as total 
      FROM (${baseQuery.replace(/SELECT.*FROM/, 'SELECT c.complaint_id FROM')}) AS temp
    `;
    
    const [countResult] = await pool.query(countQuery, queryParams);
    const total = countResult[0].total;

    // Fetch paginated data
    const dataQuery = `
      ${baseQuery}
      ORDER BY c.launched_at DESC
      LIMIT ? OFFSET ?
    `;
    
    const paginationParams = [...queryParams, limit, offset];
    const [result] = await pool.query(dataQuery, paginationParams);

    const complaints = result.map(complaint => ({
      complaintId: complaint.complaint_id,
      date: complaint.date,
      category: complaint.category,
      building: complaint.building,
      colony: complaint.colony,
      launchedBy: complaint.launched_by,
      skillman: complaint.skillman || 'Unassigned',
      type: complaint.type,
      delayTime: `${parseFloat(complaint.delay_time_hours).toFixed(1)} hours`,
      status: complaint.status
    }));

    res.json({
      success: true,
      data: complaints,
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit)
    });

  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({
      success: false,
      message: 'Error fetching delayed complaints'
    });
  }
});







// API endpoint to get colonies with their buildings
app.get('/api/colonies-with-buildings', async (req, res) => {
  const pageAccess = 'complaints-report';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res.status(401).json({
        error: 'Unauthorized - Invalid token. Please login again.'
      });
    }

    // Query colonies and buildings
    const query = `
      SELECT 
        c.ColonyNumber as id, 
        c.Name as name,
        l.location_id as buildingId, 
        l.building_number as buildingName
      FROM Colonies c
      LEFT JOIN Location l ON c.ColonyNumber = l.colony_number
      ORDER BY c.Name, l.building_number
    `;

    const [result] = await pool.query(query);

    // Group buildings by colony
    const coloniesMap = new Map();
    result.forEach(row => {
      if (!coloniesMap.has(row.id)) {
        coloniesMap.set(row.id, {
          id: row.id,
          name: row.name,
          buildings: []
        });
      }
      if (row.buildingId && row.buildingName) {
        coloniesMap.get(row.id).buildings.push({
          id: row.buildingId,
          name: row.buildingName
        });
      }
    });

    const colonies = Array.from(coloniesMap.values());
    res.json(colonies);

  } catch (err) {
    console.error('Error fetching colonies with buildings:', err);
    res.status(500).json({ error: 'Failed to fetch colonies and buildings' });
  }
});








// API endpoint to get categories with their natures
app.get('/api/categories-with-natures', async (req, res) => {
  // Verify Authorization header exists
  const pageAccess = 'complaints-report';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res.status(401).json({
        error: 'Unauthorized - Invalid token. Please login again.'
      });
    }

    // Query categories with natures
    const query = `
      SELECT 
        subdivision_name AS category,
        nature_name AS nature
      FROM Category
      ORDER BY subdivision_name, nature_name
    `;

    const [result] = await pool.query(query);

    // Group natures by category
    const categoriesMap = new Map();
    result.forEach(row => {
      if (!categoriesMap.has(row.category)) {
        categoriesMap.set(row.category, {
          name: row.category,
          natures: []
        });
      }
      if (row.nature) {
        categoriesMap.get(row.category).natures.push(row.nature);
      }
    });

    const categories = Array.from(categoriesMap.values());
    res.json(categories);

  } catch (err) {
    console.error('Error fetching categories with natures:', err);
    res.status(500).json({ error: 'Failed to fetch categories and natures' });
  }
});











// API endpoint for sub division report
app.post('/api/subdiv-report', async (req, res) => {
  const pageAccess = 'complaints-report';

  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  const { fromDate, toDate, category } = req.body;

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);
    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    // Prepare WHERE clause and parameters
    let whereClause = '';
    let params = [];

    if (fromDate && toDate) {
      if (fromDate === toDate) {
        // Same day → include the full day
        whereClause = `WHERE CAST(launched_at AS DATE) = ?`;
        params.push(fromDate);
      } else {
        // Different days → include start of fromDate to end of toDate
        let from = new Date(fromDate);
        let to = new Date(toDate);
        to.setHours(23, 59, 59, 999); // end of the day
        whereClause = `WHERE launched_at BETWEEN ? AND ?`;
        params.push(from, to);
      }
    } else if (fromDate) {
      let from = new Date(fromDate);
      whereClause = `WHERE launched_at >= ?`;
      params.push(from);
    } else if (toDate) {
      let to = new Date(toDate);
      to.setHours(23, 59, 59, 999);
      whereClause = `WHERE launched_at <= ?`;
      params.push(to);
    }

    // Category filter
    if (category && category !== '') {
      if (category === '-') {
        whereClause += ` AND (category IS NULL OR category = '-')`;
      } else {
        whereClause += ` AND category = ?`;
        params.push(category);
      }
    }

    // Status query
    const statusQuery = `
      SELECT 
        COALESCE(category, '-') AS subDivision,
        COUNT(CASE WHEN status = 'In-Progress' THEN 1 END) AS inprogress,
        COUNT(CASE WHEN status = 'Completed' THEN 1 END) AS completed,
        COUNT(CASE WHEN status = 'Un-Assigned' THEN 1 END) AS sna,
        COUNT(CASE WHEN status = 'Deferred' THEN 1 END) AS deferred,
        COUNT(*) AS total
      FROM Complaints
      ${whereClause}
      GROUP BY COALESCE(category, '-')
      ORDER BY COALESCE(category, '-')
    `;

    // Priority query
    const priorityQuery = `
      SELECT 
        COALESCE(category, '-') AS subDivision,
        COUNT(CASE WHEN priority = 'Immediate' THEN 1 END) AS immediate,
        COUNT(CASE WHEN priority = 'Urgent' THEN 1 END) AS urgent,
        COUNT(CASE WHEN priority = 'Routine' THEN 1 END) AS routine,
        COUNT(CASE WHEN priority = 'Deferred' THEN 1 END) AS deferred,
        COUNT(*) AS total
      FROM Complaints
      ${whereClause}
      GROUP BY COALESCE(category, '-')
      ORDER BY COALESCE(category, '-')
    `;

    // Run queries in parallel
    const [statusResult, priorityResult] = await Promise.all([
      pool.query(statusQuery, params),
      pool.query(priorityQuery, params)
    ]);

    res.json({
      statusData: statusResult[0],
      priorityData: priorityResult[0]
    });

  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});









// API for summary reporting

app.get('/api/summary-report', async (req, res) => {
  const pageAccess = 'complaints-report';

  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  const { year } = req.query;

  if (!year || isNaN(year)) {
    return res.status(400).json({ error: 'Valid year parameter is required' });
  }

  try {
    const pool = await initDb(); // should return a mysql2/promise pool
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Verify token exists in Users table
    const [tokenCheck] = await pool.execute('SELECT id FROM Users WHERE token = ?', [token]);
    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const intYear = parseInt(year);

    // Fetch all natures and colonies
    const [naturesResult, coloniesResult] = await Promise.all([
      pool.execute('SELECT name FROM Natures'),
      pool.execute('SELECT Name, ColonyNumber FROM Colonies')
    ]);

    const allNatures = naturesResult[0];
    const allColonies = coloniesResult[0];

    // Query complaints by nature
    const natureQuery = `
      SELECT 
        n.name AS nature,
        COUNT(c.complaint_id) AS total,
        CASE 
          WHEN (SELECT COUNT(*) FROM Complaints WHERE YEAR(launched_at) = ?) > 0
          THEN (COUNT(c.complaint_id) * 100.0 / (SELECT COUNT(*) FROM Complaints WHERE YEAR(launched_at) = ?))
          ELSE 0
        END AS percentage
      FROM Natures n
      LEFT JOIN Complaints c
        ON n.name = c.nature
       AND YEAR(c.launched_at) = ?
      GROUP BY n.name
      ORDER BY total DESC, n.name
    `;

    // Query complaints by colony
    const colonyQuery = `
      SELECT 
        col.Name AS colony,
        COUNT(c.complaint_id) AS total,
        CASE 
          WHEN (SELECT COUNT(*) FROM Complaints WHERE YEAR(launched_at) = ?) > 0
          THEN (COUNT(c.complaint_id) * 100.0 / (SELECT COUNT(*) FROM Complaints WHERE YEAR(launched_at) = ?))
          ELSE 0
        END AS percentage
      FROM Colonies col
      LEFT JOIN Location l ON col.ColonyNumber = l.colony_number
      LEFT JOIN Complaints c
        ON l.location_id = c.location_id
       AND YEAR(c.launched_at) = ?
      GROUP BY col.Name, col.ColonyNumber
      ORDER BY total DESC, col.Name
    `;

    const [natureComplaints, colonyComplaints] = await Promise.all([
      pool.execute(natureQuery, [intYear, intYear, intYear]),
      pool.execute(colonyQuery, [intYear, intYear, intYear])
    ]);

    // Ensure all natures included and cast numbers
    const natureData = allNatures.map(natureItem => {
      const found = natureComplaints[0].find(item => item.nature === natureItem.name);
      if (found) {
        return {
          nature: found.nature,
          total: Number(found.total),
          percentage: Number(found.percentage)
        };
      }
      return { nature: natureItem.name, total: 0, percentage: 0 };
    });

    // Ensure all colonies included and cast numbers
    const colonyData = allColonies.map(colonyItem => {
      const found = colonyComplaints[0].find(item => item.colony === colonyItem.Name);
      if (found) {
        return {
          colony: found.colony,
          total: Number(found.total),
          percentage: Number(found.percentage)
        };
      }
      return { colony: colonyItem.Name, total: 0, percentage: 0 };
    });

    res.json({
      nature: natureData,
      colony: colonyData
    });

  } catch (error) {
    console.error('Error fetching summary report:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});









// Endpoints for Default Reporting
// Complaints endpoint
app.get('/api/complaints-report', async (req, res) => {
  const pageAccess = 'complaints-report';
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    const {
      colony,
      building,
      category,
      nature,
      status,
      priority,
      fromDate,
      toDate
    } = req.query;

    let query = `
      SELECT 
        c.complaint_id as id,
        CAST(c.launched_at as DATE) as date,
        c.category as subdiv,
        c.nature,
        c.type as ntype,
        col.Name as colony,
        l.building_number as building,
        u.receiver as launchedBy,
        s.name as skillman,
        cust.full_name as customer,
        c.priority as ptype,
        c.status
      FROM Complaints c
      LEFT JOIN Location l ON c.location_id = l.location_id
      LEFT JOIN Colonies col ON l.colony_number = col.ColonyNumber
      LEFT JOIN Users u ON c.receiver_id = u.id
      LEFT JOIN Skillmen s ON c.skillman_id = s.id
      LEFT JOIN Customers cust ON c.customer_id = cust.customer_id
      WHERE 1=1
    `;

    const params = [];

    if (colony) {
      query += ` AND col.ColonyNumber LIKE ?`;
      params.push(`%${colony}%`);
    }
    if (building) {
      query += ` AND l.building_number LIKE ?`;
      params.push(`%${building}%`);
    }
    if (category) {
      query += ` AND c.category = ?`;
      params.push(category);
    }
    if (nature) {
      query += ` AND c.nature = ?`;
      params.push(nature);
    }
    if (status) {
      query += ` AND c.status = ?`;
      params.push(status);
    }
    if (priority) {
      query += ` AND c.priority = ?`;
      params.push(priority);
    }
    if (fromDate) {
      query += ` AND CAST(c.launched_at as DATE) >= ?`;
      params.push(fromDate);
    }
    if (toDate) {
      query += ` AND CAST(c.launched_at as DATE) <= ?`;
      params.push(toDate);
    }

    query += ` ORDER BY c.launched_at DESC`;

    const [result] = await pool.query(query, params);

    res.json(result);
  } catch (err) {
    console.error('Error fetching complaints:', err);
    res.status(500).json({ error: 'Failed to fetch complaints data' });
  }
});







// Rating Report
// API endpoint to get rating reports
app.get('/ratings', async (req, res) => {
  const pageAccess = 'rating-report';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    // SQL query to get rating data
    const query = `
      SELECT 
        c.complaint_id,
        c.launched_at as date,
        cu.full_name as user,
        cu.phone_number as number,
        c.category as type,
        CONCAT(c.nature, '/', c.type) as complaint_category,
        col.Name as colony,
        loc.building_number as building,
        cf.rating,
        cf.review,
        cf.created_at as feedback_date
      FROM Complaints c
      INNER JOIN Customers cu ON c.customer_id = cu.customer_id
      INNER JOIN Location loc ON c.location_id = loc.location_id
      INNER JOIN Colonies col ON loc.colony_number = col.ColonyNumber
      INNER JOIN ComplaintFeedback cf ON c.complaint_id = cf.complaint_id
      WHERE cf.rating IS NOT NULL
      ORDER BY cf.created_at DESC
    `;

    const [result] = await pool.query(query);

    // Format the data for the frontend
    const ratingsData = result.map(item => ({
      date: item.date,
      complaintNumber: item.complaint_id,
      user: item.user,
      number: item.number,
      type: item.type,
      category: item.complaint_category,
      colony: item.colony,
      building: item.building,
      rating: item.rating,
      review: item.review || 'No review provided'
    }));

    res.json(ratingsData);
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to fetch rating data' });
  }
});










// API endpoint to get all skillman summary data
app.get('/api/all-skillman-summary', async (req, res) => {
  const pageAccess = 'skillman-report';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res.status(401).json({
        error: 'Unauthorized - Invalid token. Please login again.'
      });
    }

    // Query to get skillman performance data
    const query = `
      SELECT 
        s.id,
        s.name,
        s.phoneNumber as phone,
        s.designation,
        COUNT(c.complaint_id) as totalComplaints,
        SUM(CASE WHEN c.status = 'In-Progress' THEN 1 ELSE 0 END) as inProgress,
        SUM(CASE WHEN c.status = 'Completed' THEN 1 ELSE 0 END) as completed,
        AVG(CASE WHEN cf.status = 'reviewed' THEN COALESCE(cf.rating, 0) ELSE NULL END) as rating,
        SUM(CASE 
            WHEN c.completed_at IS NOT NULL AND c.assigned_at IS NOT NULL 
            THEN TIMESTAMPDIFF(MINUTE, c.assigned_at, c.completed_at) / 60.0
            ELSE 0 
        END) as totalHours,
        CASE 
            WHEN SUM(CASE WHEN c.status = 'Completed' THEN 1 ELSE 0 END) > 0
            THEN SUM(CASE 
                    WHEN c.completed_at IS NOT NULL AND c.assigned_at IS NOT NULL 
                    THEN TIMESTAMPDIFF(MINUTE, c.assigned_at, c.completed_at) / 60.0
                    ELSE 0 
                END) / NULLIF(SUM(CASE WHEN c.status = 'Completed' THEN 1 ELSE 0 END), 0)
            ELSE 0
        END as averageHours,
        CASE 
            WHEN COUNT(c.complaint_id) > 0
            THEN (SUM(CASE WHEN c.status = 'Completed' THEN 1 ELSE 0 END) * 100.0) / COUNT(c.complaint_id)
            ELSE 0
        END as productivity,
        COUNT(CASE WHEN cf.status = 'reviewed' THEN 1 ELSE NULL END) as reviewedFeedbacks
      FROM Skillmen s
      LEFT JOIN Complaints c ON s.id = c.skillman_id
      LEFT JOIN ComplaintFeedback cf ON c.complaint_id = cf.complaint_id
      GROUP BY s.id, s.name, s.phoneNumber, s.designation
      ORDER BY s.name
    `;

    const [result] = await pool.query(query);

    // Format the data for the frontend
    const skillmanData = result.map(row => {
      const totalHours = parseFloat(row.totalHours).toFixed(1);
      const averageHours = parseFloat(row.averageHours).toFixed(1);
      const rating = row.reviewedFeedbacks > 0
        ? parseFloat(row.rating).toFixed(1)
        : '0.0';

      return {
        id: row.id,
        name: row.name,
        phone: row.phone,
        designation: row.designation,
        totalComplaints: row.totalComplaints,
        inProgress: row.inProgress,
        completed: row.completed,
        rating: rating,
        timeSpent: `${totalHours}h`,
        averageTime: `${averageHours}hrs`,
        productivity: parseFloat(row.productivity).toFixed(1) + '%'
      };
    });

    res.json(skillmanData);
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to fetch skillman data' });
  }
});








// POST endpoint to retrieve complaints for a specific skillman with filters
app.post('/api/retrieve-complaints-for-one-skillman', async (req, res) => {
  const pageAccess = 'skillman-report';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res.status(401).json({
        error: 'Unauthorized - Invalid token. Please login again.'
      });
    }

    const { skillmanName, status, type, fromDate, toDate } = req.body;

    if (!skillmanName) {
      return res.status(400).json({ error: 'Skillman name is required' });
    }

    // Build base query
    let query = `
      SELECT 
        c.complaint_id,
        DATE_FORMAT(c.launched_at, '%Y-%m-%d') as launched_date,
        DATE_FORMAT(c.completed_at, '%Y-%m-%d') as completion_date,
        c.nature as category,
        l.building_number as building,
        u.name as launched_by,
        cust.full_name as customer,
        c.status,
        CASE 
          WHEN c.assigned_at IS NOT NULL AND c.completed_at IS NOT NULL 
          THEN ROUND(TIMESTAMPDIFF(SECOND, c.assigned_at, c.completed_at) / 3600.0, 2)
          ELSE NULL 
        END as hours_taken,
        DATE_FORMAT(c.assigned_at, '%Y-%m-%d %H:%i:%s') as assigned_time,
        DATE_FORMAT(c.completed_at, '%Y-%m-%d %H:%i:%s') as completed_time,
        c.launched_at
      FROM Complaints c
      INNER JOIN Skillmen s ON c.skillman_id = s.id
      INNER JOIN Users u ON c.receiver_id = u.id
      INNER JOIN Customers cust ON c.customer_id = cust.customer_id
      INNER JOIN Location l ON c.location_id = l.location_id
      INNER JOIN Colonies col ON l.colony_number = col.ColonyNumber
      WHERE s.name = ?
        AND c.status NOT IN ('Deferred', 'SNA')
    `;

    const params = [skillmanName];

    if (status) {
      query += ` AND c.status = ?`;
      params.push(status);
    }

    if (type) {
      query += ` AND c.type = ?`;
      params.push(type);
    }

    if (fromDate) {
      query += ` AND c.launched_at >= ?`;
      params.push(fromDate);
    }

    if (toDate) {
      const nextDay = new Date(toDate);
      nextDay.setDate(nextDay.getDate() + 1);
      query += ` AND c.launched_at < ?`;
      params.push(nextDay.toISOString().split('T')[0]); // Format as YYYY-MM-DD
    }

    query += ` ORDER BY c.launched_at DESC`;

    const [result] = await pool.query(query, params);

    // Hide raw launched_at
    const cleanedResults = result.map(({ launched_at, ...rest }) => rest);

    res.json(cleanedResults);
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});








async function runQuery(query, params = []) {
  try {
    const pool = await initDb(); // Use the existing connection pool
    
    // Execute query with parameters
    const [rows, fields] = await pool.query(query, params);
    
    // Return in similar format to MSSQL for compatibility
    return { 
      recordset: rows, 
      rowsAffected: fields ? fields.affectedRows : 0 
    };
  } catch (error) {
    console.error('Query execution error:', error);
    throw error;
  }
}









// daily-complaints
app.get('/api/complaints/daily-stats', async (req, res) => {
  const pageAccess = 'daily-report';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res
        .status(401)
        .json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
  } catch (error) {
    console.error('Token validation error:', error);
    return res.status(500).json({ error: 'Database error while checking token' });
  }

  const date = req.query.date || new Date().toISOString().split('T')[0];
  const page = parseInt(req.query.page) || 1;
  const pageSize = parseInt(req.query.pageSize) || 10;
  const offset = (page - 1) * pageSize;

  try {
    // 1️⃣ Status by Category
    const statusResult = await runQuery(
      `
      SELECT 
        category AS Category,
        SUM(CASE WHEN status = 'Un-Assigned' THEN 1 ELSE 0 END) AS unassigned,
        SUM(CASE WHEN status = 'In-Progress' THEN 1 ELSE 0 END) AS inProgress,
        SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed,
        SUM(CASE WHEN status = 'Deferred' THEN 1 ELSE 0 END) AS deferred,
        COUNT(*) AS total
      FROM Complaints
      WHERE DATE(launched_at) = DATE(?)
      GROUP BY category
      `,
      [date]
    );

    const statusLabels = statusResult.recordset.map(r => r.Category);
    const statusByCategory = {
      labels: statusLabels,
      datasets: [
        { label: 'Unassigned', data: statusResult.recordset.map(r => r.unassigned), backgroundColor: '#e74c3c' },
        { label: 'In-Progress', data: statusResult.recordset.map(r => r.inProgress), backgroundColor: '#f39c12' },
        { label: 'Completed', data: statusResult.recordset.map(r => r.completed), backgroundColor: '#2ecc71' },
        { label: 'Deferred', data: statusResult.recordset.map(r => r.deferred), backgroundColor: '#9b59b6' }
      ]
    };

    // 2️⃣ Category Ratio
    const categoryRatio = {
      labels: statusLabels,
      data: statusResult.recordset.map(r => r.total)
    };

    // 3️⃣ Priority Table
    const priorityResult = await runQuery(
      `
      SELECT 
        category,
        SUM(CASE WHEN priority = 'immediate' THEN 1 ELSE 0 END) AS immediate,
        SUM(CASE WHEN priority = 'urgent' THEN 1 ELSE 0 END) AS urgent,
        SUM(CASE WHEN priority = 'routine' THEN 1 ELSE 0 END) AS routine,
        SUM(CASE WHEN priority = 'deferred' THEN 1 ELSE 0 END) AS deferred,
        COUNT(*) AS total
      FROM Complaints
      WHERE DATE(launched_at) = DATE(?)
      GROUP BY category
      ORDER BY category
      `,
      [date]
    );

    // 4️⃣ Productivity Chart
    const productivityResult = await runQuery(
      `
      SELECT 
        priority,
        SUM(CASE WHEN status = 'Un-Assigned' THEN 1 ELSE 0 END) AS unassigned,
        SUM(CASE WHEN status = 'In-Progress' THEN 1 ELSE 0 END) AS inProgress,
        SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed,
        SUM(CASE WHEN status = 'Deferred' THEN 1 ELSE 0 END) AS deferred,
        COUNT(*) AS total
      FROM Complaints
      WHERE DATE(launched_at) = DATE(?)
      GROUP BY priority
      ORDER BY 
        CASE 
          WHEN priority = 'immediate' THEN 1
          WHEN priority = 'urgent' THEN 2
          WHEN priority = 'routine' THEN 3
          WHEN priority = 'deferred' THEN 4
          ELSE 5
        END
      `,
      [date]
    );

    const productivityData = {
      labels: productivityResult.recordset.map(r => r.priority),
      datasets: [
        { label: 'Unassigned', data: productivityResult.recordset.map(r => r.unassigned), backgroundColor: '#e74c3c' },
        { label: 'In-Progress', data: productivityResult.recordset.map(r => r.inProgress), backgroundColor: '#f39c12' },
        { label: 'Completed', data: productivityResult.recordset.map(r => r.completed), backgroundColor: '#2ecc71' },
        { label: 'Deferred', data: productivityResult.recordset.map(r => r.deferred), backgroundColor: '#9b59b6' }
      ]
    };

    // 5️⃣ Deferred Complaints List
    const deferredResult = await runQuery(
      `
      SELECT 
        c.category AS Category,
        DATE_FORMAT(c.launched_at, '%Y-%m-%d') AS Date,
        c.complaint_id AS ComplaintNo,
        CONCAT(COALESCE(col.Name, 'Unknown'), ', ', COALESCE(loc.building_number, 'N/A')) AS Address,
        c.nature AS Nature,
        c.type AS Type,
        TIMESTAMPDIFF(HOUR, c.launched_at, NOW()) AS Hours
      FROM Complaints c
      LEFT JOIN Location loc ON c.location_id = loc.location_id
      LEFT JOIN Colonies col ON loc.colony_number = col.ColonyNumber
      WHERE c.status = 'Deferred'
        AND DATE(c.launched_at) = DATE(?)
      ORDER BY c.launched_at DESC
      LIMIT ? OFFSET ?
      `,
      [date, pageSize, offset]
    );

    const deferredCountResult = await runQuery(
      `
      SELECT COUNT(*) AS totalCount
      FROM Complaints
      WHERE status = 'Deferred'
        AND DATE(launched_at) = DATE(?)
      `,
      [date]
    );

    const totalDeferred = deferredCountResult.recordset[0].totalCount;

    res.json({
      success: true,
      statusByCategory,
      categoryRatio,
      productivityData,
      tables: {
        statusTable: statusResult.recordset,
        priorityTable: priorityResult.recordset,
        deferredTable: deferredResult.recordset
      },
      pagination: {
        page,
        pageSize,
        total: totalDeferred,
        totalPages: Math.ceil(totalDeferred / pageSize)
      }
    });
  } catch (err) {
    console.error('❌ Database error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});









// Dashboard APIs

// Endpoint to get monthly complaints data for the current year
app.get('/api/monthly-complaints', async (req, res) => {
  const pageAccess = 'dashboard';
  // 🔑 Verify Authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res
        .status(401)
        .json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    // Get current year
    const currentYear = new Date().getFullYear();

    // Step 2: Fetch complaints grouped by month + status
    const [result] = await pool.query(`
      SELECT 
        MONTH(launched_at) AS month,
        status,
        COUNT(*) AS count
      FROM Complaints
      WHERE YEAR(launched_at) = ?
      GROUP BY MONTH(launched_at), status
      ORDER BY month, status
    `, [currentYear]);

    // Step 3: Initialize arrays (12 months each)
    const monthlyData = {
      pending: new Array(12).fill(0),
      inprogress: new Array(12).fill(0),
      completed: new Array(12).fill(0)
    };

    // Step 4: Map results into arrays
    result.forEach(row => {
      const monthIndex = row.month - 1; // convert 1–12 → 0–11

      switch (row.status) {
        case 'Un-Assigned':
        case 'Deferred':
        case 'SNA':
          monthlyData.pending[monthIndex] += row.count; // += just in case multiple statuses map to pending
          break;
        case 'In-Progress':
          monthlyData.inprogress[monthIndex] += row.count;
          break;
        case 'Completed':
          monthlyData.completed[monthIndex] += row.count;
          break;
      }
    });

    // Step 5: Send result
    res.json(monthlyData);

  } catch (error) {
    console.error('Error fetching monthly complaints data:', error);
    res.status(500).json({ error: 'Failed to fetch monthly complaints data' });
  }
});








// Category complaints endpoint
app.get('/api/category-complaints', async (req, res) => {
  const pageAccess = 'dashboard';
  // 🔑 Verify Authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query('SELECT id FROM Users WHERE token = ?', [token]);

    if (tokenCheck.length === 0) {
      return res
        .status(401)
        .json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    // Step 2: Get all subdivisions
    const [subdivisionsResult] = await pool.query('SELECT name FROM Subdivision');
    const subdivisions = subdivisionsResult.map(row => row.name);

    // Step 3: Get complaint counts by category + status
    const [result] = await pool.query(`
      SELECT 
        category, 
        COUNT(*) AS count,
        status
      FROM Complaints 
      WHERE category IS NOT NULL
      GROUP BY category, status
    `);

    // Step 4: Initialize counts for all categories
    const categoryCounts = {};
    subdivisions.forEach(category => {
      categoryCounts[category] = {
        InProgress: 0,
        Completed: 0,
        Deferred: 0,
        UnAssigned: 0,
        SNA: 0
      };
    });

    // Step 5: Process query results into our structure
    result.forEach(row => {
      let statusKey = row.status.replace('-', ''); // "In-Progress" → "InProgress"
      if (statusKey.toLowerCase() === 'deffered') statusKey = 'Deferred'; // fix typo handling

      if (categoryCounts[row.category]) {
        categoryCounts[row.category][statusKey] = row.count;
      }
    });

    // Step 6: Final format for frontend
    const categoryData = subdivisions.map(category => {
      const counts = categoryCounts[category];
      const total = Object.values(counts).reduce((sum, count) => sum + count, 0);

      return {
        name: category,
        value: total,
        details: counts
      };
    });

    res.json(categoryData);

  } catch (error) {
    console.error('Error fetching category complaints:', error);
    res.status(500).json({ error: 'Failed to fetch category complaints data' });
  }
});







// Nature complaints endpoint
app.get('/api/nature-complaints', async (req, res) => {
  const pageAccess = 'dashboard';
  // 🔑 Verify Authorization header
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res
        .status(401)
        .json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }

    // Step 2: Get all natures
    const [naturesResult] = await pool.query('SELECT name FROM Natures');
    const natures = naturesResult.map(row => row.name);

    // Step 3: Get complaint counts by nature + status
    const [result] = await pool.query(`
      SELECT 
        nature, 
        COUNT(*) AS count,
        status
      FROM Complaints 
      WHERE nature IS NOT NULL
      GROUP BY nature, status
    `);

    // Step 4: Initialize counts for all natures
    const natureCounts = {};
    natures.forEach(nature => {
      natureCounts[nature] = {
        InProgress: 0,
        Completed: 0,
        Deferred: 0,
        UnAssigned: 0,
        SNA: 0
      };
    });

    // Step 5: Process results into our structure
    result.forEach(row => {
      let statusKey = row.status.replace('-', ''); // "In-Progress" → "InProgress"
      if (statusKey.toLowerCase() === 'deffered') statusKey = 'Deferred'; // normalize typo

      if (natureCounts[row.nature]) {
        natureCounts[row.nature][statusKey] = row.count;
      }
    });

    // Step 6: Final format
    const natureData = natures.map(nature => {
      const counts = natureCounts[nature];
      const total = Object.values(counts).reduce((sum, count) => sum + count, 0);

      return {
        name: nature,
        value: total,
        details: counts
      };
    });

    res.json(natureData);

  } catch (error) {
    console.error('Error fetching nature complaints:', error);
    res.status(500).json({ error: 'Failed to fetch nature complaints data' });
  }
});









app.get('/api/stats', async (req, res) => {
  const pageAccess = 'dashboard';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
  } catch(error) {
    console.error('Error: ' + error);
    return res.status(500).json({ error: 'Internal server error during authentication' });
  }

  try {
    // Connect to the database
    const pool = await initDb();
    
    // Execute all count queries in parallel
    const [coloniesResult, customersResult, apartmentsResult, skillmenResult] = await Promise.all([
      pool.query('SELECT COUNT(*) as count FROM Colonies'),
      pool.query('SELECT COUNT(*) as count FROM Customers'),
      pool.query(`SELECT COUNT(*) as count FROM Location WHERE resdl = 'Resdl'`),
      pool.query(`SELECT COUNT(*) as count FROM Skillmen`)
    ]);
    
    // Extract counts from results (MySQL returns array of rows)
    const coloniesCount = coloniesResult[0][0].count;
    const customersCount = customersResult[0][0].count;
    const apartmentsCount = apartmentsResult[0][0].count;
    const skillmenCount = skillmenResult[0][0].count;
    
    // Send the response
    res.json({
      colonies: coloniesCount,
      customers: customersCount,
      apartments: apartmentsCount,
      skillman: skillmenCount
    });
    
  } catch (error) {
    console.error('Database query error:', error);
    res.status(500).json({ 
      error: 'Failed to fetch statistics',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});








app.get("/api/get-categories-for-dashboard", async (req, res) => {
  const pageAccess = 'dashboard';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
  } catch(error) {
    console.error('Error: ' + error);
    return res.status(500).json({ error: 'Internal server error during authentication' });
  }

  try {
    const pool = await initDb(); // Changed from sql.connect(dbConfig) to use your existing initDb()
    const [result] = await pool.query("SELECT ColonyNumber, Name FROM Colonies");

    res.json(result);
  } catch (err) {
    console.error("Error fetching colonies:", err);
    res.status(500).json({ error: "Database error" });
  }
});







// Categories endpoint
app.get('/get-categories-for-dashboard', async (req, res) => {
  const pageAccess = 'dashboard';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    // Use the existing connection pool
    const pool = await initDb(); // reuse the pool instead of creating a new connection
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }
    
    // Query the Natures table using the pool
    const [result] = await pool.query('SELECT name FROM Natures ORDER BY name');
    
    // Format the results and encode the values
    const categories = result.map(row => {
      const encodedName = encodeURIComponent(row.name);
      return {
        id: encodedName,
        name: encodedName
      };
    });
    
    // Send response
    res.json(categories);
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});









app.get('/api/complaints-summary-count', async (req, res) => {
  const pageAccess = 'dashboard';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  let pool; // Declare pool variable outside try blocks for finally access
  
  try {
    pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
  } catch(error) {
    console.error('Error: ' + error);
    return res.status(500).json({ error: 'Internal server error during authentication' });
  }

  try {
    // Use the existing pool (no need to create a new one)
    const [result] = await pool.query(`
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN status IN ('Un-Assigned') THEN 1 ELSE 0 END) AS unassigned,
        SUM(CASE WHEN status IN ('In-Progress', 'Deferred', 'SNA') THEN 1 ELSE 0 END) AS inprogress,
        SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed
      FROM Complaints
    `);

    const stats = result[0]; // MySQL returns array of rows, get first row

    res.json({
      total: stats.total,
      unassigned: stats.unassigned,
      inprogress: stats.inprogress,
      completed: stats.completed
    });

  } catch (error) {
    console.error('Error fetching complaints summary:', error);
    res.status(500).json({ error: 'Failed to fetch complaints summary' });
  } finally {
    // Note: With connection pools, you typically don't close the pool after each request
    // The pool manages connections automatically
    // If you need to close the pool, you would do it when shutting down the application
  }
});










app.get('/api/trends-data', async (req, res) => {
  const pageAccess = 'dashboard';
  // Verify Authorization header exists
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const pool = await initDb();
    const accessiblity = await checkAccess(token, pageAccess, pool);
    if (accessiblity.status !== 'success') {
      return res.status(401).json({ error: 'Unauthorized - Invalid token please login again.' });
    }

    // Step 1: Verify token exists in Users table
    const [tokenCheck] = await pool.query(
      'SELECT id FROM Users WHERE token = ?',
      [token]
    );

    if (tokenCheck.length === 0) {
      return res.status(401).json({ error: 'Unauthorized - Invalid token. Please login again.' });
    }
  } catch(error) {
    console.error('Error: ' + error);
    return res.status(500).json({ error: 'Internal server error during authentication' });
  }

  try {
    const { colony, category } = req.query;
    
    // Decode the parameters if they were encoded
    const decodedColony = colony ? decodeURIComponent(Buffer.from(colony, 'base64').toString()) : '';
    const decodedCategory = category ? decodeURIComponent(Buffer.from(category, 'base64').toString()) : '';
    
    // Connect to the database
    const pool = await initDb();
    
    // Build the query with parameters
    let query = `
      SELECT 
        MONTH(c.launched_at) as month,
        c.status,
        COUNT(*) as count
      FROM Complaints c
      INNER JOIN Location l ON c.location_id = l.location_id
      WHERE c.launched_at >= DATE_SUB(NOW(), INTERVAL 11 MONTH)
    `;
    
    // Add parameters
    const params = [];
    const values = [];
    
    if (decodedColony) {
      query += ` AND l.colony_number = ?`;
      params.push('colony');
      values.push(decodedColony);
    }
    
    if (decodedCategory) {
      query += ` AND c.category = ?`;
      params.push('category');
      values.push(decodedCategory);
    }
    
    query += `
      GROUP BY MONTH(c.launched_at), c.status
      ORDER BY MONTH(c.launched_at), c.status
    `;
    
    // Execute the query with parameters
    const [result] = await pool.query(query, values);
    
    // Initialize data structure
    const trendsData = {
      categories: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
      pending: new Array(12).fill(0),
      inprogress: new Array(12).fill(0),
      completed: new Array(12).fill(0)
    };
    
    // Process the results
    result.forEach(row => {
      const monthIndex = row.month - 1; // Convert to 0-based index
      const status = row.status.toLowerCase().replace('-', '');
      const count = row.count;
      
      if (status === 'unassigned') {
        trendsData.pending[monthIndex] += count;
      } else if (status === 'inprogress' || status === 'deferred' || status === 'sna') {
        trendsData.inprogress[monthIndex] += count;
      } else if (status === 'completed') {
        trendsData.completed[monthIndex] += count;
      }
    });
    
    res.json(trendsData);
    
  } catch (error) {
    console.error('Error fetching trends data:', error);
    res.status(500).json({ error: 'Failed to fetch trends data' });
  } 
});




















// Handle database pool errors
if (pool) {
  pool.on('error', (err) => {
    console.error('MySQL pool error:', err);
  });
}

// Handle graceful shutdown
process.on('SIGINT', async () => {
  if (pool) {
    await pool.end(); // use .end() instead of .close() for mysql2
    console.log('Database pool closed');
  }
  process.exit();
});



module.exports = {
  initDb,
  dbConfig
};


// Start the server
// app.listen(port, () => {
//   console.log(`Server running on http://localhost:${port}`);
// });

// https.createServer(httpsOptions, app).listen(port, () => {
//   console.log(`HTTPS server running at https://192.168.100.4:${port}`);
// });


// const allowedIPs = [
// ];

// app.use((req, res, next) => {
//   const clientIP = req.ip.replace('::ffff:', ''); // normalize

//   if (!allowedIPs.includes(clientIP)) {
//     return res.status(403).send('Access denied');
//   }

//   next();
// });


// https.createServer(httpsOptions, app).listen(port, '0.0.0.0', () => {
//   console.log(`HTTPS server running at https://192.168.100.4:${port}`);
// });

//--------------------------------------ip whitelisting
const allowedIPs = ['192.168.137.1', '10.4.3.250', '127.0.0.1', '::1'];
//const allowedIPs = [];

const server = https.createServer(httpsOptions, (req, res) => {
  const clientIP = req.socket.remoteAddress.replace('::ffff:', '');

  if (!allowedIPs.includes(clientIP)) {
    res.writeHead(403);
    return res.end("Access denied");
  }
  app(req, res);
});

server.listen(port, '0.0.0.0', () => {
  console.log(`HTTPS server running at https://davydjones.self`);
});
