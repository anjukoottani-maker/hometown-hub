const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'hometown_hub_secret_key';

// Middleware to parse JSON and serve frontend files
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 1. DATABASE SETUP (SQLite - Auto Creates File)
// ==========================================
const db = new sqlite3.Database('./hometown.db');

db.serialize(() => {
  // Users Table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    hometown TEXT,
    current_city TEXT,
    role TEXT DEFAULT 'USER'
  )`);

  // Communities Table (status: PENDING or APPROVED)
  db.run(`CREATE TABLE IF NOT EXISTS communities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    city_village TEXT,
    description TEXT,
    rules TEXT DEFAULT '1. Be respectful. 2. Keep posts relevant to our hometown.',
    status TEXT DEFAULT 'PENDING',
    created_by INTEGER
  )`);

  // Memberships Table (role: MEMBER or MODERATOR, status: PENDING or APPROVED)
  db.run(`CREATE TABLE IF NOT EXISTS memberships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    community_id INTEGER,
    role TEXT DEFAULT 'MEMBER',
    status TEXT DEFAULT 'PENDING',
    UNIQUE(user_id, community_id)
  )`);

  // Posts Table
  db.run(`CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    community_id INTEGER,
    author_id INTEGER,
    category TEXT,
    content TEXT,
    image_url TEXT,
    is_pinned INTEGER DEFAULT 0,
    likes INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Comments Table
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER,
    author_id INTEGER,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Events Table
  db.run(`CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    community_id INTEGER,
    title TEXT,
    event_date TEXT,
    location TEXT,
    description TEXT,
    attendees INTEGER DEFAULT 0
  )`);

  // Reports Table (For Platform Admin)
  db.run(`CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER,
    reporter_name TEXT,
    reason TEXT,
    status TEXT DEFAULT 'OPEN'
  )`);
});

// ==========================================
// 2. AUTHENTICATION MIDDLEWARE
// ==========================================
function verifyUser(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Please log in first' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid session' });
    req.user = user;
    next();
  });
}

// ==========================================
// 3. USER AUTH ROUTES (Register & Login)
// ==========================================
app.post('/api/register', (req, res) => {
  const { name, email, password, hometown, current_city } = req.body;
  const hashed = bcrypt.hashSync(password, 8);

  // First user registered becomes PLATFORM_ADMIN automatically
  db.get('SELECT COUNT(*) as count FROM users', (err, row) => {
    const role = row.count === 0 ? 'PLATFORM_ADMIN' : 'USER';

    db.run(
      'INSERT INTO users (name, email, password, hometown, current_city, role) VALUES (?, ?, ?, ?, ?, ?)',
      [name, email, hashed, hometown, current_city, role],
      function (err) {
        if (err) return res.status(400).json({ error: 'Email already registered' });
        const token = jwt.sign({ id: this.lastID, name, role, hometown }, SECRET_KEY);
        res.json({ token, user: { id: this.lastID, name, email, hometown, current_city, role } });
      }
    );
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const token = jwt.sign(
      { id: user.id, name: user.name, role: user.role, hometown: user.hometown },
      SECRET_KEY
    );
    res.json({
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        hometown: user.hometown,
        current_city: user.current_city,
        role: user.role,
      },
    });
  });
});

// ==========================================
// 4. COMMUNITY ROUTES (Search, Create, Join)
// ==========================================
app.get('/api/communities', (req, res) => {
  const search = `%${req.query.q || ''}%`;
  db.all(
    `SELECT c.*, (SELECT COUNT(*) FROM memberships WHERE community_id = c.id AND status = 'APPROVED') as member_count 
     FROM communities c 
     WHERE status = 'APPROVED' AND (name LIKE ? OR city_village LIKE ?)`,
    [search, search],
    (err, rows) => res.json(rows || [])
  );
});

// Community Onboarding Request
app.post('/api/communities', verifyUser, (req, res) => {
  const { name, city_village, description } = req.body;
  const status = req.user.role === 'PLATFORM_ADMIN' ? 'APPROVED' : 'PENDING';

  db.run(
    'INSERT INTO communities (name, city_village, description, status, created_by) VALUES (?, ?, ?, ?, ?)',
    [name, city_village, description, status, req.user.id],
    function (err) {
      const communityId = this.lastID;
      // Creator becomes the Community Moderator
      db.run(
        'INSERT INTO memberships (user_id, community_id, role, status) VALUES (?, ?, ?, ?)',
        [req.user.id, communityId, 'MODERATOR', 'APPROVED']
      );
      res.json({ message: status === 'APPROVED' ? 'Community Created!' : 'Submitted for Admin Approval!' });
    }
  );
});

// Request to Join Community
app.post('/api/communities/:id/join', verifyUser, (req, res) => {
  db.run(
    'INSERT OR IGNORE INTO memberships (user_id, community_id, role, status) VALUES (?, ?, ?, ?)',
    [req.user.id, req.params.id, 'MEMBER', 'PENDING'],
    () => res.json({ message: 'Join request sent to moderator!' })
  );
});

// Get Single Community Details, Posts, Events & Members
app.get('/api/communities/:id', verifyUser, (req, res) => {
  const communityId = req.params.id;

  db.get('SELECT * FROM communities WHERE id = ?', [communityId], (err, community) => {
    db.get(
      'SELECT * FROM memberships WHERE user_id = ? AND community_id = ?',
      [req.user.id, communityId],
      (err, myMembership) => {
        db.all(
          `SELECT p.*, u.name as author_name, u.current_city 
           FROM posts p JOIN users u ON p.author_id = u.id 
           WHERE p.community_id = ? ORDER BY p.is_pinned DESC, p.created_at DESC`,
          [communityId],
          (err, posts) => {
            db.all(
              `SELECT c.*, u.name as author_name FROM comments c JOIN users u ON c.author_id = u.id`,
              (err, allComments) => {
                // Attach comments to their respective posts
                const postsWithComments = (posts || []).map((p) => ({
                  ...p,
                  comments: (allComments || []).filter((c) => c.post_id === p.id),
                }));

                db.all('SELECT * FROM events WHERE community_id = ?', [communityId], (err, events) => {
                  db.all(
                    `SELECT m.*, u.name, u.hometown, u.current_city 
                     FROM memberships m JOIN users u ON m.user_id = u.id 
                     WHERE m.community_id = ?`,
                    [communityId],
                    (err, members) => {
                      res.json({
                        community,
                        myMembership,
                        posts: postsWithComments,
                        events: events || [],
                        members: members || [],
                      });
                    }
                  );
                });
              }
            );
          }
        );
      }
    );
  });
});

// Moderator: Approve Member Request
app.post('/api/memberships/:id/approve', verifyUser, (req, res) => {
  db.run('UPDATE memberships SET status = "APPROVED" WHERE id = ?', [req.params.id], () =>
    res.json({ message: 'Member approved' })
  );
});

// ==========================================
// 5. POSTS, COMMENTS, LIKES & EVENTS ROUTES
// ==========================================
app.post('/api/communities/:id/posts', verifyUser, (req, res) => {
  const { category, content, image_url } = req.body;
  db.run(
    'INSERT INTO posts (community_id, author_id, category, content, image_url) VALUES (?, ?, ?, ?, ?)',
    [req.params.id, req.user.id, category, content, image_url || ''],
    () => res.json({ message: 'Post published!' })
  );
});

app.post('/api/posts/:id/like', verifyUser, (req, res) => {
  db.run('UPDATE posts SET likes = likes + 1 WHERE id = ?', [req.params.id], () =>
    res.json({ message: 'Liked' })
  );
});

app.post('/api/posts/:id/pin', verifyUser, (req, res) => {
  db.run('UPDATE posts SET is_pinned = CASE WHEN is_pinned = 1 THEN 0 ELSE 1 END WHERE id = ?', [req.params.id], () =>
    res.json({ message: 'Toggled pin' })
  );
});

app.delete('/api/posts/:id', verifyUser, (req, res) => {
  db.run('DELETE FROM posts WHERE id = ?', [req.params.id], () => res.json({ message: 'Post deleted' }));
});

app.post('/api/posts/:id/comments', verifyUser, (req, res) => {
  db.run(
    'INSERT INTO comments (post_id, author_id, content) VALUES (?, ?, ?)',
    [req.params.id, req.user.id, req.body.content],
    () => res.json({ message: 'Comment added' })
  );
});

app.post('/api/communities/:id/events', verifyUser, (req, res) => {
  const { title, event_date, location, description } = req.body;
  db.run(
    'INSERT INTO events (community_id, title, event_date, location, description) VALUES (?, ?, ?, ?, ?)',
    [req.params.id, title, event_date, location, description],
    () => res.json({ message: 'Event created!' })
  );
});

app.post('/api/events/:id/rsvp', verifyUser, (req, res) => {
  db.run('UPDATE events SET attendees = attendees + 1 WHERE id = ?', [req.params.id], () =>
    res.json({ message: 'RSVP confirmed!' })
  );
});

app.post('/api/posts/:id/report', verifyUser, (req, res) => {
  db.run(
    'INSERT INTO reports (post_id, reporter_name, reason) VALUES (?, ?, ?)',
    [req.params.id, req.user.name, req.body.reason],
    () => res.json({ message: 'Reported to Admin' })
  );
});

// ==========================================
// 6. PLATFORM ADMIN DASHBOARD ROUTES
// ==========================================
app.get('/api/admin', verifyUser, (req, res) => {
  if (req.user.role !== 'PLATFORM_ADMIN') return res.status(403).json({ error: 'Admin only' });

  db.all('SELECT * FROM communities WHERE status = "PENDING"', (err, pendingCommunities) => {
    db.all('SELECT * FROM reports WHERE status = "OPEN"', (err, reports) => {
      db.get('SELECT COUNT(*) as users FROM users', (err, u) => {
        db.get('SELECT COUNT(*) as communities FROM communities WHERE status = "APPROVED"', (err, c) => {
          db.get('SELECT COUNT(*) as posts FROM posts', (err, p) => {
            db.get('SELECT COUNT(*) as events FROM events', (err, e) => {
              res.json({
                kpis: { users: u.users, communities: c.communities, posts: p.posts, events: e.events },
                pendingCommunities: pendingCommunities || [],
                reports: reports || [],
              });
            });
          });
        });
      });
    });
  });
});

app.post('/api/admin/communities/:id/approve', verifyUser, (req, res) => {
  db.run('UPDATE communities SET status = "APPROVED" WHERE id = ?', [req.params.id], () =>
    res.json({ message: 'Community Approved!' })
  );
});

app.post('/api/admin/reports/:id/resolve', verifyUser, (req, res) => {
  db.run('UPDATE reports SET status = "RESOLVED" WHERE id = ?', [req.params.id], () =>
    res.json({ message: 'Report Resolved!' })
  );
});

// Start Server
app.listen(PORT, () => {
  console.log(`Hometown Hub is running at http://localhost:${PORT}`);
});
