# Node Auth Starter

This repository provides a simple and functional **login and authentication system** built using **Node.js**, **Express**, and **MongoDB** (or your choice of database). It's a great starting point for adding user authentication to any Node-based application.

## 🔐 Features

- 🧑‍💻 User registration and login
- 🔑 Password hashing with bcrypt
- 🛡 Session or token-based authentication
- ✅ Input validation and error handling
- 🌐 RESTful API structure (extendable)

## 🧰 Tech Stack

- Node.js
- Express.js
- MongoDB (via Mongoose)
- bcrypt (for password hashing)
- (Optional) JWT or express-session

## 📁 Folder Structure

```
.
├── src/
│   ├── routes/           # Auth routes (login, register)
│   ├── controllers/      # Request handlers
│   ├── models/           # User model
│   └── index.js          # Main app entry point
├── config/               # DB config and env setup
├── package.json
└── README.md
```

## ⚙️ Getting Started

1. **Clone the repository**
   ```bash
   git clone https://github.com/rkd1989/node-auth-starter.git
   cd node-auth-starter
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   - Create a `.env` file:
     ```
     MONGO_URI=mongodb://localhost:27017/authdb
     JWT_SECRET=your_secret_key
     ```

4. **Start the server**
   ```bash
   node src/index.js
   ```

## 🌐 Sample Routes

```
POST /register
POST /login
GET /profile (protected)
```

## ✅ Use Cases

- Quick start for authentication in any Node app
- Educational reference for beginners
- Base layer for building a full-stack application

## 🤝 Contribute

Feel free to fork the repo, customize it, or submit a PR with improvements!

## 📄 License

This project is licensed under the MIT License.

> Maintained by [@rkd1989](https://github.com/rkd1989)
