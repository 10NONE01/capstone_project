# capstone_project

# SecureAuto — FIU Cybersecurity Capstone

SecureAuto is a web application developed for our FIU Cybersecurity Capstone project. It demonstrates backend authentication, password hashing, database management, and Role-Based Access Control (RBAC).

The application includes three types of users: **Customer, Mechanic, and Admin**. Each role has different permissions and dashboard functions.

## 1. What You Need Before Starting

Before running SecureAuto, you need two free programs installed on your computer.

### Visual Studio Code (VS Code)

VS Code is the program we use to open and edit the project files. You do not need prior experience with it.

Download: https://code.visualstudio.com/

Install it using the default installation options.

### Node.js

Node.js allows your computer to run the backend server. The backend handles user logins, database requests, and security permissions.

Download: https://nodejs.org/

Install a current **LTS (Long-Term Support)** version that supports `node:sqlite` and the `--env-file` option (Node.js 22.13 or later).

Node.js also includes **npm**, which is used to install the packages our application needs.

After installation, restart VS Code if it was already open.

## 2. Download the Project from GitHub

Open our GitHub repository:

https://github.com/10NONE01/capstone_project

Make sure the **main** branch is selected.

1. Click the green **Code** button.
2. Select **Download ZIP**.
3. Locate the downloaded ZIP file.
4. Right-click it and select **Extract All** on Windows, or extract it using your operating system's file manager.
5. Open the extracted project folder.

You do not need a GitHub account just to download a public repository.

## 3. Open the Project in VS Code

1. Open Visual Studio Code.
2. Click **File → Open Folder**.
3. Select the extracted `capstone_project` folder.
4. Click **Select Folder** or **Open**.
5. If VS Code asks whether you trust the folder, choose **Yes** after confirming it came from our project repository.

You should now see project files such as `server.js`, `package.json`, `public/`, `database/`, and `scripts/` on the left side.

## 4. Open the Terminal

A terminal is a place where you type commands to run programs.

In VS Code:

1. Click **Terminal** in the top menu.
2. Select **New Terminal**.
3. A terminal panel will appear at the bottom of the screen.

Make sure the terminal is opened inside the project folder containing `package.json`.

To verify Node.js was installed correctly, type:

```bash
node --version
```

Then type:

```bash
npm --version
```

Both commands should display version numbers.

If either command is not recognized, check the Node.js installation and restart VS Code.

## 5. Install the Project Dependencies

In the terminal, type:

```bash
npm install
```

Press Enter.

**What does this do?**

npm reads `package.json` and downloads the libraries needed by SecureAuto, including Express and Express Session.

It automatically creates a folder called `node_modules/`.

You only need to run this again when setting up a new copy or when project dependencies change.

Wait until the terminal finishes and returns to the command prompt.

## 6. Configure the Session Secret

SecureAuto uses a session secret to protect login sessions. This value is stored locally rather than shared through GitHub.

In the main project folder, create a new file named:

`.env`

Open your VS Code terminal and generate a random secret:

```bash
node -e 'console.log(require("node:crypto").randomBytes(32).toString("hex"))'
```

Copy the generated value.

Inside `.env`, add:

```dotenv
SESSION_SECRET=PASTE_YOUR_GENERATED_SECRET_HERE
```

Replace the placeholder with your generated secret and save the file.

Do not add spaces around the `=` symbol.

The `.env` file should remain private and should not be uploaded to GitHub.

## 7. Start the SecureAuto Website

In the VS Code terminal, enter:

```bash
npm start
```

Press Enter.

If everything is configured correctly, you should see a message similar to:

```text
Server running at http://127.0.0.1:4100
```

This means your computer is now running the SecureAuto backend server.

**Important:** Keep the terminal open while using the website. Closing it or stopping the process will shut down the server.

## 8. Open the Website

Open Google Chrome, Firefox, or another web browser.

Enter:

http://127.0.0.1:4100

You should see the SecureAuto homepage.

To access the login page directly, visit:

http://127.0.0.1:4100/login.html

The website runs locally on your computer. It is not hosted on a public server.

## 9. Demo Login Credentials

The database contains fictional accounts created for testing the application's authentication and RBAC functionality.

| Role | Email | Password |
|---|---|---|
| Customer | customer@demo.invalid | [Customer demo password] |
| Mechanic | mechanic@demo.invalid | [Mechanic demo password] |
| Admin | admin@demo.invalid | [Admin demo password] |

Replace the password placeholders with the corresponding demonstration passwords.

### Testing Different Roles

**Customer:** Log in using the customer credentials. The dashboard should display customer-related features, including access to the customer's own appointments and information.

**Mechanic:** Log out and sign in with the mechanic credentials. The dashboard should display functions intended for mechanics, including authorized service-request information.

**Admin:** Log out and sign in using the admin account. This role is intended for administrative functionality and additional application management features.

Some dashboard functionality is still being developed.

## 10. Cybersecurity Features

SecureAuto demonstrates several security concepts covered in our cybersecurity studies.

### Password Hashing

User passwords are stored as password hashes in SQLite instead of plaintext.

This helps protect passwords from direct disclosure if the database is compromised. Password hashes must still be protected because attackers may attempt to crack them.

### Authentication

The backend verifies login credentials before granting access to authenticated functionality.

### Role-Based Access Control (RBAC)

The application assigns permissions based on user roles.

For example, customers should not be able to access another customer's private appointments or mechanic-only functionality.

Authorization is enforced by backend routes rather than relying solely on the appearance of the dashboard.

### Session Management

Express Session is used to maintain authenticated user sessions.

A locally configured `SESSION_SECRET` helps protect session integrity.

## 11. How to Stop the Server

When you finish testing the application:

1. Return to the VS Code terminal.
2. Press **Ctrl + C**.
3. The server will stop.

To run the website again later, open the project folder, open the terminal, and type:

```bash
npm start
```

You do not normally need to run `npm install` every time.

## 12. Troubleshooting

### "npm is not recognized"

Make sure Node.js is installed. Restart VS Code and try again.

### "SESSION_SECRET is missing"

Make sure `.env` is saved in the main project folder and contains a valid `SESSION_SECRET` value.

### "Cannot find module"

Run:

```bash
npm install
```

Then try `npm start` again.

### "Address already in use"

The server may already be running in another terminal.

Stop the previous instance using Ctrl + C before starting a new one.

### Login does not work

Check that you entered the correct demo email, password, and selected role.

The included demo database must also contain the corresponding user accounts.

Do not run database initialization or account seeding scripts unless instructed, because those utilities may change the existing demo database.

## 13. Project Status

SecureAuto is currently a Capstone prototype.

The team is continuing to improve the application, including additional dashboard functionality, service-request management, RBAC testing, audit logging, and security documentation.

**This project uses fictional demonstration data and is not intended for production use.**