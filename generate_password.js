// generate_password.js

const bcrypt = require('bcryptjs');

async function generatePasswordHash(password) {
    try {
        const saltRounds = 12;
        const hash = await bcrypt.hash(password, saltRounds);
        console.log(`Password: ${password}`);
        console.log(`Hash: ${hash}`);
        console.log('\nSQL to add user:');
        console.log(`INSERT INTO users (username, email, password_hash, full_name, role, is_active) VALUES ('username', 'email@company.com', '${hash}', 'Full Name', 'user', TRUE);`);
    } catch (error) {
        console.error('Error generating hash:', error);
    }
}

// Get password from command line argument
const password = process.argv[2];

if (!password) {
    console.log('Usage: node generate_password.js <password>');
    process.exit(1);
}

console.log('Generating password hash...\n');
generatePasswordHash(password);

// node generate_password.js myNewPassword123