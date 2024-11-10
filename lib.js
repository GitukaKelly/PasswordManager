const PasswordManager = require('./password-manager');

// Create a new PasswordManager instance
const manager = new PasswordManager();

// Function to handle user input for adding a password
function addPassword(service, password, masterPassword) {
    manager.addPassword(service, password, masterPassword);
}

// Function to handle user input for getting a password
function getPassword(service, masterPassword) {
    manager.getPassword(service, masterPassword);
}

// Function to handle user input for deleting a password
function deletePassword(service, masterPassword) {
    manager.deletePassword(service, masterPassword);
}

module.exports = { addPassword, getPassword, deletePassword };
