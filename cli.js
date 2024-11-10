const readline = require('readline');
const PasswordManager = require('./password-manager');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

const manager = new PasswordManager();

async function promptMasterPasswordAndAction() {
    // Check if the master password has already been set in the password manager
    if (!manager.masterPasswordHash) {
        // No master password hash file found, prompt to set a new master password
        rl.question('Enter your master password to set it up: ', async (masterPassword) => {
            await manager.init(masterPassword);
            console.log('Master password has been set.');
            await promptAction();  // Await to ensure sequential operations
        });
    } else {
        // Prompt to enter an existing master password to load the manager
        rl.question('Enter your master password to log in: ', async (masterPassword) => {
            try {
                await manager.load(masterPassword);
                console.log('Successfully loaded password manager.');
                await promptAction();  // Await to ensure sequential operations
            } catch (error) {
                console.log("Error:", error.message);
                rl.close();
            }
        });
    }
}

async function promptAction() {
    rl.question('Choose an action (add, get, delete): ', async (action) => {
        if (action === 'add') {
            rl.question('Enter the service name: ', (service) => {
                rl.question('Enter the password: ', async (password) => {
                    await manager.addPassword(service, password);
                    console.log(`Password added for ${service}`);
                    rl.close();
                });
            });
        } else if (action === 'get') {
            rl.question('Enter the service name: ', async (service) => {
                try {
                    const password = await manager.getPassword(service);
                    console.log(`Password for ${service}: ${password}`);
                } catch (error) {
                    console.log(error.message);
                }
                rl.close();
            });
        } else if (action === 'delete') {
            rl.question('Enter the service name: ', async (service) => {
                try {
                    await manager.deletePassword(service);
                    console.log(`Password deleted for ${service}`);
                } catch (error) {
                    console.log(error.message);
                }
                rl.close();
            });
        } else {
            console.log("Invalid action.");
            rl.close();
        }
    });
}

// Start the password manager
promptMasterPasswordAndAction();
