#!/usr/bin/env node

/**
 * NGrok Auto-Start Script
 * Automatically starts ngrok tunnel on http://localhost:5173
 * This runs whenever you execute: npm run start
 */

const { spawn } = require('child_process');
const path = require('path');
const os = require('os');

// Determine ngrok executable path based on OS
const ngrokPath = path.join(
  os.homedir(),
  'AppData',
  'Local',
  'ngrok',
  'ngrok.exe'
);

console.log('🚀 Starting ngrok tunnel...');
console.log(`📍 Tunnel will expose: http://localhost:5173`);
console.log(`📦 NGrok path: ${ngrokPath}`);
console.log('');

// Start ngrok process
const ngrok = spawn(ngrokPath, ['http', '5173', '--log=stdout'], {
  stdio: 'inherit',
  shell: true
});

// Handle process errors
ngrok.on('error', (err) => {
  console.error('❌ Error starting ngrok:', err.message);
  console.log('');
  console.log('Make sure ngrok is installed at:');
  console.log(ngrokPath);
  console.log('');
  console.log('If not installed, run:');
  console.log('$ProgressPreference = "SilentlyContinue"; Invoke-WebRequest -Uri "https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-windows-amd64.zip" -OutFile "$env:TEMP\\ngrok.zip"; Expand-Archive -Path "$env:TEMP\\ngrok.zip" -DestinationPath "$env:LOCALAPPDATA\\ngrok" -Force;');
  process.exit(1);
});

// Handle process exit
ngrok.on('close', (code) => {
  console.log(`\n⚠️  NGrok tunnel closed with code ${code}`);
});

// Handle parent process termination
process.on('SIGINT', () => {
  console.log('\n\n🛑 Stopping ngrok tunnel...');
  ngrok.kill();
  process.exit(0);
});

process.on('SIGTERM', () => {
  ngrok.kill();
  process.exit(0);
});

console.log('✅ NGrok tunnel started successfully!');
console.log('');
console.log('📋 Once ngrok is running, your app will be available at:');
console.log('   https://[your-ngrok-url].ngrok-free.dev');
console.log('');
console.log('📌 Note: The ngrok URL changes each time you restart.');
console.log('   Update Google OAuth settings with the new URL.');
console.log('');
console.log('Press Ctrl+C to stop all services.');
