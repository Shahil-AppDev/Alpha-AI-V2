// Test script pour comprendre le protocole WebSocket OpenClaw
const WebSocket = require('ws');

const GATEWAY_URL = 'ws://127.0.0.1:18789';
const TOKEN = '46d0aec7fabdba9ee356c5a8a930f334cc59b2963df620fa8b25e92f9c47ec01';

console.log('Connecting to OpenClaw gateway...');
const ws = new WebSocket(GATEWAY_URL);

ws.on('open', () => {
  console.log('✅ Connected to OpenClaw gateway');
  
  // Test 1: Send connect message with token
  const connectMessage = {
    type: 'connect',
    params: {
      auth: {
        token: TOKEN,
      },
    },
  };
  
  console.log('📤 Sending connect message:', JSON.stringify(connectMessage, null, 2));
  ws.send(JSON.stringify(connectMessage));
});

ws.on('message', (data) => {
  const message = JSON.parse(data.toString());
  console.log('📥 Received message:', JSON.stringify(message, null, 2));
  
  // If we receive a challenge, respond to it
  if (message.type === 'event' && message.event === 'connect.challenge') {
    console.log('🔐 Received challenge, responding with auth...');
    
    // Try responding to the challenge
    const authResponse = {
      type: 'connect.response',
      id: message.id,
      params: {
        auth: {
          token: TOKEN,
        },
        nonce: message.payload?.nonce,
      },
    };
    
    console.log('📤 Sending auth response:', JSON.stringify(authResponse, null, 2));
    ws.send(JSON.stringify(authResponse));
  }
  
  if (message.type === 'event' && message.event === 'connect.authenticated') {
    console.log('✅ Successfully authenticated!');
  }
  
  if (message.type === 'error') {
    console.error('❌ Error:', message.error);
  }
});

ws.on('error', (error) => {
  console.error('❌ WebSocket error:', error.message);
});

ws.on('close', () => {
  console.log('🔌 Disconnected from OpenClaw gateway');
  process.exit(0);
});

// Timeout after 10 seconds
setTimeout(() => {
  console.log('⏱️  Timeout - closing connection');
  ws.close();
}, 10000);
