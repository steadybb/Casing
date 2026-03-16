// diagnose.js
const http = require('http');
const os = require('os');
const { exec } = require('child_process');

console.log('\n' + '='.repeat(60));
console.log('🔍 REDIRECTOR PRO - SYSTEM DIAGNOSTIC v4.1.0');
console.log('='.repeat(60));

// Node.js info
console.log('\n📦 NODE.JS ENVIRONMENT:');
console.log(`   Version: ${process.version}`);
console.log(`   Platform: ${process.platform}`);
console.log(`   Architecture: ${process.arch}`);
console.log(`   PID: ${process.pid}`);
console.log(`   Memory Limit: ${process.argv.find(arg => arg.includes('max-old-space-size')) || 'Not set'}`);

// Environment variables
console.log('\n🌍 ENVIRONMENT VARIABLES:');
console.log(`   NODE_ENV: ${process.env.NODE_ENV || '❌ NOT SET'}`);
console.log(`   PORT: ${process.env.PORT || '❌ NOT SET'}`);
console.log(`   HOST: ${process.env.HOST || '0.0.0.0 (default)'}`);
console.log(`   DATABASE_URL: ${process.env.DATABASE_URL ? '✅ Configured' : '❌ Not set'}`);
console.log(`   REDIS_URL: ${process.env.REDIS_URL ? '✅ Configured' : '❌ Not set'}`);
console.log(`   SESSION_SECRET: ${process.env.SESSION_SECRET ? '✅ Configured' : '❌ Not set'}`);
console.log(`   METRICS_API_KEY: ${process.env.METRICS_API_KEY ? '✅ Configured' : '❌ Not set'}`);

// System info
console.log('\n💻 SYSTEM RESOURCES:');
console.log(`   Hostname: ${os.hostname()}`);
console.log(`   OS: ${os.type()} ${os.release()}`);
console.log(`   CPUs: ${os.cpus().length} cores`);
console.log(`   Total Memory: ${Math.round(os.totalmem() / 1024 / 1024)} MB`);
console.log(`   Free Memory: ${Math.round(os.freemem() / 1024 / 1024)} MB`);
console.log(`   Load Average: ${os.loadavg().map(l => l.toFixed(2)).join(', ')}`);
console.log(`   Uptime: ${Math.round(os.uptime() / 60)} minutes`);

// Network interfaces
console.log('\n🌐 NETWORK INTERFACES:');
const nets = os.networkInterfaces();
let hasExternalIPv4 = false;
for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
        if (net.family === 'IPv4') {
            console.log(`   ${name}: ${net.address} ${net.internal ? '(internal)' : '(external)'}`);
            if (!net.internal) hasExternalIPv4 = true;
        }
    }
}

// Check if ports are in use
console.log('\n🔌 PORT AVAILABILITY:');
const portsToCheck = [process.env.PORT || 10000, 3000, 8080, 5000];

const checkPort = (port) => {
    return new Promise((resolve) => {
        const testServer = http.createServer();
        testServer.listen(port, '0.0.0.0')
            .once('listening', () => {
                testServer.close();
                console.log(`   ✅ Port ${port} is AVAILABLE`);
                resolve({ port, available: true });
            })
            .once('error', (err) => {
                if (err.code === 'EADDRINUSE') {
                    console.log(`   ❌ Port ${port} is IN USE`);
                } else if (err.code === 'EACCES') {
                    console.log(`   ⚠️  Port ${port} requires privileges`);
                } else {
                    console.log(`   ❓ Port ${port}: ${err.message}`);
                }
                resolve({ port, available: false, error: err.code });
            });
    });
};

// Run port checks sequentially
(async () => {
    for (const port of portsToCheck) {
        await checkPort(port);
    }

    // Test binding to the actual PORT
    console.log('\n🧪 TESTING PRODUCTION PORT BINDING:');
    const targetPort = process.env.PORT || 10000;
    console.log(`   Attempting to bind to port ${targetPort}...`);
    
    const server = http.createServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ 
            status: 'ok', 
            message: 'Diagnostic server running',
            port: targetPort,
            time: new Date().toISOString()
        }));
    });

    try {
        await new Promise((resolve, reject) => {
            server.listen(targetPort, '0.0.0.0')
                .once('listening', () => {
                    const addr = server.address();
                    console.log(`   ✅ SUCCESS! Bound to ${addr.address}:${addr.port}`);
                    console.log(`   🌐 Test URL: http://localhost:${targetPort}`);
                    console.log(`   📝 Press Ctrl+C to stop the test server`);
                    
                    // Keep running for 10 seconds to allow testing
                    setTimeout(() => {
                        server.close();
                        console.log('\n   Test complete - server closed');
                        process.exit(0);
                    }, 10000);
                    
                    resolve();
                })
                .once('error', (err) => {
                    console.error(`   ❌ FAILED: ${err.message}`);
                    if (err.code === 'EADDRINUSE') {
                        console.error(`   Port ${targetPort} is already in use by another process`);
                    }
                    reject(err);
                });
        });
    } catch (err) {
        console.error('\n❌ Diagnostic failed - port binding issue detected!');
        process.exit(1);
    }
})();
