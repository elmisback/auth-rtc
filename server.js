import { createServer } from 'https';
import { readFileSync } from 'fs';
import { WebSocketServer } from 'ws';

const server = createServer({
  cert: readFileSync('/etc/letsencrypt/live/auth-rtc.strcat.xyz/fullchain.pem'),
  key: readFileSync('/etc/letsencrypt/live/auth-rtc.strcat.xyz/privkey.pem')
});

const wss1 = new WebSocketServer({ noServer: true, maxPayload: 1024 });
const wss2 = new WebSocketServer({ noServer: true, maxPayload: 1024 });

wss1.on('open', () => {})

wss1.on('connection', function connection(ws) {
	ws.on('message', function incoming(message) {
		console.log('received: %s', message);
	      });
	    
	      ws.send('something');
});

wss2.on('open', () => {})

wss2.on('connection', function connection(ws) {
	ws.on('message', function incoming(message) {
		console.log('received: %s', message);
	      });
	    
	      ws.send('something');
});


server.on('upgrade', function upgrade(request, socket, head) {
  const {pathname}  = new URL(request.url, `http://${request.headers.host}`);

  if (pathname === '/host') {
    wss1.handleUpgrade(request, socket, head, function done(ws) {
      wss1.emit('connection', ws, request);
    });
  } else if (pathname === '/transient') {
    wss2.handleUpgrade(request, socket, head, function done(ws) {
      wss2.emit('connection', ws, request);
    });
  } else {
    socket.destroy();
  }
});

server.listen(8443);