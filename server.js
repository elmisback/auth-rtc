import { createServer } from 'https';
import { readFileSync } from 'fs';
import { WebSocketServer } from 'ws';

const server = createServer({
  cert: readFileSync('/etc/letsencrypt/live/auth-rtc.strcat.xyz/fullchain.pem'),
  key: readFileSync('/etc/letsencrypt/live/auth-rtc.strcat.xyz/privkey.pem')
});

const host_socket_server = new WebSocketServer({ noServer: true, maxPayload: 1024 });
const transient_socket_server = new WebSocketServer({ noServer: true, maxPayload: 1024 });

const log = (...msg) => console.log(`${new Date.toUTCString()}::`, ...msg)
const hosts = {}  // Map<public_key_hash, {send : string -> ()}>

const try_parse = (text, log) => {
  try {
    return JSON.parse(text)
  } catch (e) {
    log(e)
    return undefined
  }
}

// from https://stackoverflow.com/questions/21797299/convert-base64-string-to-arraybuffer
function base64ToArrayBuffer(base64) {
  var binary_string = window.atob(base64);
  var len = binary_string.length;
  var bytes = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
      bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}
// from https://stackoverflow.com/questions/9267899/arraybuffer-to-base64-encoded-string
function arrayBufferToBase64( buffer ) {
  var binary = '';
  var bytes = new Uint8Array( buffer );
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
      binary += String.fromCharCode( bytes[ i ] );
  }
  return window.btoa( binary );
}

const hash_public_key = async public_key => {
  await crypto.subtle.
}

host_socket_server.on('connection', function connection(ws) {
  const unauthenticated_host_name = '<not authenticated>'
  const timeout_ms = 5 * 1000

  const per_connection_properties = {
    challenge: Math.random().toString(),
    authenticated: false,
    host: unauthenticated_host_name
  }
  
  const outer_log = log
  const log = (...msg) => outer_log(`host ${per_connection_properties.host}::`, ...msg)
  
  const abort = msg => {
    log('abort::', msg)
    ws.send(JSON.stringify({error: msg}))
    ws.close()
  }
  const check_obj_has_all_keys = (keys, o, missing_fn) => {
    for (let k of keys) {
      if (!(k in o)) {
        missing_fn(k)
        return false
      }
    }
    return true
  }
  const valid_signature = ({public_key, signature}) => {
  }

	ws.on('message', (message) => {
    log('message::', message)
    const data = try_parse(message)
    if (data === undefined) {
      abort(`Couldn't parse message.`)
      return;
    }
		if (!per_connection_properties.authenticated) {
      
      // Validate the message
      const example_data = {public_key: '', signature: ''}
      if (!check_obj_has_all_keys(
            Object.keys(example_data), 
            data, 
            k => abort(`Missing key in message: "${k}"`))) return;

      if (!valid_signature(data)) {
        abort(`Signature couldn't be validated.`)
        // NOTE (potential bad actor)?
        return;
      }
      
      
      // ...
      log('authenticated')
      return;
    }
  
  
  ws.on('close', () => {
    log('attempting to delete host', host)
    const output = host in hosts ? (delete hosts[host], 'deleted') : 'nothing to clean up'
    log(output)
  })

  // A challenge message will look like {"challenge":"0.3038331491796824"} 
  ws.send(JSON.stringify({challenge}))

  // Schedule cleanup
  setTimeout(() => per_connection_properties.authenticated ? 'good' : ws.close(), timeout_ms)

})

transient_socket_server.on('connection', function connection(ws) {
	ws.on('message', function incoming(message) {
		console.log('received: %s', message);
	      });
	    
	      ws.send('something');
});


server.on('upgrade', function upgrade(request, socket, head) {
  const {pathname}  = new URL(request.url, `http://${request.headers.host}`);

  if (pathname === '/host') {
    host_socket_server.handleUpgrade(request, socket, head, function done(ws) {
      host_socket_server.emit('connection', ws, request);
    });
  } else if (pathname === '/transient') {
    transient_socket_server.handleUpgrade(request, socket, head, function done(ws) {
      transient_socket_server.emit('connection', ws, request);
    });
  } else {
    socket.destroy();
  }
});

server.listen(8443);