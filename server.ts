import { createServer } from 'https'
import { readFileSync } from 'fs'
import { WebSocketServer } from 'ws'
import { webcrypto as crypto } from 'crypto'


const server = createServer({
  cert: readFileSync('/etc/letsencrypt/live/auth-rtc.strcat.xyz/fullchain.pem'),
  key: readFileSync('/etc/letsencrypt/live/auth-rtc.strcat.xyz/privkey.pem')
});

const host_socket_server = new WebSocketServer({ noServer: true, maxPayload: 1024 });
const transient_socket_server = new WebSocketServer({ noServer: true, maxPayload: 1024 });

const global_log = (...msg) => console.log(`${new Date().toUTCString()}::`, ...msg)
const log = global_log
const hosts = {}  // Map<public_key_hash, {send : string -> ()}>
const transients = {} // Map<public_key_hash, {target : public_key_hash, send : string -> ()}

const attempt = (fn, onerror = (error) => { }) => {
  try {
    return fn()
  } catch (e) {
    onerror(e)
    return undefined
  }
}

const try_parse = (text, log) => attempt(() => JSON.parse(text), log)

// from https://stackoverflow.com/questions/21797299/convert-base64-string-to-arraybuffer
// adapted for node (atob deprecated)
function base64ToBuffer(base64) {
  return Buffer.from(base64, 'base64')
  // var binary_string = Buffer.from(base64, 'base64');
  // var len = binary_string.length;
  // var bytes = new Uint8Array(len);
  // for (var i = 0; i < len; i++) {
  //   bytes[i] = binary_string.charCodeAt(i);
  // }
  // return bytes.buffer;
}
// from https://stackoverflow.com/questions/9267899/arraybuffer-to-base64-encoded-string
// adapted for node (btoa deprecated)
function bufferToBase64(buffer) {
  return buffer.toString('base64')
  // var binary = '';
  // var bytes = new Uint8Array(buffer);
  // var len = bytes.byteLength;
  // for (var i = 0; i < len; i++) {
  //   binary += String.fromCharCode(bytes[i]);
  // }
  // return binary.toString('base64');
}

const try_hash_public_key = (public_key, log) => attempt(() => crypto.subtle.digest('SHA-512', base64ToBuffer(public_key)), log)

const check_obj_has_all_keys = (keys, o, missing_fn) => {
  for (let k of keys) {
    if (!(k in o)) {
      missing_fn(k)
      return false
    }
  }
  return true
}

const try_import_verify_key = async (base64_pub_key, log) =>
    attempt(() =>
      crypto.subtle.importKey(
        'spki',
        base64ToBuffer(base64_pub_key),
        {
          name: "RSASSA-PKCS1-v1_5",
          hash: "SHA-256",
        },
        true,
        ["verify"]), log)

const try_verify = async (public_key, signature, known_message, log) => attempt(crypto.subtle.verify('RSASSA-PKCS1-v1_5', public_key, signature, known_message), log)

const valid_signature = async ({ public_key, signature }) => {
  const pub_key_imported = await try_import_verify_key(public_key, log)
  if (!pub_key_imported) return `unreadable public key`

  const signature_imported = attempt(() => base64ToBuffer(signature), log)
  if (!signature_imported) return `unreadable signature`

  const verified = await try_verify(pub_key_imported, signature_imported, per_connection_properties.challenge, log)
  if (verified === undefined) return `internal verify error`

  if (!verified) return `signature doesn't match public key`

  return 'ok'
}

host_socket_server.on('connection', function connection(ws) {
  const unauthenticated_host_name = '<not authenticated>'
  const timeout_ms = 5 * 1000

  const per_connection_properties = {
    challenge: Math.random().toString(),
    authenticated: false,
    host: unauthenticated_host_name
  }

  const log = (...msg) => global_log(`host ${per_connection_properties.host}::`, ...msg)

  ws.on('message', async (message) => {

    log('message::', message)
    const abort = msg => {
      log('abort::', msg)
      ws.send(JSON.stringify({ error: msg }))
      ws.close()
    }
    const data = try_parse(message, log)
    if (data === undefined) return abort(`Couldn't parse message.`)

    if (!per_connection_properties.authenticated) {

      // Validate the message
      const example_data = { public_key: '', signature: '' }
      if (!check_obj_has_all_keys(
        Object.keys(example_data),
        data,
        k => abort(`missing key in message: "${k}"`))) return;

      const { public_key, signature } = data

      const out = await valid_signature(data)
      if (out != 'ok') return abort(out)

      const public_key_hash = await try_hash_public_key(public_key, log)
      if (!public_key_hash) return abort(`unhashable public key`)

      per_connection_properties.host = public_key_hash
      per_connection_properties.authenticated = true
      hosts[public_key_hash] = { send: ws.send }
      delete per_connection_properties.challenge;

      log('authenticated')
      return;
    } else {
      // Validate the message
      const example_data = { to: '', message: '' }
      if (!check_obj_has_all_keys(
        Object.keys(example_data),
        data,
        k => abort(`missing key in message: "${k}"`))) return;

      const { to, message } = data

      if (!(to in transients)) return log('tried to send to nonexistent transient')
      

      const { target, send } = transients[to]

      if (target != per_connection_properties.host) {
        log('tried to send to unexpected transient')
        return log('transient expected', target)
      }
      
      send(JSON.stringify({ message }))
    }
  })


  ws.on('close', () => {
    const host = per_connection_properties.host
    log('attempting to delete host', host)
    const output = host in hosts ? (delete hosts[host], 'deleted') : 'nothing to clean up'
    log(output)
  })

  // A challenge message will look like {"challenge":"0.3038331491796824"} 
  ws.send(JSON.stringify({ challenge: per_connection_properties.challenge }))

  // Schedule cleanup
  setTimeout(() => per_connection_properties.authenticated ? 'good' : ws.close(), timeout_ms)

})

transient_socket_server.on('connection', function connection(ws) {
  const unauthenticated_transient_name = '<not authenticated>'
  const timeout_ms = 5 * 1000

  const per_connection_properties = {
    challenge: Math.random().toString(),
    authenticated: false,
    transient: unauthenticated_transient_name,
    count_remaining_send: 2,
    count_remaining_receive: 2
  }
  const log = (...msg) => global_log(`transient ${per_connection_properties.transient}::`, ...msg)

  ws.on('message', function incoming(message) {
    console.log('received: %s', message);
  });

  ws.on('close', () => {
    const transient = per_connection_properties.transient
    log('attempting to delete host', transient)
    const output = transient in transients ? (delete transients[transient], 'deleted') : 'nothing to clean up'
    log(output)
  })

  // A challenge message will look like {"challenge":"0.3038331491796824"} 
  ws.send(JSON.stringify({ challenge: per_connection_properties.challenge }))

  // Schedule cleanup
  setTimeout(() => per_connection_properties.authenticated ? 'good' : ws.close(), timeout_ms)
});


server.on('upgrade', function upgrade(request, socket, head) {
  const { pathname } = new URL(request.url, `http://${request.headers.host}`);

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