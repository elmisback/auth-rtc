import { createServer } from 'https'
import { readFileSync } from 'fs'
import { WebSocketServer, WebSocket } from 'ws'
import { webcrypto as crypto } from 'crypto'

const server = createServer({
  cert: readFileSync('/etc/letsencrypt/live/auth-rtc.strcat.xyz/fullchain.pem'),
  key: readFileSync('/etc/letsencrypt/live/auth-rtc.strcat.xyz/privkey.pem')
});

const host_socket_server = new WebSocketServer({
  noServer: true, maxPayload: 2 * 1024
});
const transient_socket_server = new WebSocketServer({
  noServer: true, maxPayload: 2 * 1024
});

const global_log = (...msg) => console.log(`${new Date().toUTCString()}`, `::`, ...msg)
const log = global_log
const hosts = {}  // Map<public_key, {send : string -> ()}>
const transients = {} // Map<public_key, {host : public_key, send : string -> ()}

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
          name: 'ECDSA',
          namedCurve: "P-384"
        },
        true,
        ["verify"]), log)

const try_verify = async (public_key, signature, known_message, log) => attempt(() => crypto.subtle.verify({ name: 'ECDSA', hash: "SHA-256" }, public_key, signature, known_message), log)

const valid_signature = async ({ public_key, signature, challenge }) => {
  const pub_key_imported = await try_import_verify_key(public_key, log)
  if (!pub_key_imported) return `unreadable public key`

  const signature_imported = attempt(() => base64ToBuffer(signature), log)
  if (!signature_imported) return `unreadable signature`

  const verified = await try_verify(pub_key_imported, signature_imported, challenge, log)
  if (verified === undefined) return `internal verify error`

  if (!verified) return `signature doesn't match public key`

  return 'ok'
}

host_socket_server.on('connection', function connection(ws) {
  const unauthenticated_host_name = '<not authenticated>'
  const timeout_ms = 5 * 1000
  const heartbeat_ms = 54 * 1000

  const per_connection_properties = {
    challenge: Math.random().toString(),
    authenticated: false,
    host: unauthenticated_host_name
  }

  const log = (...msg) => global_log(`host ${per_connection_properties.host}`, `::`, ...msg)

  ws.on('message', async (message) => {
    if ((message) == 'pong') {
      no_heartbeat = false
      return
    }
    log('message', '::', new TextDecoder().decode(message))
    const abort = msg => {
      log('abort','::', msg)
      attempt(() => ws.close(1008, msg), log)
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

      const out = await valid_signature({ ...data, challenge: per_connection_properties.challenge })
      if (out != 'ok') return abort(out)

      // const public_key_hash = await try_hash_public_key(public_key, log)
      // if (!public_key_hash) return abort(`unhashable public key`)

      per_connection_properties.host = public_key
      per_connection_properties.authenticated = true
      if (hosts[public_key]) hosts[public_key].close(1008, 'new connection established')
      hosts[public_key] = { send: msg => attempt(() => ws.send(msg), log), close: (...args) => ws.close(...args) }
      delete per_connection_properties.challenge;

      return log('authenticated')
    } else {
      // Validate the message
      const example_data = { to: '', message: '' }
      if (!check_obj_has_all_keys(
        Object.keys(example_data),
        data,
        k => abort(`missing key in message: "${k}"`))) return;

      const { to, message } = data

      if (!(to in transients)) return log('tried to send to nonexistent transient')
      

      const { host, send } = transients[to]

      if (host != per_connection_properties.host) {
        log('tried to send to unexpected transient')
        return log('transient expected', host)
      }
      
      send(JSON.stringify({ message }))
    }
  })


  ws.on('close', () => {
    // TODO use a heartbeat for cleanup and keeping the connection open
    // const host = per_connection_properties.host
    // log('attempting to delete host', host)
    // const output = host in hosts ? (delete hosts[host], 'deleted') : 'nothing to clean up'
    // log(output)
  })

  let no_heartbeat = false
  const schedule_heartbeat = () => setTimeout(() => {
    if (no_heartbeat) {
      const host = per_connection_properties.host
      host in hosts ? (delete hosts[host], 'deleted') : 'nothing to clean up'
      ws.close(1008, `no heartbeat`)
      return;
    }
    no_heartbeat = true
    ws.send('ping')
    schedule_heartbeat()
  }, heartbeat_ms)
  schedule_heartbeat()

  // A challenge message will look like {"challenge":"0.3038331491796824"} 
  attempt(() => ws.send(JSON.stringify({ challenge: per_connection_properties.challenge })), log)

  // Schedule cleanup
  setTimeout(() => per_connection_properties.authenticated ? 'good' : attempt(() => ws.close(`failed to authenticate within ${timeout_ms} ms`), log), timeout_ms)

})

const already_terminated = ws => ws.readyState in [WebSocket.CLOSED, WebSocket.CLOSING]

transient_socket_server.on('connection', function connection(ws) {
  const unauthenticated_transient_name = '<not authenticated>'
  const timeout_ms = 5 * 1000
  const max_connection_ms = 20 * 1000

  const per_connection_properties = {
    challenge: Math.random().toString(),
    authenticated: false,
    transient: unauthenticated_transient_name,
    count_remaining_send: 3,
    count_remaining_receive: 3
  }
  const log = (...msg) => global_log(`transient ${per_connection_properties.transient}`, `::`, ...msg)

  ws.on('message', async (message) => {
    log('message', '::', new TextDecoder().decode(message))
    const abort = msg => {
      log('abort','::', msg)
      attempt(() => ws.close(1008, msg), log)
    }
    const data = try_parse(message, log)
    if (data === undefined) return abort(`Couldn't parse message.`)

    if (!per_connection_properties.authenticated) {

      // Validate the message
      const example_data = { public_key: '', signature: '', host: '<host_public_key>' }
      if (!check_obj_has_all_keys(
        Object.keys(example_data),
        data,
        k => abort(`missing key in message: "${k}"`))) return;
      
      const { public_key, signature, host } = data

      if (!(host in hosts)) return abort(`host unavailable`)

      const out = await valid_signature({ ...data, challenge: per_connection_properties.challenge })
      if (out != 'ok') return abort(out)

      // const public_key_hash = await try_hash_public_key(public_key, log)
      // if (!public_key_hash) return abort(`unhashable public key`)

      per_connection_properties.transient = public_key
      per_connection_properties.authenticated = true

      const wrapped_send = msg => {
        attempt(() => ws.send(msg), log)
        per_connection_properties.count_remaining_receive -= 1
        if (per_connection_properties.count_remaining_receive <= 0) ws.close('all messages sent')
      }
      transients[public_key] = { host, send: wrapped_send }
      delete per_connection_properties.challenge

      // Schedule cleanup
      setTimeout(() => !already_terminated(ws) ? attempt(() => ws.close(`failed to finish transaction within ${max_connection_ms} ms`), log) : 'good', max_connection_ms)

      log('authenticated')
    }
    // Validate the message
    const example_data = { message: '' }
    if (!check_obj_has_all_keys(
      Object.keys(example_data),
      data,
      k => abort(`missing key in message: "${k}"`))) return;

    message = data.message
    
    const { transient } = per_connection_properties
    const { host } = transients[transient]
    if (!(host in hosts)) return abort('host unavailable')
    
    const { send } = hosts[host]
    
    send(JSON.stringify({from: transient, message }))

    per_connection_properties.count_remaining_send -= 1
    if (per_connection_properties.count_remaining_send <= 0) return ws.close()
  })

  ws.on('close', () => {
    const transient = per_connection_properties.transient
    log('attempting to delete transient', transient)
    const output = transient in transients ? (delete transients[transient], 'deleted') : 'nothing to clean up'
    log(output)
  })

  // A challenge message will look like {"challenge":"0.3038331491796824"} 
  attempt(() => ws.send(JSON.stringify({ challenge: per_connection_properties.challenge })), log)

  // Schedule cleanup
  setTimeout(() => per_connection_properties.authenticated || already_terminated(ws) ? 'good' : ws.close(`failed to authenticate within ${timeout_ms} ms`), timeout_ms)
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