// Observe authentication callers; never change packet bytes or key material.
const hooked = new Set();
function installAuthProbe() {
  let ws;
  try { ws = Process.getModuleByName('ws2_32.dll'); } catch (_) { return; }
  for (const name of ['send', 'WSASend']) {
    if (hooked.has(name)) continue;
    const address = ws.getExportByName(name);
    Interceptor.attach(address, {
      onEnter(args) {
        try {
          const buffer = name === 'send' ? args[1] : args[1].add(4).readPointer();
          const size = name === 'send' ? args[2].toInt32() : args[1].readU32();
          if (size < 219 || buffer.readU16() !== 0x5713
              || buffer.add(5).readU8() !== 5) return;
          const owner = Process.getModuleByName('BinaryTrU.exe');
          send({kind: 'auth_probe', api: name, size: size,
            key_hook_bytes: Array.from(new Uint8Array(
              owner.base.add(0x4e4531).readByteArray(12))),
            stack: Thread.backtrace(this.context, Backtracer.ACCURATE).map(pc => {
              const module = Process.findModuleByAddress(pc);
              return module ? module.name + '+' + pc.sub(module.base) : String(pc);
            })});
        } catch (error) { send({kind: 'auth_probe_error', error: String(error)}); }
      }
    });
    hooked.add(name);
  }
}
Process.attachModuleObserver({onAdded(module) {
  if (module.name.toLowerCase() === 'ws2_32.dll') installAuthProbe();
}});
installAuthProbe();

// Only observe small random buffers requested by game code, not other processes.
const randomHooked = new Set();
function installRandomProbe() {
  for (const [dll, api, outputIndex, sizeIndex] of [
    ['advapi32.dll', 'CryptGenRandom', 2, 1],
    ['advapi32.dll', 'SystemFunction036', 0, 1],
    ['bcrypt.dll', 'BCryptGenRandom', 1, 2],
  ]) {
    if (randomHooked.has(api)) continue;
    let fn;
    try { fn = Process.getModuleByName(dll).getExportByName(api); }
    catch (_) { continue; }
    Interceptor.attach(fn, {
      onEnter(args) {
        this.size = args[sizeIndex].toUInt32();
        this.output = args[outputIndex];
        this.stack = null;
        if (this.size > 0 && this.size <= 64) {
          this.stack = Thread.backtrace(this.context, Backtracer.ACCURATE).map(pc => {
            const module = Process.findModuleByAddress(pc);
            return module ? module.name + '+' + pc.sub(module.base) : String(pc);
          });
        }
      },
      onLeave(result) {
        if (!this.stack || !this.stack.some(x => x.startsWith('BinaryTrU.exe+'))) return;
        const success = api === 'BCryptGenRandom' ? result.toInt32() === 0 : !result.isNull();
        if (!success) return;
        try {
          const bytes = new Uint8Array(this.output.readByteArray(this.size));
          send({kind: 'random_probe', api, size: this.size,
            hex: Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(''),
            stack: this.stack});
        } catch (error) { send({kind: 'random_probe_error', error: String(error)}); }
      }
    });
    randomHooked.add(api);
  }
}
Process.attachModuleObserver({onAdded() { installRandomProbe(); }});
installRandomProbe();

// The observed ProudNet RNG wrapper returns its completed output in args[0].
// Preserve the existing 16-byte test token by repeating it for the 32-byte seed.
function installProudRandomHook() {
  const game = Process.getModuleByName('BinaryTrU.exe');
  const target = game.base.add(0x1a1770);
  const sig = new Uint8Array(target.readByteArray(6));
  if (Array.from(sig).join(',') !== '86,139,116,36,8,133') {
    send({event: 'proud_random_signature_mismatch'});
    return;
  }
  Interceptor.attach(target, {
    onEnter(args) {
      this.output = args[0];
      this.size = args[1].toUInt32();
    },
    onLeave(result) {
      if (this.size !== 32 || result.toInt32() !== 32) return;
      const old = Array.from(new Uint8Array(this.output.readByteArray(32)),
        b => b.toString(16).padStart(2, '0')).join('');
      if (FORCE_KEY) {
        const bytes = FORCE_KEY.repeat(2).match(/../g).map(h => parseInt(h, 16));
        this.output.writeByteArray(bytes);
      }
      send({kind: 'sessionkey', event: 'proud_random_forced', ip: '?', port: 0,
        old, forced: FORCE_KEY, seed_hex: FORCE_KEY ? FORCE_KEY.repeat(2) : null});
    }
  });
  send({event: 'proud_random_hook_ready'});
}
installProudRandomHook();

// Observe AES key expansion separately: RNG output is not proof of AES identity.
function installAesProbe() {
  const game = Process.getModuleByName('BinaryTrU.exe');
  const target = game.base.add(0x169190);
  const signature = new Uint8Array(target.readByteArray(3));
  if (Array.from(signature).join(',') !== '131,236,52') {
    send({kind: 'aes_probe_signature_mismatch'});
    return;
  }
  Interceptor.attach(target, {
    onEnter(args) {
      const length = args[2].toUInt32();
      if (![16, 24, 32].includes(length)) return;
      try {
        send({kind: 'aes_key_probe', length,
          key: Array.from(new Uint8Array(args[1].readByteArray(length)),
            b => b.toString(16).padStart(2, '0')).join(''),
          stack: Thread.backtrace(this.context, Backtracer.ACCURATE).map(pc => {
            const module = Process.findModuleByAddress(pc);
            return module ? module.name + '+' + pc.sub(module.base) : String(pc);
          })});
      } catch (error) { send({kind: 'aes_probe_error', error: String(error)}); }
    }
  });
}
installAesProbe();

function installProudKeyHook() {
  const game = Process.getModuleByName('BinaryTrU.exe');
  const target = game.base.add(0x1963a0);
  const signature = Array.from(new Uint8Array(target.readByteArray(4))).join(',');
  if (signature !== '139,68,36,8') {
    send({event: 'proud_key_signature_mismatch'});
    return;
  }
  Interceptor.attach(target, {
    onEnter(args) {
      this.array = args[0];
      this.bits = args[1].toUInt32();
      this.caller = this.returnAddress.sub(game.base).toUInt32();
    },
    onLeave(result) {
      if (this.bits !== 128 || (result.toInt32() & 255) !== 1
          || ![0x170ddb, 0x170fb4].includes(this.caller)) return;
      try {
        if (this.array.add(12).readU32() < 16) throw new Error('short key array');
        const output = this.array.add(8).readPointer();
        if (FORCE_KEY) output.writeByteArray(FORCE_KEY.match(/../g).map(h => parseInt(h,16)));
        send({kind: 'proudkey', forced: FORCE_KEY, caller: this.caller,
          key: Array.from(new Uint8Array(output.readByteArray(16)),
            b => b.toString(16).padStart(2,'0')).join('')});
      } catch (error) { send({kind: 'proud_key_error', error: String(error)}); }
    }
  });
  send({event: 'proud_key_hook_ready'});
}
installProudKeyHook();
