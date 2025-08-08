import { parentPort, workerData } from 'worker_threads';
import { Keypair } from '@solana/web3.js';

const { suffix, reportEvery } = workerData;

let attempts = 0;
let running = true;

parentPort.on('message', (msg) => {
  if (msg?.type === 'stop') {
    running = false;
  }
});

function loop() {
  while (running) {
    const kp = Keypair.generate();
    attempts++;
    const addr = kp.publicKey.toBase58();

    if (attempts % reportEvery === 0) {
      parentPort.postMessage({ type: 'progress', attempts: reportEvery });
    }

    if (addr.endsWith(suffix)) {
      parentPort.postMessage({ type: 'found', address: addr, secretKey: Array.from(kp.secretKey) });
      running = false;
      break;
    }
  }
}

loop();
