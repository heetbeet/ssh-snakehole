// Use the same terminal parser as VS Code, with no browser or display server.
const { Terminal } = require('@xterm/headless');
const { Unicode11Addon } = require('@xterm/addon-unicode11');
const { StringDecoder } = require('node:string_decoder');
const readline = require('node:readline');
const terminal = new Terminal({cols: 100, rows: 30, allowProposedApi: true});
terminal.loadAddon(new Unicode11Addon());
terminal.unicode.activeVersion = '11';
const decoder = new StringDecoder('utf8');
let replies = '';
terminal.onData(data => replies += data);
function report() {
  const buffer = terminal.buffer.active;
  const screen = Array.from({length: terminal.rows}, (_, y) =>
    buffer.getLine(buffer.viewportY + y)?.translateToString(true) || '').join('\n');
  const prefix = terminal.modes.applicationCursorKeysMode ? '\x1bO' : '\x1b[';
  const keys = {left: prefix + 'D', end: prefix + 'F'};
  process.stdout.write(JSON.stringify({screen, buffer: buffer.type, replies, keys}) + '\n');
  replies = '';
}
readline.createInterface({input: process.stdin}).on('line', line => {
  const request = JSON.parse(line);
  if (request.resize) terminal.resize(...request.resize);
  if (request.data) terminal.write(decoder.write(Buffer.from(request.data, 'base64')), report);
  else report();
});
