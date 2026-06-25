import http from 'http';
import crypto from 'crypto';
import { XMLParser } from 'fast-xml-parser';

const parser = new XMLParser();
const PORT = process.env.PORT || 3000;

class WeComCrypto {
  constructor(token, encodingAESKey, corpId) {
    this.token = token;
    this.corpId = corpId;
    this.aesKey = Buffer.from(encodingAESKey + '=', 'base64');
  }
  verifySignature(timestamp, nonce, msgEncrypt, signature) {
    const arr = [this.token, timestamp, nonce, msgEncrypt].sort();
    return crypto.createHash('sha1').update(arr.join('')).digest('hex') === signature;
  }
  verifyGetSignature(timestamp, nonce, signature) {
    const arr = [this.token, timestamp, nonce].sort();
    return crypto.createHash('sha1').update(arr.join('')).digest('hex') === signature;
  }
  decrypt(encryptedMsg) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', this.aesKey, this.aesKey.slice(0, 16));
    decipher.setAutoPadding(false);
    let decrypted = Buffer.concat([decipher.update(Buffer.from(encryptedMsg, 'base64')), decipher.final()]);
    const msgLen = decrypted.readUInt32BE(16);
    return decrypted.slice(20, 20 + msgLen).toString('utf8');
  }
  encrypt(replyMsg) {
    const random16 = crypto.randomBytes(16);
    const msgBuf = Buffer.from(replyMsg, 'utf8');
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(msgBuf.length, 0);
    const content = Buffer.concat([random16, lenBuf, msgBuf, Buffer.from(this.corpId, 'utf8')]);
    const blockSize = 32;
    const padLen = blockSize - (content.length % blockSize);
    const pad = Buffer.alloc(padLen, padLen);
    const padded = Buffer.concat([content, pad]);
    const cipher = crypto.createCipheriv('aes-256-cbc', this.aesKey, this.aesKey.slice(0, 16));
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(padded), cipher.final()]).toString('base64');
  }
  buildReplySignature(timestamp, nonce, encryptedMsg) {
    const arr = [this.token, timestamp, nonce, encryptedMsg].sort();
    return crypto.createHash('sha1').update(arr.join('')).digest('hex');
  }
}

function buildEncryptedReply(wc, toUser, fromUser, agentId, content) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomBytes(8).toString('hex');
  const plainXml = `<xml><ToUserName><![CDATA[${toUser}]]></ToUserName><FromUserName><![CDATA[${fromUser}]]></FromUserName><CreateTime>${timestamp}</CreateTime><MsgType><![CDATA[text]]></MsgType><Content><![CDATA[${content}]]></Content><AgentID>${agentId}</AgentID></xml>`;
  const encrypted = wc.encrypt(plainXml);
  const signature = wc.buildReplySignature(timestamp, nonce, encrypted);
  return `<xml><Encrypt><![CDATA[${encrypted}]]></Encrypt><MsgSignature><![CDATA[${signature}]]></MsgSignature><TimeStamp>${timestamp}</TimeStamp><Nonce><![CDATA[${nonce}]]></Nonce></xml>`;
}

async function callClaude(userMessage) {
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': process.env.ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-6',
      max_tokens: 1000,
      system: process.env.SYSTEM_PROMPT || '你是一个高效的AI助手，用简洁的中文回复。',
      messages: [{ role: 'user', content: userMessage }],
    }),
  });
  const data = await resp.json();
  if (data.error) throw new Error(data.error.message);
  return data.content[0].text;
}

function getQuery(url) {
  const u = new URL(url, 'http://localhost');
  return Object.fromEntries(u.searchParams);
}

const server = http.createServer(async (req, res) => {
  const wc = new WeComCrypto(
    process.env.WECOM_TOKEN,
    process.env.WECOM_ENCODING_AES_KEY,
    process.env.WECOM_CORP_ID
  );
  const q = getQuery(req.url);

  if (req.method === 'GET') {
    if (!wc.verifyGetSignature(q.timestamp, q.nonce, q.msg_signature)) {
      res.writeHead(403); res.end('Forbidden'); return;
    }
    try {
      res.writeHead(200); res.end(wc.decrypt(q.echostr));
    } catch(e) {
      res.writeHead(500); res.end('Decrypt failed');
    }
    return;
  }

  if (req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const outer = parser.parse(body);
        const encryptedMsg = outer.xml?.Encrypt;
        if (!encryptedMsg) { res.writeHead(400); res.end('Bad Request'); return; }
        if (!wc.verifySignature(q.timestamp, q.nonce, encryptedMsg, q.msg_signature)) {
          res.writeHead(403); res.end('Forbidden'); return;
        }
        const msg = parser.parse(wc.decrypt(encryptedMsg)).xml;
        if (msg.MsgType !== 'text') {
          res.writeHead(200); res.end(buildEncryptedReply(wc, msg.FromUserName, msg.ToUserName, msg.AgentID, '目前只支持文字消息～')); return;
        }
        const aiReply = await callClaude(String(msg.Content));
        res.writeHead(200); res.end(buildEncryptedReply(wc, msg.FromUserName, msg.ToUserName, msg.AgentID, aiReply));
      } catch(err) {
        console.error(err);
        res.writeHead(500); res.end('Error');
      }
    });
    return;
  }

  res.writeHead(404); res.end('Not found');
});

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
