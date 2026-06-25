import crypto from 'crypto';
import { XMLParser } from 'fast-xml-parser';

const parser = new XMLParser();

class WeComCrypto {
  constructor(token, encodingAESKey, corpId) {
    this.token = token;
    this.corpId = corpId;
    this.aesKey = Buffer.from(encodingAESKey + '=', 'base64');
  }

  verifySignature(timestamp, nonce, msgEncrypt, signature) {
    const arr = [this.token, timestamp, nonce, msgEncrypt].sort();
    const sha1 = crypto.createHash('sha1').update(arr.join('')).digest('hex');
    return sha1 === signature;
  }

  verifyGetSignature(timestamp, nonce, signature) {
    const arr = [this.token, timestamp, nonce].sort();
    const sha1 = crypto.createHash('sha1').update(arr.join('')).digest('hex');
    return sha1 === signature;
  }

  decrypt(encryptedMsg) {
    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      this.aesKey,
      this.aesKey.slice(0, 16)
    );
    decipher.setAutoPadding(false);
    let decrypted = Buffer.concat([
      decipher.update(Buffer.from(encryptedMsg, 'base64')),
      decipher.final()
    ]);
    const msgLen = decrypted.readUInt32BE(16);
    const content = decrypted.slice(20, 20 + msgLen).toString('utf8');
    return content;
  }

  encrypt(replyMsg) {
    const random16 = crypto.randomBytes(16);
    const msgBuf = Buffer.from(replyMsg, 'utf8');
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(msgBuf.length, 0);
    const corpIdBuf = Buffer.from(this.corpId, 'utf8');
    const content = Buffer.concat([random16, lenBuf, msgBuf, corpIdBuf]);

    const blockSize = 32;
    const padLen = blockSize - (content.length % blockSize);
    const pad = Buffer.alloc(padLen, padLen);
    const padded = Buffer.concat([content, pad]);

    const cipher = crypto.createCipheriv(
      'aes-256-cbc',
      this.aesKey,
      this.aesKey.slice(0, 16)
    );
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(padded), cipher.final()]).toString('base64');
  }

  buildReplySignature(timestamp, nonce, encryptedMsg) {
    const arr = [this.token, timestamp, nonce, encryptedMsg].sort();
    return crypto.createHash('sha1').update(arr.join('')).digest('hex');
  }
}

function buildEncryptedReply(crypto_, toUser, fromUser, agentId, content) {
  const timestamp = String(Math.floor(Date.now() / 1000));
  const nonce = crypto.randomBytes(8).toString('hex');

  const plainXml = `<xml>
<ToUserName><![CDATA[${toUser}]]></ToUserName>
<FromUserName><![CDATA[${fromUser}]]></FromUserName>
<CreateTime>${timestamp}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[${content}]]></Content>
<AgentID>${agentId}</AgentID>
</xml>`;

  const encrypted = crypto_.encrypt(plainXml);
  const signature = crypto_.buildReplySignature(timestamp, nonce, encrypted);

  return `<xml>
<Encrypt><![CDATA[${encrypted}]]></Encrypt>
<MsgSignature><![CDATA[${signature}]]></MsgSignature>
<TimeStamp>${timestamp}</TimeStamp>
<Nonce><![CDATA[${nonce}]]></Nonce>
</xml>`;
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

export default async function handler(req, res) {
  const wecomCrypto = new WeComCrypto(
    process.env.WECOM_TOKEN,
    process.env.WECOM_ENCODING_AES_KEY,
    process.env.WECOM_CORP_ID
  );

  const { msg_signature, timestamp, nonce, echostr } = req.query;

  if (req.method === 'GET') {
    if (!wecomCrypto.verifyGetSignature(timestamp, nonce, msg_signature)) {
      return res.status(403).send('Forbidden');
    }
    try {
      const decrypted = wecomCrypto.decrypt(echostr);
      return res.status(200).send(decrypted);
    } catch (e) {
      return res.status(500).send('Decrypt failed');
