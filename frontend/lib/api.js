import axios from 'axios';

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || '',
  timeout: 120000, // 2 minutes to allow 7-agent sequential AI processing
  headers: {
    'Content-Type': 'application/json',
  },
});

export async function checkHealth() {
  const { data } = await api.get('/api/health');
  return data;
}

export async function analyzeGeneral(sourceType, content, metadata = null) {
  const { data } = await api.post('/api/analyze', {
    source_type: sourceType,
    content,
    metadata,
  });
  return data;
}

export async function analyzeURL(url, followRedirects = true) {
  const { data } = await api.post('/api/analyze/url', {
    url,
    follow_redirects: followRedirects,
  });
  return data;
}

export async function analyzeEmail(rawEmail, sender = null, subject = null) {
  const { data } = await api.post('/api/analyze/email', {
    raw_email: rawEmail,
    sender,
    subject,
  });
  return data;
}

export async function analyzeFile(file) {
  const formData = new FormData();
  formData.append('file', file);

  // Point directly to backend to bypass Next.js 10MB rewrite limits for large videos
  const backendUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

  const { data } = await axios.post(`${backendUrl}/api/analyze/file`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
    timeout: 300000, // 5 minutes for deepfake video scans
  });
  return data;
}

export async function syncLiveEmail(emailAddress, appPassword, imapServer = 'imap.gmail.com', limit = 5) {
  const { data } = await api.post('/api/live/sync/email', {
    email_address: emailAddress,
    app_password: appPassword,
    imap_server: imapServer,
    limit,
  });
  return data;
}

export async function analyzeText(text, context = null) {
  const { data } = await api.post('/api/analyze/text', {
    text,
    context,
  });
  return data;
}

export async function getReports() {
  const { data } = await api.get('/api/reports');
  return data;
}

export async function getReport(scanId) {
  const { data } = await api.get(`/api/reports/${scanId}`);
  return data;
}

export async function runAdversarial(scanId) {
  const { data } = await api.post(`/api/reports/${scanId}/adversarial`);
  return data;
}

export default api;
