import axios from 'axios';

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || '',
  timeout: 30000,
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
