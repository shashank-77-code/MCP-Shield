export async function requestJson(fetchImpl, url, options = {}) {
  const response = await fetchImpl(url, options);
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`Server returned an invalid response (${response.status}).`);
  }
  if (!response.ok) {
    const detail = typeof payload?.detail === 'string' ? payload.detail : `Request failed (${response.status}).`;
    throw new Error(detail);
  }
  return payload;
}
