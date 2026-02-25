const COGNITO_DOMAIN = process.env.COGNITO_DOMAIN;
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  'Access-Control-Allow-Methods': 'POST,OPTIONS',
};

export const handler = async (event) => {
  // CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: corsHeaders, body: '' };
  }

  const path = event.path || event.rawPath;
  const body = event.body ? JSON.parse(event.body) : {};

  try {
    // 로그인 (인가코드 → 토큰)
    if (path.endsWith('/auth/token')) {
      const { code } = body;
      if (!code) return error(400, 'code is required');

      const tokens = await fetchTokens({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
      });
      return success(tokens);
    }

    // 토큰 갱신
    if (path.endsWith('/auth/refresh')) {
      const { refresh_token } = body;
      if (!refresh_token) return error(400, 'refresh_token is required');

      const tokens = await fetchTokens({
        grant_type: 'refresh_token',
        refresh_token,
      });
      return success(tokens);
    }

    // 로그아웃
    if (path.endsWith('/auth/logout')) {
      const { access_token } = body;
      if (!access_token) return error(400, 'access_token is required');

      await fetch(`${COGNITO_DOMAIN}/oauth2/revoke`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': 'Basic ' + btoa(`${CLIENT_ID}:${CLIENT_SECRET}`),
        },
        body: new URLSearchParams({ token: access_token }),
      });
      return success({ message: 'logged out' });
    }

    return error(404, 'Not found');

  } catch (e) {
    console.error(e);
    return error(500, 'Internal server error');
  }
};

async function fetchTokens(params) {
  const res = await fetch(`${COGNITO_DOMAIN}/oauth2/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': 'Basic ' + btoa(`${CLIENT_ID}:${CLIENT_SECRET}`),
    },
    body: new URLSearchParams({ ...params, client_id: CLIENT_ID }),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Cognito error: ${err}`);
  }
  return res.json();
}

const success = (data) => ({
  statusCode: 200,
  headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  body: JSON.stringify(data),
});

const error = (statusCode, message) => ({
  statusCode,
  headers: { ...corsHeaders, 'Content-Type': 'application/json' },
  body: JSON.stringify({ message }),
});