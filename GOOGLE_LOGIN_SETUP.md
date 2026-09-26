# Google Login Setup

Google sign-in is optional. Password login works without it.

1. Create an OAuth 2.0 Web Application credential in Google Cloud Console.
2. Add an authorized redirect URI matching your deployment exactly:
   - Local: `http://127.0.0.1:5000/auth/google/callback`
   - Server: `https://YOUR-DOMAIN/auth/google/callback`
3. Copy the client ID and client secret into `.env`:

```env
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=https://YOUR-DOMAIN/auth/google/callback
```

4. Restart AEGIS. Both Login and New User/Signup screens will show **Continue with Google** / **Sign up with Google**.

The callback creates a normal AEGIS user record on first Google login and reuses the same account on later logins.
