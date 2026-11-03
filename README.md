# sessionkit

Small HS256 session tokens and Express middleware. About 80 lines, no crypto dependencies.

```js
const { sign, requireSession, requireRole } = require("sessionkit");

const token = sign({ sub: "ada", role: "member" }, process.env.SESSION_SECRET, { expiresIn: 3600 });

app.get("/me", requireSession(process.env.SESSION_SECRET), (req, res) => res.json(req.session));
app.get("/admin", requireSession(secret), requireRole("admin"), handler);
```

## Run the demo server

```sh
npm install
SESSION_SECRET=$(openssl rand -hex 32) npm start
curl -s localhost:3000/login -H 'content-type: application/json' -d '{"user":"ada","password":"correct horse"}'
```

## Tests

```sh
npm test
```

## License

MIT
