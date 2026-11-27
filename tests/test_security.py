import os, sys, tempfile, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import app as appmod


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        appmod.DB = os.path.join(self.tmp.name, "t.db")
        appmod.config.UPLOAD_DIR = os.path.join(self.tmp.name, "up")
        os.makedirs(appmod.config.UPLOAD_DIR)
        open(os.path.join(self.tmp.name, "secret.txt"), "w").write("top secret")
        open(os.path.join(appmod.config.UPLOAD_DIR, "ok.txt"), "w").write("fine")
        appmod.init_db()
        self.c = appmod.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def test_sqli_login_bypass(self):
        self.c.post("/register", data={"name": "bob", "password": "pw"})
        r = self.c.post("/login", data={"name": "bob' OR '1'='1' --", "password": "x"})
        self.assertEqual(r.status_code, 401)

    def test_login_ok_and_hash_not_md5(self):
        self.c.post("/register", data={"name": "bob", "password": "pw"})
        self.assertEqual(self.c.post("/login", data={"name": "bob", "password": "pw"}).status_code, 200)
        h = appmod.db().execute("SELECT password FROM users").fetchone()[0]
        self.assertNotRegex(h, r"^[0-9a-f]{32}$")

    def test_xss_and_ssti(self):
        r = self.c.get("/search", query_string={"q": "<script>alert(1)</script>{{7*7}}"})
        self.assertNotIn(b"<script>", r.data)
        self.assertNotIn(b"49", r.data)

    def test_command_injection(self):
        self.assertEqual(self.c.get("/ping", query_string={"host": "127.0.0.1; id"}).status_code, 400)
        self.assertEqual(self.c.get("/ping", query_string={"host": "$(id)"}).status_code, 400)

    def test_path_traversal(self):
        self.assertEqual(self.c.get("/download", query_string={"file": "../secret.txt"}).status_code, 404)
        self.assertEqual(self.c.get("/download", query_string={"file": "ok.txt"}).data, b"fine")

    def test_open_redirect(self):
        for bad in ("https://evil.com", "//evil.com", "/\\evil.com", "javascript:alert(1)"):
            self.assertEqual(self.c.get("/redirect", query_string={"url": bad}).status_code, 400, bad)
        self.assertEqual(self.c.get("/redirect", query_string={"url": "/home"}).status_code, 302)

    def test_ssrf(self):
        for u in ("http://169.254.169.254/", "https://127.0.0.1/", "https://example.com/"):
            self.assertEqual(self.c.get("/fetch", query_string={"url": u}).status_code, 403, u)

    def test_yaml_unsafe_tag(self):
        r = self.c.post("/import", data="!!python/object/apply:os.system ['echo pwned']")
        self.assertEqual(r.status_code, 400)

    def test_pickle_rejected(self):
        import pickle
        self.assertEqual(self.c.post("/restore", data=pickle.dumps({"a": 1})).status_code, 400)

    def test_eval_removed(self):
        self.assertEqual(self.c.get("/calc", query_string={"expr": "2+3*4"}).data, b"14")
        self.assertEqual(self.c.get("/calc", query_string={"expr": "__import__('os').getcwd()"}).status_code, 400)

    def test_idor(self):
        self.c.post("/register", data={"name": "alice", "password": "pw"})  # uid 1
        conn = appmod.db()
        conn.execute("INSERT INTO notes (owner, body) VALUES (1, 'alice private')")
        conn.commit()
        self.assertEqual(self.c.get("/note/1").status_code, 401)
        self.c.post("/register", data={"name": "mallory", "password": "pw"})
        self.c.post("/login", data={"name": "mallory", "password": "pw"})
        self.assertEqual(self.c.get("/note/1").status_code, 404)

    def test_no_hardcoded_secrets_or_debug(self):
        self.assertFalse(appmod.config.DEBUG)
        self.assertNotEqual(appmod.config.SECRET_KEY, "super-secret-key-123")
        self.assertFalse(hasattr(appmod.config, "AWS_SECRET_ACCESS_KEY"))


if __name__ == "__main__":
    unittest.main()
