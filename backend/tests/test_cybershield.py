"""Comprehensive backend & workflow test suite for CyberShield."""

from pathlib import Path
import sys
import unittest

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app import create_app  # noqa: E402
from config import TestConfig  # noqa: E402
from extensions import db  # noqa: E402


class CyberShieldTestCase(unittest.TestCase):
    """Verifies API contracts, detection rules, safeguards, self-recovery, and DB persistence."""

    def setUp(self):
        self.app = create_app(config_class=TestConfig, seed_baseline=True)
        self.client = self.app.test_client()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_01_healthy_baseline_and_dashboard(self):
        res = self.client.get("/api/health")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "Healthy")
        self.assertTrue(data["health"]["real_metrics"]["sqlite_reachable"])

        dash = self.client.get("/api/dashboard").get_json()
        self.assertEqual(dash["system_status"], "Healthy")
        self.assertEqual(dash["summary"]["active_simulated_blocks"], 0)
        self.assertGreaterEqual(dash["summary"]["total_security_events"], 4)

    def test_02_normal_traffic_and_single_login_prevent_false_alarms(self):
        res = self.client.post("/api/simulation/normal-traffic", json={"request_count": 8})
        self.assertEqual(res.status_code, 201)
        payload = res.get_json()
        self.assertFalse(payload["detection"]["is_threat"])
        self.assertIsNone(payload["incident"])

        # Isolated single failed login should not raise a false incident
        single = self.client.post(
            "/api/simulation/failed-logins",
            json={"source_ip": "192.0.2.88", "attempts": 1},
        )
        self.assertEqual(single.status_code, 201)
        single_data = single.get_json()
        self.assertFalse(single_data["detection"]["is_threat"])
        self.assertTrue(single_data["detection"]["false_alarm_prevented"])
        self.assertIsNone(single_data["incident"])

    def test_03_full_demo_workflow_failed_logins_block_incident_recovery(self):
        # Step 3-6: Trigger repeated failed logins
        sim = self.client.post(
            "/api/simulation/failed-logins",
            json={"source_ip": "203.0.113.45", "attempts": 7},
        )
        self.assertEqual(sim.status_code, 201)
        data = sim.get_json()
        self.assertTrue(data["detection"]["is_threat"])
        self.assertGreaterEqual(data["risk"]["risk_score"], 60)
        self.assertIn(data["risk"]["severity"], ("High", "Critical"))
        self.assertTrue(data["response"]["block_applied"])
        self.assertIsNotNone(data["incident"])
        incident_id = data["incident"]["id"]

        # Verify blocked source exists and can be manually unblocked
        blocks = self.client.get("/api/blocked-sources").get_json()
        self.assertEqual(blocks["active_count"], 1)
        block_id = blocks["blocked_sources"][0]["id"]

        unblock = self.client.post(f"/api/blocked-sources/{block_id}/unblock", json={})
        self.assertEqual(unblock.status_code, 200)
        self.assertFalse(unblock.get_json()["blocked_source"]["is_active"])

        # Step 7: Inspect incident and update status
        detail = self.client.get(f"/api/incidents/{incident_id}").get_json()
        self.assertGreaterEqual(len(detail["incident"]["history"]), 4)

        patch = self.client.patch(
            f"/api/incidents/{incident_id}",
            json={"status": "Resolved", "notes": "Verified containment in test"},
        )
        self.assertEqual(patch.status_code, 200)
        self.assertEqual(patch.get_json()["incident"]["status"], "Resolved")

        # Step 8-10: Service failure -> Self-Recovery -> Restored Healthy
        fail = self.client.post("/api/simulation/service-failure", json={})
        self.assertEqual(fail.status_code, 201)
        self.assertEqual(fail.get_json()["health"]["overall_status"], "Critical")

        rec = self.client.post("/api/simulation/service-recovery", json={})
        self.assertEqual(rec.status_code, 200)
        rec_data = rec.get_json()
        self.assertEqual(rec_data["recovery_action"]["status"], "Completed")
        self.assertEqual(rec_data["health_after"]["overall_status"], "Healthy")

    def test_04_safeguard_blocks_real_external_ip_and_supports_human_approval(self):
        # Attempt with non-RFC-5737 IP must not be blocked
        ext = self.client.post(
            "/api/simulation/failed-logins",
            json={"source_ip": "8.8.8.8", "attempts": 8},
        )
        self.assertEqual(ext.status_code, 201)
        self.assertFalse(ext.get_json()["response"]["block_applied"])
        self.assertIn("Safeguard", ext.get_json()["response"]["action_taken"])

        # Enable human approval on failed_login_burst rule
        rules = self.client.get("/api/rules").get_json()["rules"]
        login_rule = next(r for r in rules if r["event_type"] == "failed_login_burst")
        upd = self.client.patch(
            f"/api/rules/{login_rule['id']}",
            json={"requires_human_approval": True},
        )
        self.assertEqual(upd.status_code, 200)

        queued = self.client.post(
            "/api/simulation/failed-logins",
            json={"source_ip": "203.0.113.120", "attempts": 8},
        ).get_json()
        self.assertTrue(queued["response"]["pending_approval"])
        self.assertFalse(queued["response"]["block_applied"])

        block_id = queued["response"]["blocked_source"]["id"]
        approved = self.client.post(f"/api/blocked-sources/{block_id}/approve", json={})
        self.assertEqual(approved.status_code, 200)
        self.assertTrue(approved.get_json()["blocked_source"]["is_active"])

    def test_05_other_endpoints_and_csv_export(self):
        self.client.post("/api/simulation/suspicious-traffic", json={"request_count": 65})
        self.client.post("/api/simulation/restricted-access", json={"probes": 3})
        self.client.post("/api/simulation/excessive-errors", json={"error_count": 18})
        self.client.post("/api/simulation/database-failure", json={})
        self.client.post("/api/recovery/trigger", json={"target_type": "database_failure"})

        mon = self.client.get("/api/monitoring?refresh=true")
        self.assertEqual(mon.status_code, 200)

        ev = self.client.get("/api/events?threats_only=true")
        self.assertEqual(ev.status_code, 200)
        self.assertGreater(ev.get_json()["count"], 0)

        mem = self.client.get("/api/immune-memory")
        self.assertEqual(mem.status_code, 200)
        self.assertGreater(mem.get_json()["total_cataloged_signatures"], 0)

        rep = self.client.get("/api/reports")
        self.assertEqual(rep.status_code, 200)
        self.assertGreater(rep.get_json()["totals"]["total_incidents"], 0)

        csv_res = self.client.get("/api/reports/export")
        self.assertEqual(csv_res.status_code, 200)
        self.assertIn("text/csv", csv_res.content_type)
        self.assertIn("Incident Code", csv_res.get_data(as_text=True))

    def test_06_validation_and_error_handling(self):
        self.assertEqual(
            self.client.post("/api/simulation/failed-logins", json={"attempts": 999}).status_code,
            400,
        )
        self.assertEqual(self.client.get("/api/incidents/99999").status_code, 404)
        self.assertEqual(
            self.client.patch("/api/incidents/1", json={"status": "InvalidState"}).status_code,
            400,
        )
        self.assertEqual(self.client.post("/api/blocked-sources/99999/unblock").status_code, 404)

    def test_07_live_login_portal_hides_threats_and_logs_for_admin(self):
        # Valid login succeeds cleanly
        ok = self.client.post(
            "/api/auth/login",
            json={"username": "student", "password": "DemoPass@123"},
        )
        self.assertEqual(ok.status_code, 200)
        self.assertTrue(ok.get_json()["authenticated"])

        # 4 wrong attempts return generic message without leaking threat internals
        for _ in range(4):
            r = self.client.post(
                "/api/auth/login",
                json={"username": "student", "password": "wrong"},
                headers={"X-Simulated-Client-IP": "192.0.2.150"},
            )
            self.assertEqual(r.status_code, 401)
            body = r.get_json()
            self.assertFalse(body["locked"])
            self.assertNotIn("risk_score", body)
            self.assertNotIn("incident_code", body)

        # 5th wrong attempt silently triggers backend threat detection & block
        fifth = self.client.post(
            "/api/auth/login",
            json={"username": "student", "password": "wrong"},
            headers={"X-Simulated-Client-IP": "192.0.2.150"},
        )
        self.assertEqual(fifth.status_code, 403)
        fifth_data = fifth.get_json()
        self.assertTrue(fifth_data["locked"])
        self.assertNotIn("risk_score", fifth_data)
        self.assertNotIn("incident_code", fifth_data)

        # Verify Admin backend recorded the threat incident and active block
        incidents = self.client.get("/api/incidents").get_json()["incidents"]
        self.assertTrue(any(i["source_ip"] == "192.0.2.150" for i in incidents))
        blocks = self.client.get("/api/blocked-sources").get_json()["blocked_sources"]
        self.assertTrue(any(b["source_ip"] == "192.0.2.150" and b["is_active"] for b in blocks))

        # 6th attempt even with valid password is rejected for user
        sixth = self.client.post(
            "/api/auth/login",
            json={"username": "student", "password": "DemoPass@123"},
            headers={"X-Simulated-Client-IP": "192.0.2.150"},
        )
        self.assertEqual(sixth.status_code, 403)
        self.assertTrue(sixth.get_json()["locked"])

    def test_08_restricted_endpoint_and_recovery_settings(self):
        # Probing restricted endpoint twice autonomously creates an incident silently
        p1 = self.client.get(
            "/api/admin/debug-console",
            headers={"X-Simulated-Client-IP": "198.51.100.77"},
        )
        self.assertEqual(p1.status_code, 403)
        self.assertNotIn("threat_detected", p1.get_json())

        p2 = self.client.get(
            "/api/admin/debug-console",
            headers={"X-Simulated-Client-IP": "198.51.100.77"},
        )
        self.assertEqual(p2.status_code, 403)
        incidents = self.client.get("/api/incidents").get_json()["incidents"]
        self.assertTrue(any(i["source_ip"] == "198.51.100.77" for i in incidents))

        # Autonomous self-healing settings endpoint
        cfg = self.client.patch(
            "/api/recovery/settings",
            json={"enabled": True, "delay_seconds": 8},
        )
        self.assertEqual(cfg.status_code, 200)
        self.assertEqual(cfg.get_json()["auto_heal"]["delay_seconds"], 8)

    def test_09_admin_only_soc_isolation(self):
        """Ensure Admin SOC APIs reject unauthenticated users when ADMIN_AUTH_REQUIRED is True."""
        from config import Config

        class StrictAdminConfig(Config):
            TESTING = True
            SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
            AUTO_HEAL_ENABLED = False
            ADMIN_AUTH_REQUIRED = True

        strict_app = create_app(config_class=StrictAdminConfig, seed_baseline=True)
        client = strict_app.test_client()

        # Regular user portal & health check work without admin login
        self.assertEqual(client.get("/").status_code, 200)
        self.assertEqual(client.get("/api/portal/status").status_code, 200)

        # Unauthenticated user cannot read CyberShield SOC telemetry
        self.assertEqual(client.get("/api/dashboard").status_code, 401)
        self.assertEqual(client.get("/api/incidents").status_code, 401)
        self.assertEqual(client.get("/api/blocked-sources").status_code, 401)

        # Admin sign-in unlocks SOC endpoints
        login = client.post(
            "/api/admin/login",
            json={"username": "admin", "password": "AdminShield@2026"},
        )
        self.assertEqual(login.status_code, 200)
        self.assertEqual(client.get("/api/dashboard").status_code, 200)
        self.assertEqual(client.get("/api/incidents").status_code, 200)

    def test_10_multiple_wrong_logins_trigger_system_warning_and_clear(self):
        """Ensure 2+ wrong login attempts trigger System: Warning, and Unblock/Clear restores Healthy."""
        ip = "192.0.2.175"

        # 1st wrong attempt -> Healthy (no false alarm)
        self.client.post(
            "/api/auth/login",
            json={"username": "student", "password": "bad1"},
            headers={"X-Simulated-Client-IP": ip},
        )
        dash1 = self.client.get("/api/dashboard").get_json()
        self.assertEqual(dash1["system_status"], "Healthy")
        self.assertEqual(len(dash1["login_warnings"]), 0)
        self.assertEqual(dash1["summary"]["recent_wrong_logins"], 1)

        # 2nd and 3rd wrong attempts -> System: Warning + Multiple Wrong Login alert
        for pw in ("bad2", "bad3"):
            r = self.client.post(
                "/api/auth/login",
                json={"username": "student", "password": pw},
                headers={"X-Simulated-Client-IP": ip},
            )
            self.assertEqual(r.status_code, 401)
            self.assertFalse(r.get_json()["locked"])

        dash3 = self.client.get("/api/dashboard").get_json()
        self.assertEqual(dash3["system_status"], "Warning")
        self.assertEqual(dash3["summary"]["recent_wrong_logins"], 3)
        self.assertEqual(len(dash3["login_warnings"]), 1)
        self.assertEqual(dash3["login_warnings"][0]["attempts"], 3)
        self.assertFalse(dash3["login_warnings"][0]["blocked"])

        # Clear warning returns system cleanly to Healthy and resets streak
        cleared = self.client.post("/api/alerts/clear", json={"source_ip": ip})
        self.assertEqual(cleared.status_code, 200)
        self.assertEqual(cleared.get_json()["health"]["overall_status"], "Healthy")
        self.assertEqual(cleared.get_json()["health"]["recent_wrong_logins"], 0)

        # 5 wrong attempts from fresh streak -> blocked, then 1-click Unblock + resolve_incident restores Healthy
        for i in range(5):
            r = self.client.post(
                "/api/auth/login",
                json={"username": "student", "password": f"wrong{i}"},
                headers={"X-Simulated-Client-IP": ip},
            )
            expected_code = 403 if i == 4 else 401
            self.assertEqual(r.status_code, expected_code)

        blocks = self.client.get("/api/blocked-sources").get_json()["blocked_sources"]
        blk = next(b for b in blocks if b["source_ip"] == ip and b["is_active"])
        ub = self.client.post(
            f"/api/blocked-sources/{blk['id']}/unblock",
            json={"resolve_incident": True},
        )
        self.assertEqual(ub.status_code, 200)
        self.assertEqual(self.client.get("/api/dashboard").get_json()["system_status"], "Healthy")

        # Next single wrong attempt after unblock starts at 1/5 instead of instant re-block
        after_ub = self.client.post(
            "/api/auth/login",
            json={"username": "student", "password": "typo"},
            headers={"X-Simulated-Client-IP": ip},
        )
        self.assertEqual(after_ub.status_code, 401)
        self.assertFalse(after_ub.get_json()["locked"])


if __name__ == "__main__":
    unittest.main()
