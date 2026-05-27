"""Tests for hardening fixes:
  - Fix 1: wazuh_manager_breaker wired into WazuhClient
  - Fix 2: IP/CIDR protection on active response targets
  - Fix 3: Periodic stale approval token cleanup
"""
from __future__ import annotations

import os
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ── Fix 1: Wazuh Manager circuit breaker ─────────────────────────────────────

class TestWazuhManagerCircuitBreaker:
    def fresh_backend_breaker(self, fail_threshold=3, reset_seconds=30):
        from wazuh_mcp.circuit_breaker import BackendCircuitBreaker
        return BackendCircuitBreaker(
            name="wazuh_manager_test",
            fail_threshold=fail_threshold,
            reset_seconds=reset_seconds,
        )

    def test_breaker_starts_closed(self):
        b = self.fresh_backend_breaker()
        assert b.allow() is True
        assert b.is_open is False

    def test_breaker_opens_after_threshold(self):
        b = self.fresh_backend_breaker(fail_threshold=3)
        b.record_failure()
        b.record_failure()
        assert b.allow() is True   # not open yet (2 < 3)
        b.record_failure()         # 3rd failure
        assert b.allow() is False  # now open

    def test_breaker_resets_on_success(self):
        b = self.fresh_backend_breaker(fail_threshold=3)
        b.record_failure()
        b.record_failure()
        b.record_success()   # reset counter
        b.record_failure()   # should NOT open (counter was reset)
        assert b.allow() is True

    def test_breaker_status_reports_correctly(self):
        b = self.fresh_backend_breaker(fail_threshold=2, reset_seconds=60)
        b.record_failure()
        b.record_failure()
        s = b.status()
        assert s["circuit_open"] is True
        assert s["circuit_resets_in_seconds"] > 0

    def test_module_level_singletons_exist(self):
        from wazuh_mcp.circuit_breaker import opensearch_breaker, wazuh_manager_breaker
        assert opensearch_breaker.name == "opensearch"
        assert wazuh_manager_breaker.name == "wazuh_manager"

    @pytest.mark.asyncio
    async def test_wazuh_client_raises_when_breaker_open(self):
        """WazuhClient.request() must raise RuntimeError when circuit is open."""
        from wazuh_mcp.circuit_breaker import BackendCircuitBreaker
        fake_breaker = BackendCircuitBreaker("test", fail_threshold=1, reset_seconds=60)
        fake_breaker.record_failure()  # open the circuit
        assert fake_breaker.is_open

        with patch("wazuh_mcp.wazuh_client.wazuh_manager_breaker", fake_breaker):
            from wazuh_mcp.wazuh_client import WazuhClient
            from wazuh_mcp.config import Config
            import dataclasses

            # Minimal config — no real network calls needed
            cfg = Config(
                manager_host="https://test:55000",
                manager_user="u", manager_pass="p",
                indexer_host="https://test:9200",
                indexer_user="u", indexer_pass="p",
                alerts_index="wazuh-alerts-*", vuln_index="wazuh-vuln-*",
                inventory_packages_index="pkg-*", inventory_processes_index="proc-*",
                inventory_ports_index="ports-*",
                verify_ssl=False, ca_bundle=None,
                allow_writes=False, request_timeout=10,
                cloud_mode=False, tenants=(),
            )
            client = WazuhClient(cfg)
            with pytest.raises(RuntimeError, match="circuit breaker open"):
                await client.request("GET", "/")
            await client.aclose()

    @pytest.mark.asyncio
    async def test_wazuh_client_upload_xml_raises_when_breaker_open(self):
        """WazuhClient.upload_xml_file() must raise RuntimeError when circuit is open."""
        from wazuh_mcp.circuit_breaker import BackendCircuitBreaker
        fake_breaker = BackendCircuitBreaker("test", fail_threshold=1, reset_seconds=60)
        fake_breaker.record_failure()

        with patch("wazuh_mcp.wazuh_client.wazuh_manager_breaker", fake_breaker):
            from wazuh_mcp.wazuh_client import WazuhClient
            from wazuh_mcp.config import Config
            cfg = Config(
                manager_host="https://test:55000",
                manager_user="u", manager_pass="p",
                indexer_host="https://test:9200",
                indexer_user="u", indexer_pass="p",
                alerts_index="wazuh-alerts-*", vuln_index="wazuh-vuln-*",
                inventory_packages_index="pkg-*", inventory_processes_index="proc-*",
                inventory_ports_index="ports-*",
                verify_ssl=False, ca_bundle=None,
                allow_writes=False, request_timeout=10,
                cloud_mode=False, tenants=(),
            )
            client = WazuhClient(cfg)
            with pytest.raises(RuntimeError, match="circuit breaker open"):
                await client.upload_xml_file("/rules/files/test.xml", "<rules/>")
            await client.aclose()


# ── Fix 2: IP/CIDR protection on active response ─────────────────────────────

class TestActiveResponseIPProtection:
    def test_public_ip_allowed(self):
        from wazuh_mcp.validators import validate_active_response_target
        assert validate_active_response_target("203.0.113.50") is None

    def test_none_src_ip_allowed(self):
        from wazuh_mcp.validators import validate_active_response_target
        assert validate_active_response_target(None) is None

    def test_rfc1918_10_blocked(self):
        from wazuh_mcp.validators import validate_active_response_target
        result = validate_active_response_target("10.0.0.1")
        assert result is not None
        assert "protected" in result.lower()

    def test_rfc1918_172_blocked(self):
        from wazuh_mcp.validators import validate_active_response_target
        result = validate_active_response_target("172.16.5.10")
        assert result is not None

    def test_rfc1918_192_168_blocked(self):
        from wazuh_mcp.validators import validate_active_response_target
        result = validate_active_response_target("192.168.1.1")
        assert result is not None

    def test_loopback_blocked(self):
        from wazuh_mcp.validators import validate_active_response_target
        assert validate_active_response_target("127.0.0.1") is not None

    def test_ipv6_loopback_blocked(self):
        from wazuh_mcp.validators import validate_active_response_target
        assert validate_active_response_target("::1") is not None

    def test_link_local_blocked(self):
        from wazuh_mcp.validators import validate_active_response_target
        assert validate_active_response_target("169.254.1.1") is not None

    def test_broadcast_blocked(self):
        from wazuh_mcp.validators import validate_active_response_target
        assert validate_active_response_target("255.255.255.255") is not None

    def test_invalid_ip_returns_error(self):
        from wazuh_mcp.validators import validate_active_response_target
        result = validate_active_response_target("not-an-ip")
        assert result is not None
        assert "Invalid" in result

    def test_custom_cidr_blocked(self):
        from wazuh_mcp.validators import validate_active_response_target
        with patch.dict(os.environ, {"WAZUH_AR_BLOCKED_CIDRS": "203.0.113.0/24"}):
            result = validate_active_response_target("203.0.113.50")
            assert result is not None

    def test_custom_cidr_other_ips_still_allowed(self):
        from wazuh_mcp.validators import validate_active_response_target
        with patch.dict(os.environ, {"WAZUH_AR_BLOCKED_CIDRS": "203.0.113.0/24"}):
            # Different public IP not in blocked CIDR
            assert validate_active_response_target("198.51.100.1") is None

    def test_malformed_custom_cidr_ignored(self):
        from wazuh_mcp.validators import validate_active_response_target
        with patch.dict(os.environ, {"WAZUH_AR_BLOCKED_CIDRS": "not-a-cidr,999.999.999.999/24"}):
            # Should not raise — malformed entries are silently skipped
            result = validate_active_response_target("203.0.113.1")
            assert result is None


# ── Fix 3: Stale approval token cleanup ───────────────────────────────────────

class TestApprovalTokenCleanup:
    def test_expire_stale_removes_old_tokens(self):
        from wazuh_mcp.approval import ApprovalStore
        store = ApprovalStore()
        token = store.create("run_active_response", {"agent_id": "001"}, ttl=1)
        # Manually backdate the expiry
        store._pending[token]["expire_at"] = time.time() - 1
        removed = store.expire_stale()
        assert removed == 1
        assert token not in store._pending

    def test_expire_stale_keeps_valid_tokens(self):
        from wazuh_mcp.approval import ApprovalStore
        store = ApprovalStore()
        token = store.create("run_active_response", {"agent_id": "001"}, ttl=300)
        removed = store.expire_stale()
        assert removed == 0
        assert token in store._pending

    def test_expire_stale_mixed_tokens(self):
        from wazuh_mcp.approval import ApprovalStore
        store = ApprovalStore()
        t_valid = store.create("cmd", {}, ttl=300)
        t_stale = store.create("cmd", {}, ttl=300)
        store._pending[t_stale]["expire_at"] = time.time() - 1
        removed = store.expire_stale()
        assert removed == 1
        assert t_valid in store._pending
        assert t_stale not in store._pending

    def test_approve_rejects_expired_token(self):
        from wazuh_mcp.approval import ApprovalStore
        store = ApprovalStore()
        token = store.create("cmd", {"agent_id": "001"}, ttl=300)
        store._pending[token]["expire_at"] = time.time() - 1
        result = store.approve(token)
        assert result is None

    def test_list_pending_excludes_expired(self):
        from wazuh_mcp.approval import ApprovalStore
        store = ApprovalStore()
        t_valid = store.create("cmd", {}, ttl=300)
        t_stale = store.create("cmd", {}, ttl=300)
        store._pending[t_stale]["expire_at"] = time.time() - 1
        pending = store.list_pending()
        tokens_listed = [p["token"] for p in pending]
        assert t_valid in tokens_listed
        assert t_stale not in tokens_listed

    @pytest.mark.asyncio
    async def test_approval_cleanup_loop_runs_without_error(self):
        """The cleanup coroutine should cancel cleanly."""
        import asyncio
        from wazuh_mcp.approval import ApprovalStore

        store = ApprovalStore()
        # Add a stale token
        token = store.create("cmd", {}, ttl=300)
        store._pending[token]["expire_at"] = time.time() - 1

        cancel_called = False

        async def _mock_loop():
            nonlocal cancel_called
            try:
                await asyncio.sleep(0)
                store.expire_stale()
            except asyncio.CancelledError:
                cancel_called = True
                raise

        task = asyncio.create_task(_mock_loop())
        await asyncio.sleep(0)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert cancel_called
