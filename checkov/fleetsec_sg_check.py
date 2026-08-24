"""
Custom Checkov policy — FleetSec.
Fails any aws_security_group / ingress rule that exposes SSH (22) or RDP (3389)
to 0.0.0.0/0. Complements the built-in CKV_AWS_24 / CKV_AWS_25 checks and gives
the pipeline an explicit, named guardrail (Entregable 03 requirement).

Load in CI:  checkov -d terraform --external-checks-dir checkov
"""
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck

FORBIDDEN_PORTS = {22, 3389}


class FleetSecNoPublicAdminPorts(BaseResourceCheck):
    def __init__(self):
        super().__init__(
            name="Ensure no SG exposes SSH(22)/RDP(3389) to 0.0.0.0/0 [FleetSec]",
            id="CKV_FLEETSEC_1",
            categories=[CheckCategories.NETWORKING],
            supported_resources=["aws_security_group", "aws_security_group_rule"],
        )

    def scan_resource_conf(self, conf):
        ingress_blocks = conf.get("ingress", [])
        # aws_security_group_rule is a single rule resource
        if conf.get("type") == ["ingress"]:
            ingress_blocks = [conf]

        for rule in ingress_blocks:
            cidrs = rule.get("cidr_blocks", [[]])
            cidrs = cidrs[0] if cidrs and isinstance(cidrs[0], list) else cidrs
            if "0.0.0.0/0" not in (cidrs or []):
                continue
            from_p = self._num(rule.get("from_port"))
            to_p = self._num(rule.get("to_port"))
            if from_p is None or to_p is None:
                continue
            for p in FORBIDDEN_PORTS:
                if from_p <= p <= to_p:
                    return CheckResult.FAILED
        return CheckResult.PASSED

    @staticmethod
    def _num(v):
        if isinstance(v, list):
            v = v[0] if v else None
        try:
            return int(v)
        except (TypeError, ValueError):
            return None


check = FleetSecNoPublicAdminPorts()


# --- Self-test: `python3 checkov/fleetsec_sg_check.py` -----------------------
# Verifies the per-rule logic independently of the Checkov runner.
if __name__ == "__main__":
    bad = {"ingress": [{"cidr_blocks": [["0.0.0.0/0"]], "from_port": [22], "to_port": [22]}]}
    rdp = {"ingress": [{"cidr_blocks": [["0.0.0.0/0"]], "from_port": [3389], "to_port": [3389]}]}
    rng = {"ingress": [{"cidr_blocks": [["0.0.0.0/0"]], "from_port": [20], "to_port": [4000]}]}
    ok_443 = {"ingress": [{"cidr_blocks": [["0.0.0.0/0"]], "from_port": [443], "to_port": [443]}]}
    ok_priv = {"ingress": [{"cidr_blocks": [["10.0.0.0/8"]], "from_port": [22], "to_port": [22]}]}
    cases = [
        ("SSH open to world", bad, CheckResult.FAILED),
        ("RDP open to world", rdp, CheckResult.FAILED),
        ("wide range covering 22", rng, CheckResult.FAILED),
        ("HTTPS open to world", ok_443, CheckResult.PASSED),
        ("SSH from private only", ok_priv, CheckResult.PASSED),
    ]
    failed = 0
    for name, conf, expected in cases:
        got = check.scan_resource_conf(conf)
        mark = "OK " if got == expected else "XX "
        if got != expected:
            failed += 1
        print(f"{mark}{name}: expected {expected.name}, got {got.name}")
    raise SystemExit(1 if failed else 0)
