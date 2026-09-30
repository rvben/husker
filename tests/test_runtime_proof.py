"""Check the live proof's workload locally without claiming VM validation."""
import importlib.util
import json
from pathlib import Path
import threading
import unittest
from urllib.request import Request, urlopen

spec = importlib.util.spec_from_file_location("proof_guest", Path(__file__).resolve().parents[1] /
                                           "scripts/ci/dev_proof_guest.py")
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)


class ProofWorkloadTests(unittest.TestCase):
    def test_readiness_does_not_mutate_warm_state_and_timers_progress(self):
        with guest.ProofServer(("127.0.0.1", 0)) as server:
            worker = threading.Thread(target=server.serve_forever)
            worker.start()
            try:
                def get(path):
                    request = Request("http://127.0.0.1:%s%s" % (server.server_port, path),
                                      headers={"User-Agent": "husker-runtime-proof-test"})
                    with urlopen(request, timeout=3) as response:
                        return json.load(response)
                self.assertTrue(get("/health")["ready"])
                before, after = get("/state"), get("/state")
                self.assertEqual((before["counter"], after["counter"]), (1, 2))
                self.assertEqual(before["pid"], after["pid"])
                self.assertNotEqual(before["entropy"], after["entropy"])
                self.assertGreaterEqual(after["monotonic"], before["monotonic"])
                self.assertGreaterEqual(get("/timer")["elapsed"], 0.09)
            finally:
                server.shutdown()
                worker.join()
