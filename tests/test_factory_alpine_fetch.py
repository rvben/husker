import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from fetch_factory_alpine import NoRedirect, REPOSITORY, fetch, selected_packages
from prepare_factory_arm64 import sha
import test_factory_apk as apk_fixtures


class Response(io.BytesIO):
    def __init__(self, blob, url):
        super().__init__(blob); self.url = url


class AlpineFetchTests(unittest.TestCase):
    def fixture(self, root):
        blob, package, *_ = apk_fixtures.ApkTests().fixture()
        package.update(origin='index',filename='tool-1.0-r0.apk')
        plan = root/'closure.json'
        plan.write_text(json.dumps({'version':1,'architecture':'aarch64','packages':{'tool':package}}))
        return blob, plan

    def test_private_verified_download_with_generic_identification(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); blob, plan = self.fixture(root)
            def request(request,timeout):
                self.assertEqual(request.full_url,REPOSITORY+'tool-1.0-r0.apk')
                self.assertEqual(request.get_header('User-agent'),'factory-preparation/1')
                self.assertEqual(timeout,30)
                return Response(blob,request.full_url)
            with patch('fetch_factory_alpine.urllib.request.build_opener') as opener:
                opener.return_value.open.side_effect = request
                receipt = fetch({'path':str(plan),'digest':sha(plan)},root/'output')
            self.assertEqual(len(receipt['packages']),1)
            self.assertFalse(receipt['runtime_verified'])
            self.assertEqual((root/'output/tool-1.0-r0.apk').read_bytes(),blob)
            self.assertEqual((root/'output/tool-1.0-r0.apk').stat().st_mode & 0o777,0o400)
            self.assertEqual((root/'output/downloads.json').stat().st_mode & 0o777,0o400)

    def test_corruption_redirect_and_oversize_remove_own_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); blob, plan = self.fixture(root)
            for label, contents, url in [('corrupt',b'bad',REPOSITORY+'tool-1.0-r0.apk'),
                                         ('redirect',blob,'https://example.invalid/package'),
                                         ('oversize',blob+b'x',REPOSITORY+'tool-1.0-r0.apk')]:
                with patch('fetch_factory_alpine.urllib.request.build_opener') as opener:
                    opener.return_value.open.return_value = Response(contents,url)
                    with self.assertRaises(ValueError):fetch({'path':str(plan),'digest':sha(plan)},root/label)
                self.assertFalse((root/label).exists())
            self.assertIsNone(NoRedirect().redirect_request(None,None,302,'',{},'https://example.invalid/'))

    def test_wrong_plan_pin_and_existing_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); _, plan = self.fixture(root)
            with patch('fetch_factory_alpine.urllib.request.build_opener') as opener:
                with self.assertRaises(ValueError):fetch({'path':str(plan),'digest':'sha256:'+'0'*64},root/'bad-pin')
                opener.assert_not_called()
            existing = root/'existing'; existing.mkdir(); (existing/'keep').write_text('preserve')
            with self.assertRaises(FileExistsError):fetch({'path':str(plan),'digest':sha(plan)},existing)
            self.assertEqual((existing/'keep').read_text(),'preserve')

    def test_malicious_filename_and_noninteger_size_rejected_before_network(self):
        blob, package, *_ = apk_fixtures.ApkTests().fixture()
        package.update(origin='index',filename='../secret.apk')
        plan = {'version':1,'architecture':'aarch64','packages':{'tool':package}}
        with self.assertRaises(ValueError):selected_packages(plan)
        package['filename'] = 'tool-1.0-r0.apk'; package['archive_size'] = True
        with self.assertRaises(ValueError):selected_packages(plan)


if __name__ == '__main__': unittest.main()
