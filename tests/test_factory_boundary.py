import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile
import unittest
from types import SimpleNamespace

spec=importlib.util.spec_from_file_location('boundary',Path(__file__).parents[1]/'scripts/ci/factory_boundary_e2e.py')
probe=importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)

class BoundaryTests(unittest.TestCase):
    def test_disk_capacity_supports_prepared_image_and_rejects_invalid_limits(self):
        for size in (1024**3, 2*1024**3, 8*1024**3, 32*1024**3):
            self.assertEqual(probe.proof_resources(size), dict(
                vcpu_count=1,mem_size_mib=512,disk_size_bytes=size,pids_limit=64))
        for size in (None, True, float(8*1024**3), 0, 1024**3-1,
                     8*1024**3+1, 32*1024**3+4096):
            with self.assertRaises(ValueError): probe.proof_resources(size)

    def test_inspection_uses_journaled_capacity_and_rejects_changed_resource_profile(self):
        spec = dict(commands=[dict(argv=['/workspace/factory-boundary-probe','--factory-boundary'],timeout_secs=30)],
                    correlation=dict(job='offline-boundary-proof',stage='baseline',round=0),
                    network={'mode':'none'},uid=1000,gid=1000,working_directory='/workspace',
                    environment={},writable_directories=[],artifacts=[],resources=probe.proof_resources(8*1024**3))
        probe.validate_specification(spec)
        for field, value in [('vcpu_count',2),('vcpu_count',True),('mem_size_mib',1024),
                             ('pids_limit',128),('disk_size_bytes',8*1024**3+1),('extra',1)]:
            changed=json.loads(json.dumps(spec)); changed['resources'][field]=value
            with self.assertRaises(ValueError): probe.validate_specification(changed)
        changed=json.loads(json.dumps(spec)); changed['working_directory']='/acceptance'
        with self.assertRaises(ValueError): probe.validate_specification(changed)

    def valid(self):
        records=[dict(type='check',name=name,ok=True,errno=0) for name in sorted(probe.NAMES)]
        records.append(dict(type='summary',scope='offline-job-subset-v1',checks=len(probe.NAMES),failed=0))
        return records
    def encode(self,records):
        return b'\n'.join(json.dumps(record).encode() for record in records)+b'\n'
    def test_evidence_requires_every_unique_success_and_exact_summary(self):
        records=self.valid(); self.assertEqual(len(probe.validate_output(self.encode(records),b'')),11)
        variants=[records[1:],records+[records[0]],records+[records[-1]]]
        for field,value in [('ok',False),('ok',1),('name','unknown'),('errno','0')]:
            changed=json.loads(json.dumps(records)); changed[0][field]=value; variants.append(changed)
        changed=json.loads(json.dumps(records)); changed[-1]['failed']=1; variants.append(changed)
        for value in variants:
            with self.assertRaises(ValueError): probe.validate_output(self.encode(value),b'')
        with self.assertRaises(ValueError): probe.validate_output(self.encode(records),b'unexpected')
        with self.assertRaises(ValueError): probe.validate_output(b'x'*65537,b'')
    def archive(self,entries):
        buffer=io.BytesIO()
        with tarfile.open(fileobj=buffer,mode='w') as archive:
            for name,data,mode in entries:
                item=tarfile.TarInfo(name); item.size=len(data); item.mode=mode
                archive.addfile(item,io.BytesIO(data))
        return buffer.getvalue()
    def test_proof_inputs_bind_binary_and_fixed_sentinels(self):
        binary=b'reviewed fixture probe'
        source=self.archive([('factory-boundary-probe',binary,0o755),('frozen-sentinel',probe.SENTINEL,0o644)])
        acceptance=self.archive([('frozen-sentinel',probe.SENTINEL,0o644)])
        probe.validate_inputs(source,acceptance,probe.digest(binary))
        with self.assertRaises(ValueError): probe.validate_inputs(source,acceptance,probe.digest(b'changed'))
        wrong=self.archive([('frozen-sentinel',b'changed',0o644)])
        with self.assertRaises(ValueError): probe.validate_inputs(source,wrong,probe.digest(binary))
        extra=self.archive([('frozen-sentinel',probe.SENTINEL,0o644),('unrelated',b'data',0o644)])
        with self.assertRaises(ValueError): probe.validate_inputs(source,extra,probe.digest(binary))

    def test_event_collection_rejects_truncation_and_excessive_pages(self):
        page=SimpleNamespace(output_truncated=False,events=[SimpleNamespace(stream='stdout',data=b'one')],next_cursor=1,has_more=False)
        class Job:
            def events(self,after): return page
        self.assertEqual(probe.collect_logs(Job()),(b'one',b''))
        page.output_truncated=True
        with self.assertRaises(ValueError): probe.collect_logs(Job())
        page.output_truncated=False; page.has_more=True
        with self.assertRaises(ValueError): probe.collect_logs(Job())
    def test_bounded_files_reject_symlinks_and_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); file=root/'data'; file.write_bytes(b'bounded')
            self.assertEqual(probe.bounded(file,7),b'bounded')
            with self.assertRaises(ValueError): probe.bounded(file,6)
            link=root/'link'; link.symlink_to(file)
            with self.assertRaises(OSError): probe.bounded(link,100)
    def test_native_probe_refuses_host_execution(self):
        if subprocess.check_output(['/usr/bin/uname','-s']).strip()!=b'Darwin':
            self.skipTest('native refusal fixture is for macOS; Linux runtime requires isolated guest')
        compiler=shutil.which('cc')
        if not compiler: self.skipTest('native compiler unavailable')
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'probe'
            result=subprocess.run([compiler,'-Wall','-Wextra','-Werror',str(probe.ROOT/'guest/factory/boundary-probe.c'),'-o',str(output)],capture_output=True,env={'PATH':'/usr/bin:/bin','TMPDIR':directory,'LC_ALL':'C'},timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            result=subprocess.run([str(output),'--factory-boundary'],capture_output=True,timeout=5)
            self.assertEqual(result.returncode,2)
            self.assertIn(b'refusing host execution',result.stderr)

if __name__=='__main__': unittest.main()
