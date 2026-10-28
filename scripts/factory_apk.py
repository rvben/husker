"""Bounded APK v2 integrity inspection; never install or execute package scripts."""
import base64
import hashlib
import io
import re
import tarfile
import zlib

MAX_ARCHIVE = 128 * 1024**2
MAX_DATA = 512 * 1024**2
HOOKS = {'.pre-install','.post-install','.pre-deinstall','.post-deinstall',
         '.pre-upgrade','.post-upgrade','.trigger'}


def gzip_parts(blob):
    if not 0 < len(blob) <= MAX_ARCHIVE:
        raise ValueError('APK archive exceeds bound')
    parts = []
    remaining = blob
    while remaining:
        if len(parts) >= 3:
            raise ValueError('extra APK gzip stream or trailing data')
        maximum = MAX_DATA if len(parts) == 2 else 1024*1024
        decoder = zlib.decompressobj(31)
        expanded = decoder.decompress(remaining,maximum+1)
        if len(expanded) > maximum or decoder.unconsumed_tail:
            raise ValueError('APK expanded section exceeds bound')
        if not decoder.eof:
            raise ValueError('truncated APK gzip stream')
        consumed = len(remaining)-len(decoder.unused_data)
        parts.append((remaining[:consumed],expanded))
        remaining = decoder.unused_data
    if len(parts) != 3:
        raise ValueError('signed APK v2 requires exactly three gzip sections')
    return parts


def metadata(data, signature=False):
    entries = {}
    with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
        for item in archive:
            if (len(entries) >= 16 or not item.isfile() or item.name in entries
                    or not 0 <= item.size <= 65536 or '/' in item.name
                    or (signature and not re.fullmatch(r'\.SIGN\.(RSA|RSA256|RSA512|DSA)\.[A-Za-z0-9._@+-]+',item.name))
                    or (not signature and item.name not in HOOKS | {'.PKGINFO'})):
                raise ValueError('unsupported APK signature/control entry')
            with archive.extractfile(item) as source:
                content = source.read(item.size+1)
            if len(content) != item.size:
                raise ValueError('short APK metadata entry')
            entries[item.name] = content
    if not entries:
        raise ValueError('empty APK metadata section')
    return entries


def verify_apk(blob, package, name):
    if len(blob) != package['archive_size']:
        raise ValueError('APK size does not match pinned index')
    parts = gzip_parts(blob)
    metadata(parts[0][1],signature=True)
    identity = 'Q1'+base64.b64encode(hashlib.sha1(parts[1][0]).digest()).decode('ascii')
    if identity != package['index_checksum']:
        raise ValueError('APK control checksum does not match pinned index')
    control = metadata(parts[1][1])
    if '.PKGINFO' not in control:
        raise ValueError('APK package metadata absent')
    fields = {}
    repeated = {'depend':[],'provides':[]}
    for line in control['.PKGINFO'].decode('utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition(' = ')
        if not separator:
            raise ValueError('invalid APK package metadata')
        if key in repeated:
            repeated[key].append(value)
        elif key in ('pkgname','pkgver','arch','datahash'):
            if key in fields:
                raise ValueError('duplicate APK package identity')
            fields[key] = value
    compatible_arch = (fields.get('arch') == package['architecture']
                       or package['architecture'] == 'aarch64' and fields.get('arch') == 'noarch')
    if (fields.get('pkgname') != name or fields.get('pkgver') != package['version']
            or not compatible_arch
            or sorted(set(repeated['depend'])) != sorted(set(package['dependencies']))
            or sorted(set(repeated['provides'])) != sorted(set(package['provides']))):
        raise ValueError('APK package identity/dependencies do not match resolved plan')
    if not re.fullmatch(r'[0-9a-f]{64}',fields.get('datahash','')):
        raise ValueError('APK v2 data checksum required')
    if hashlib.sha256(parts[2][0]).hexdigest() != fields['datahash']:
        raise ValueError('APK data section checksum mismatch')
    receipt = {'archive_digest':'sha256:'+hashlib.sha256(blob).hexdigest(),
               'data_digest':'sha256:'+fields['datahash'],
               'index_checksum':identity,'ignored_hooks':sorted(set(control)-{'.PKGINFO'}),
               'package_architecture':fields['arch'],
               'publisher_signature_verified':False,'runtime_verified':False}
    return receipt, parts[2][1]
