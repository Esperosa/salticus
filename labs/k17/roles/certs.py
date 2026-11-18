"""Lab CA a certifikáty web.lab.test: platný a prošlý (pro S10). Výstup do /out/ca a /tmp/tls."""
import datetime as dt, os, sys
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

def key():
    return ec.generate_private_key(ec.SECP256R1())

def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

def pem(obj):
    return obj.public_bytes(serialization.Encoding.PEM)

def kpem(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

now = dt.datetime.now(dt.timezone.utc)
os.makedirs("/out/ca", exist_ok=True); os.makedirs("/tmp/tls", exist_ok=True)
ca_path = "/out/ca/ca.pem"
if os.path.exists(ca_path) and os.path.exists("/out/ca/ca.key"):
    ca_key = serialization.load_pem_private_key(open("/out/ca/ca.key", "rb").read(), None)
    ca = x509.load_pem_x509_certificate(open(ca_path, "rb").read())
else:
    ca_key = key()
    ca = (x509.CertificateBuilder().subject_name(name("k17 lab CA")).issuer_name(name("k17 lab CA"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(days=30)).not_valid_after(now + dt.timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    open("/out/ca/ca.key.tmp", "wb").write(kpem(ca_key)); os.replace("/out/ca/ca.key.tmp", "/out/ca/ca.key")
    open(ca_path + ".tmp", "wb").write(pem(ca)); os.replace(ca_path + ".tmp", ca_path)

def leaf(start, end, out):
    k = key()
    san = x509.SubjectAlternativeName([x509.DNSName(n) for n in ("web.lab.test", "app.lab.test", "files.lab.test", "api.lab.test")])
    c = (x509.CertificateBuilder().subject_name(name("web.lab.test")).issuer_name(ca.subject)
         .public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(start).not_valid_after(end).add_extension(san, critical=False)
         .sign(ca_key, hashes.SHA256()))
    open(f"/tmp/tls/{out}.crt", "wb").write(pem(c)); open(f"/tmp/tls/{out}.key", "wb").write(kpem(k))

leaf(now - dt.timedelta(days=10), now + dt.timedelta(days=90), "valid")
leaf(now - dt.timedelta(days=100), now - dt.timedelta(days=2), "expired")
