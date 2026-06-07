from .common import random_str
import kubernetes
from .conftest import kubernetes_api_client, user_project_client

CERT = """-----BEGIN CERTIFICATE-----
MIIDEDCCAfgCCQC+HwE8rpMN7jANBgkqhkiG9w0BAQUFADBKMQswCQYDVQQGEwJV
UzEQMA4GA1UECBMHQXJpem9uYTEVMBMGA1UEChMMUmFuY2hlciBMYWJzMRIwEAYD
VQQDEwlsb2NhbGhvc3QwHhcNMTYwNjMwMDExMzMyWhcNMjYwNjI4MDExMzMyWjBK
MQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTEVMBMGA1UEChMMUmFuY2hl
ciBMYWJzMRIwEAYDVQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQC1PR0EiJjM0wbFQmU/yKSb7AuQdzhdW02ya+RQe+31/B+sOTMr
z9b473KCKf8LiFKFOIQUhR5fPvwyrrIWKCEV9pCp/wM474fX32j0zYaH6ezZjL0r
L6hTeGFScGse3dk7ej2+6nNWexpujos0djFi9Gu11iVHIJyT2Sx66kPPPZVRkJO9
5Pfetm5SLIQtJHUwy5iWv5Br+AbdXlUAjTYUqS4mhKIIbblAPbOKrYRxGXX/6oDV
J5OGLle8Uvlb8poxqmy67FPyMObNHhjggKwboXhmNuuT2OGf/VeZANMYubs4JP2V
ZLs3U/1tFMAOaQM+PbT9JuwMSmGYFX0Qiuh/AgMBAAEwDQYJKoZIhvcNAQEFBQAD
ggEBACpkRCQpCn/zmTOwboBckkOFeqMVo9cvSu0Sez6EPED4WUv/6q5tlJeHekQm
6YVcsXeOMkpfZ7qtGmBDwR+ly7D43dCiPKplm0uApO1CkogG5ePv0agvKHEybd36
xu9pt0fnxDdrP2NrP6trHq1D+CzPZooLRfmYqbt1xmIb00GpnyiJIUNuMu7GUM3q
NxWGK3eq+1cyt6xr8nLOC5zaGeSyZikw4+9vqLudNSyYdnw9mdHtrYT0GlcEP1Vc
NK+yrhDCvEWH6+4+pp8Ve2P2Le5tvbA1m24AxyuC9wHS5bUmiNHweLXNpxLFTjK8
BBUi6y1Vm9jrDi/LiiHcN4sJEoU=
-----END CERTIFICATE-----"""

KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtT0dBIiYzNMGxUJlP8ikm+wLkHc4XVtNsmvkUHvt9fwfrDkz
k0/o+Q4hlRy/T8xULrhbnbfHwO35ac9duxqmqBkmUG0TVM+H362p1t5AR+mu3vu7
di+Sc3VaDYVtQA1lR0Z5UfRxCnWyNU0HbdNxqAPXohxuPtOPP4gQeniuZx0TOMVU
uub10lIAIrZhtcj9CRgxKx+ed/gJ8w7NGn37EVJagsaPcQ74sg8tDe9GREc1/+jy
9YYimG7uKyo2V/lnZumhFxHL3VawAM0h0QVtH3a9knLJD2mkO/1ooGXIcAz0lHY0
OhT8P6a3nVltycBedy80/IlBxbeSEut3GVIgmHmUDouEDxfypmRWNPz6O6lLUsDz
5AUmvz9EbRJuURJezE4BBdoD1nQ2iWEpgTvc33yZdZz34WBAQgupF0Lh2alSM0NP
ozNMBQQb+U7myimuZgESXR9UpsPwGRTh2tLSkl6naITZoOyq8dxvkL5G2kcPIZ/Q
R8Sibeoue1B4CW9kIVjPd7A7JSEVm1roeyR9McZtk/f5iFv/HItzSbgRq/c4om6Q
RbJFYmSsKgtjg4ArrKZUEoP4PtpUbw3006KLaFs85yyLLUMFGezIRXa6S/PQvdgO
L/v7pu7fdiGiYAsa/TkUlQ/aT9JTNDjqSU0LrdN2WeZEtGLeDi4CUlZ/J5w+agXB
DlcklZQhoVnz57HftNNH916RSF4DCxqkS8sTjnx1PjfEHQqz9eDy4uXzQ5fF5Pru
IkaLeO96rqUH6r7NmXlHlTD3ptuwLjZubCRCxHHvVqhpuI5J0SD0kv/kNcdfJEIG
rXDae7ES5LG82YAOY4bUmBqfFlJX/Ut49tdxL0HWt/p2Z3LT0+k2AlbsoiRY0q+I
MzqcaxjQtdK5+XNb0s1xhYZLiHi8kJOf6B864qA5YrAGfc/GcvaKO0StpGUEQU+t
3b0s3f3FZvU3DD1ELuWH2IuaMCMA2J38y7Du5MsyWlmFiU2f1xYRd4gYhTaxtFNS
1WBTaAH1VH49LAQ/UsuWXfFpaoNeFHkrTYGTqavogVJBM9+jsIRXBGuhL42zRA4g
tkbffskggJ/4Wla9XNjg+ZG3gvGm7MSA8XEH85H/4zst70lEhnqVj3jmkxMO+DC/
EPRVk3+/68kREvRXg3GXo2BESrxzWwkCEGo9mifogRJC8nfzUlR35QVsxcSIjtBd
jxgwAt8rkDZXOkVrwcLOqbUJgbLP2RRtA0Yihdd4rgu15Hj96R09CCO/Du2VqoDv
vMeS+1zr2HjzTcNQJNlvSwiwECoWvjqGr1IVCzVSLQrSYkc7T+8cszQLVJ4/wFzB
lK+njYfEbh7i8vuymG8VyAo6o/+oG7eKRWga9rSydV0NdXhhPjkXwIGwPAy1xVQA
35Hj2bqVFWDc4H5ujRM2JEZFMopW5LzdhTV82e/ZbexntNwc0Aj/z5HfvT/lrA9x
bgS5WblkVAxBNoNryQwzqpRzwXYYzkPzr6cOJNh32YnScgI073NUY+DEC91Mcpnp
qqNpPBnP9r2LdeACXqWjzslykhjp3lnhyE9+FF1+cxp4FW5XvX6x
-----END RSA PRIVATE KEY-----"""

MALFORMED_CERT = """-----BEGIN CERTIFICATE-----
MIIDEDCCAfgCCQC+HwE8rpMN7jANBgkqhkiG9w0BAQUFADBKMQswCQYDVQQGEwJV
UzEQMA4GA1UECBMHQXJpem9uYTEVMBMGA1UEChMMUmFuY2hlciBMYWJzMRIwEAYD
VQQDEwlsb2NhbGhvc3QwHhcNMTYwNjMwMDExMzMyWhcNMjYwNjI4MDExMzMyWjBK
MQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTEVMBMGA1UEChMMUmFuY2hl
ciBMYWJzMRIwEAYDVQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQC1PR0EiJjM0wbFQmU/yKSb7AuQdzhdW02ya+RQe+31/B+sOTMr
z9b473KCKf8LiFKFOxyuC9wHS5bUmiNHweLXNpxLFTjK8
BBUi6y1Vm9jrDi/LiiHcN4sJEoU=
-----END CERTIFICATE-----"""


def test_secrets(admin_pc):
    client = admin_pc.client

    name = random_str()
    secret = client.create_secret(name=name, stringData={
        'foo': 'bar'
    })

    assert secret.type == 'secret'
    assert secret.kind == 'Opaque'
    assert secret.name == name
    assert secret.data.foo == 'YmFy'

    secret.data.baz = 'YmFy'
    secret = client.update(secret, data=secret.data)
    secret = client.reload(secret)

    assert secret.baseType == 'secret'
    assert secret.type == 'secret'
    assert secret.kind == 'Opaque'
    assert secret.name == name
    assert secret.data.foo == 'YmFy'
    assert secret.data.baz == 'YmFy'
    assert secret.namespaceId is None
    assert 'namespace' not in secret.data
    assert secret.projectId == admin_pc.project.id

    found = False
    for i in client.list_secret():
        if i.id == secret.id:
            found = True
            break

    assert found

    client.delete(secret)


def test_certificates(admin_pc):
    client = admin_pc.client

    name = random_str()
    cert = client.create_certificate(name=name, key=KEY, certs=CERT)
    assert cert.baseType == 'secret'
    assert cert.expiresAt == '2026-06-28T01:13:32Z'
    assert cert.type == 'certificate'
    assert cert.name == name
    assert cert.certs == CERT
    assert cert.namespaceId is None
    assert 'namespace' not in cert

    # cert = client.update(cert, certs='certdata2')
    # cert = client.reload(cert)
    #
    # assert cert.baseType == 'secret'
    # assert cert.type == 'certificate'
    # assert cert.name == name
    # assert cert.certs == 'certdata2'
    # assert cert.namespaceId is None
    # assert 'namespace' not in cert
    # assert cert.projectId == pc.project.id

    found = False
    for i in client.list_certificate():
        if i.id == cert.id:
            found = True
            break

    assert found

    cert = client.by_id_certificate(cert.id)
    assert cert is not None

    client.delete(cert)


def test_docker_credential(admin_pc):
    client = admin_pc.client

    name = random_str()
    registries = {'index.docker.io': {
        'username': 'foo',
        'password': 'bar',
    }}
    cert = client.create_docker_credential(name=name,
                                           registries=registries)
    assert cert.baseType == 'secret'
    assert cert.type == 'dockerCredential'
    assert cert.name == name
    assert cert.registries['index.docker.io'].username == 'foo'
    assert 'password' in cert.registries['index.docker.io']
    assert 'auth' in cert.registries['index.docker.io']
    assert cert.namespaceId is None
    assert 'namespace' not in cert
    assert cert.projectId == admin_pc.project.id

    registries['two'] = {
        'username': 'blah'
    }

    cert = client.update(cert, registries=registries)
    cert = client.reload(cert)

    assert cert.baseType == 'secret'
    assert cert.type == 'dockerCredential'
    assert cert.name == name
    assert cert.registries['index.docker.io'].username == 'foo'
    assert cert.registries.two.username == 'blah'
    assert 'password' not in cert.registries['index.docker.io']
    assert cert.namespaceId is None
    assert 'namespace' not in cert
    assert cert.projectId == admin_pc.project.id

    found = False
    for i in client.list_docker_credential():
        if i.id == cert.id:
            found = True
            break

    assert found

    cert = client.by_id_docker_credential(cert.id)
    assert cert is not None

    client.delete(cert)


def test_basic_auth(admin_pc):
    client = admin_pc.client

    name = random_str()
    cert = client.create_basic_auth(name=name,
                                    username='foo',
                                    password='bar')
    assert cert.baseType == 'secret'
    assert cert.type == 'basicAuth'
    assert cert.name == name
    assert cert.username == 'foo'
    assert 'password' in cert
    assert cert.namespaceId is None
    assert 'namespace' not in cert
    assert cert.projectId == admin_pc.project.id

    cert = client.update(cert, username='foo2')
    cert = client.reload(cert)

    assert cert.baseType == 'secret'
    assert cert.type == 'basicAuth'
    assert cert.name == name
    assert cert.username == 'foo2'
    assert 'password' not in cert
    assert cert.namespaceId is None
    assert 'namespace' not in cert
    assert cert.projectId == admin_pc.project.id

    found = False
    for i in client.list_basic_auth():
        if i.id == cert.id:
            found = True
            break

    assert found

    cert = client.by_id_basic_auth(cert.id)
    assert cert is not None

    client.delete(cert)


def test_ssh_auth(admin_pc):
    client = admin_pc.client

    name = random_str()
    cert = client.create_ssh_auth(name=name,
                                  privateKey='foo')
    assert cert.baseType == 'secret'
    assert cert.type == 'sshAuth'
    assert cert.name == name
    assert 'privateKey' in cert
    assert cert.namespaceId is None
    assert 'namespace' not in cert
    assert cert.projectId == admin_pc.project.id

    cert = client.update(cert, privateKey='foo2')
    cert = client.reload(cert)
    assert cert.baseType == 'secret'
    assert cert.type == 'sshAuth'
    assert cert.name == name
    assert 'privateKey' not in cert
    assert cert.namespaceId is None
    assert 'namespace' not in cert
    assert cert.projectId == admin_pc.project.id

    found = False
    for i in client.list_ssh_auth():
        if i.id == cert.id:
            found = True
            break

    assert found

    cert = client.by_id_ssh_auth(cert.id)
    assert cert is not None

    client.delete(cert)


def test_secret_creation_kubectl(admin_mc, admin_cc, remove_resource):
    name = random_str()
    project = admin_mc.client.create_project(name=random_str(),
                                             clusterId='local')
    remove_resource(project)
    namespace_name = random_str()
    ns = admin_cc.client.create_namespace(name=namespace_name,
                                          projectId=project.id)
    remove_resource(ns)

    k8s_client = kubernetes_api_client(admin_mc.client, 'local')
    secrets_api = kubernetes.client.CoreV1Api(k8s_client)

    secret = kubernetes.client.V1Secret()
    # Metadata
    secret.metadata = kubernetes.client.V1ObjectMeta(
        name=name,
        namespace=namespace_name)
    secret.string_data = {'tls.key': KEY, 'tls.crt': CERT}
    secret.type = "kubernetes.io/tls"

    sec = secrets_api.create_namespaced_secret(namespace=namespace_name,
                                               body=secret)
    remove_resource(sec)
    assert sec is not None

    # now get this through rancher api as namespacedCertificate
    cert_id = namespace_name+':'+name
    proj_client = user_project_client(admin_mc, project)
    cert = proj_client.by_id_namespaced_certificate(cert_id)
    assert cert is not None
    assert "RSA" in cert['algorithm']
    assert cert['expiresAt'] is not None
    assert cert['issuedAt'] is not None


def test_malformed_secret_parse(admin_mc, admin_cc, remove_resource):
    name = random_str()
    project = admin_mc.client.create_project(name=random_str(),
                                             clusterId='local')
    remove_resource(project)
    namespace_name = random_str()
    ns = admin_cc.client.create_namespace(name=namespace_name,
                                          projectId=project.id)
    remove_resource(ns)

    k8s_client = kubernetes_api_client(admin_mc.client, 'local')
    secrets_api = kubernetes.client.CoreV1Api(k8s_client)

    secret = kubernetes.client.V1Secret()
    # Metadata
    secret.metadata = kubernetes.client.V1ObjectMeta(
        name=name,
        namespace=namespace_name)
    secret.string_data = {'tls.key': KEY, 'tls.crt': MALFORMED_CERT}
    secret.type = "kubernetes.io/tls"

    sec = secrets_api.create_namespaced_secret(namespace=namespace_name,
                                               body=secret)
    remove_resource(sec)
    assert sec is not None

    # now get this through rancher api as namespacedCertificate
    cert_id = namespace_name+':'+name
    proj_client = user_project_client(admin_mc, project)
    cert = proj_client.by_id_namespaced_certificate(cert_id)
    assert cert is not None
