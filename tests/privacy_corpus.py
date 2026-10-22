"""The privacy corpus (owner, 2026-10-21): a sample of every class WARDEN masks, and the evidence it must not.

Shared by tests/test_redaction_classes.py (WARDEN's patterns, the egress check) and tests/test_datadog_agent_masking.py
(the lab's Datadog agent). Values are built from parts where their shape alone would trip a secret scanner."""

from __future__ import annotations

from fakes import HUNTER2

MASKED = {
    "EMAIL": ["user priya" + "@" + "corp.example failed", "to=ops%40" + "corp.example"],
    "PHONE": ["call +1 415 555 0142", "phone=4155550142"],
    "NAME": ["full_name=Priya Nair", '"customer_name": "Raj Mehta"', "first name: Asha", "username=asha.rao",
             "assigned to Dr. Meera Iyer", "Mrs Kapoor called", "Dear Ravi Kumar,", "cardholder_name=J Doe"],
    "IPV4": ["src=10.4.12.9", "node ip-10-0-3-22.ec2.internal"],
    "IPV6": ["from 2001:db8::8a2e:370:7334 refused"],
    "MAC": ["eth0 00:1a:2b:3c:4d:5e up", "port 001a.2b3c.4d5e"],
    "ACCOUNTID": ["account 1234" + "56789012"],
    "TENANT": ["tenant_id=acme-42", "org_id: globex7", '"user_id": "u-99812"'],
    "HOSTNAME": ["db at billing-db.prod.corp:5432", "smb://files.lan/share", "ldap.intranet refused",
                 "printer.local offline", "nas.home.arpa"],
    "APIKEY": ["key " + "sk-ant-" + "api03-abcdefghijklmnop", "AKIA" + "IOSFODNN7EXAMPLE"],
    "SECRET": ["password=" + HUNTER2 + "x", "client_secret: s3cr3tvalue"],
    "CREDITCARD": ["card 4111 1111 1111 1111", "card 4242 4242 4242 4242", "card 5555-5555-5555-4444"],
    "SSN": ["ssn 123-45-6789 on file"],
    "AADHAAR": ["aadhaar 2345 6789 0123"],
    "PAN": ["pan " + "ABCPD" + "1234E"],
    "ADDRESS": ["ships to 221B Baker Street", "office at 12 MG Road", "lives at 4 Shanti Nagar"],
}

# Evidence that must stay as it is: WARDEN reads, cites and acts on these.
KEPT = [
    "2026-10-21T10:02:11Z checkout ERROR 500 upstream timeout",
    "name=orders-api replicas=3",
    "orders.shop.svc.cluster.local:8080 refused",
    "node ip-<IPV4_1>.ap-south-1.compute.internal",
    "image registry/shop/checkout:1.4.2-rc1",
    "task 4471 exited with code 137 (OOMKilled)",
    "HTTP 503 from payments in 1200 ms",
    "rule warden-dev-lab-tick-silent",
    "Main St",
    "at jdk.internal.reflect.Method.invoke(Method.java:566)",
    "kotlin.internal.PlatformImplementationsKt.getIMPLEMENTATIONS",
    "File threading.py, in threading.local()",
]
