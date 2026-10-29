# AWS SDK protocol qualification cell

This separate uv project qualifies the current Cryptalis source against the real
boto3/botocore request serializer, KMS service model, error types and Stubber.
It does not contact AWS. Explicit public synthetic credentials bypass credential
resolution; fixture tripwires reject credential discovery and HTTP transport.
The transport tripwire has an intentional failure control before each test.

The recorded Linux x86_64 cell uses CPython 3.12.14, uv 0.12.23,
boto3 1.42.89, botocore 1.42.97, SQLAlchemy 2.1.3 and SQLModel 0.0.48.
The SDK pair retains the prior observed compatible versions recorded in
[`aws-kms-sdk-environment-20261023.json`](../../docs/_reset/aws-kms-sdk-environment-20261023.json).
This is current-source requalification of that pair, not a claim about newer SDKs.

From the repository root, create a separate environment:

```sh
UV_CACHE_DIR=/workspace/.cache/uv UV_PROJECT_ENVIRONMENT=/workspace/.cryptalis-cloud/aws-sdk-venv uv sync --project qualification/aws-sdk --locked --python 3.12.14 --default-index https://pypi.org/simple
```

The uv lock records exact registry versions and artifact hashes. The editable
Cryptalis dependency explicitly selects this checkout; the mandatory wrapper
checks every imported Cryptalis module against that source before and after tests.
The exported `requirements.txt` contains registry dependencies with hashes and
excludes editable Cryptalis. It is not a complete standalone deployment input.
Regenerate that export only after reviewing a lock change:

```sh
UV_CACHE_DIR=/workspace/.cache/uv uv export --project qualification/aws-sdk --locked --format requirements-txt --no-emit-package cryptalis --output-file qualification/aws-sdk/requirements.txt --default-index https://pypi.org/simple
```

Configure the already authorized disposable PostgreSQL 16 target through the
normal private wrapper files. Keep those files outside Git. Run all tests through
the wrapper, including this SDK-only profile:

```sh
/workspace/.cryptalis-cloud/aws-sdk-venv/bin/python scripts/test_postgres.py --receipt /tmp/cryptalis-aws-sdk-new-receipt.json --scope 'Actual SDK protocol and direct rewrap recovery; no live AWS access' -- tests/profile_aws_kms_sdk.py tests/test_aws_kms.py tests/test_cf1.py tests/test_rewrap_preparation.py -q
```

Use a new receipt path. A failed database or runtime-binding probe stops the run.
The host's managed environment may require its normal socket/network permission
for the PostgreSQL probes; SDK transport stays denied by the fixture.

The recorded protocol run passes 129 tests, including 22 actual-SDK protocol
cases, with stable source and runtime bindings. Direct-rewrap cases use both AWS
and development source providers, distinct source/target identities and exact
source unwrap → target wrap → target unwrap requests. Wrong roots, short material,
wrong response key identity and a disabled target refuse. Original source custody
and healthy retry remain usable. Existing context/serialization, service-error,
malformed-response and cancellation checks also pass.

Stubber supplies responses. These checks do not establish service cryptography,
live custody, IAM, workload identity, remote cancellation, deletion, production
operation or independent security review. The product runtime lock and existing
HTTP wheel environment are unchanged. All seven production gates remain UNKNOWN.

A subsequent 149-check source selection also includes the SDK cases and the
runtime tenant prelookup correction. That selection verifies pinned membership
and exact tenant type before the host resolver. Neither selection contacts AWS.
