# trivy-sandbox

```shell
$ trivy --version
Version: 0.28.1

$ trivy conf  --policy policies/policy --namespaces user manifests/
```

## Test

```shell
$ opa test policies
$ conftest verify -p policies/
```
