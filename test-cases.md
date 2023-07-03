## Tests cases examples

### Test 1, run trivy scan for AppSecret

```
  curl -X 'POST' 'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "AppSecret",
  "target": "/root/.aws",
  "host": "devhost",
  "vrn": "vrn01",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```

### Test 2, run trivy scan for DockerConfig

```
  curl -X 'POST' 'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "DockerConfig",
  "target": "/root/downloads/altprobe-docker",
  "host": "devhost",
  "vrn": "vrn01",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```

### Test 3, run trivy scan for K8sConfig

```
  curl -X 'POST' 'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "K8sConfig",
  "target": "cluster",
  "host": "master-node",
  "vrn": "vrn02",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```

### Test 4, run trivy scan for AppVuln

```
  curl -X 'POST' 'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "AppVuln",
  "target": "/root/downloads/VulnNodeApp",
  "host": "devhost",
  "vrn": "vrn01",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```

### Test 5, run trivy scan for DockerVuln

```
  curl -X 'POST' 'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "DockerVuln",
  "target": "projectdiscovery/nuclei",
  "host": "devhost",
  "vrn": "vrn01",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```

### Test 6, run trivy scan for K8sVuln

```
  curl -X 'POST' 'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "K8sVuln",
  "target": "cluster",
  "host": "master-node",
  "vrn": "vrn02",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```

### Test 7, run trivy scan for AppSbom

```
  curl -X 'POST' 'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "AppSbom",
  "target": "/root/downloads/VulnNodeApp",
  "host": "devhost",
  "vrn": "vrn01",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```

### Test 8, run trivy scan for DockerSbom

```
  curl -X 'POST' 'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "DockerSbom",
  "target": "projectdiscovery/nuclei",
  "host": "devhost",
  "vrn": "vrn01",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```
 
### Test 9, run trivy scan for CloudFormation

```
  curl -X 'POST' 'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "CloudFormation",
  "target": "/root/downloads/cloud-formation",
  "host": "devhost",
  "vrn": "vrn01",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```

### Test 10, run trivy scan for Terraform

```
  curl -X 'POST' 'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "Terraform",
  "target": "/root/downloads/terraform-examples",
  "host": "devhost",
  "vrn": "vrn01",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```

### Test 11, run KubeHunter scan

```
  curl -X 'POST' 'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "KubeHunter",
  "target": "192.168.1.70",
  "host": "devhost",
  "vrn": "vrn01",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```

### Test 12, run ZAP scan

```
  curl -X 'POST' 'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "ZAP",
  "target": "http://192.168.1.20",
  "host": "devhost",
  "vrn": "vrn01",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```

### Test 13, run Nmap scan

```
  curl -X 'POST' 'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "Nmap",
  "target": "192.168.1.20",
  "host": "devhost",
  "vrn": "vrn01",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```

### Test 14, run Nuclei scan

```
  curl -X 'POST' 'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "Nuclei",
  "target": "192.168.1.20",
  "host": "devhost",
  "vrn": "vrn01",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```

### Test 15, run Nikto scan

```
  curl -X 'POST' 'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "Nikto",
  "target": "http://192.168.1.20",
  "host": "devhost",
  "vrn": "vrn01",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```

### Test 16, run CloudSploit scan

```
  curl -X 'POST' 'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "CloudSploit",
  "target": "aws",
  "host": "devhost",
  "vrn": "vrn01",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```

### Test 17, run Semgrep scan

```
  curl -X 'POST' \
  'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "Semgrep",
  "target": "/root/downloads/semgrep-test",
  "host": "devhost",
  "vrn": "vrn01",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```

### Test 18, run SonarQube scan

```
  curl -X 'POST' \
  'http://192.168.1.20:8080/alertflex-ctrl/rest/posture' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
  "delay": 1000,
  "alertCorr": "AllFindings",
  "postureType": "SonarQube",
  "target": "/root/downloads/VulnNodeApp",
  "host": "devhost",
  "vrn": "vrn01",
  "project": "5a50c6fe-ef05-49b8-9d21-14567b58d4e7"
  }'
```
