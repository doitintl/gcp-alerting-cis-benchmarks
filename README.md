# Security Alerts for Cloud Monitoring
The following suggestions are to enhance Google Cloud Platform's Cloud Monitoring by adding additional security monitoring and alerting based on CIS benchmarks.

# Tip: stay current with CIS/NIST
It is recommended that you check the latest [Security Command Center Remediations](https://cloud.google.com/security-command-center/docs/how-to-remediate-security-health-analytics-findings) and search the page for "MONITORING" for any additional recommended checks by CIS and NIST.

# SSH
OS Login enables centralized SSH key management with IAM, and it disables metadata-based SSH key configuration on all instances in a project. OS Login can be enabled on the project level or on the instance level. Instance-level values override the project-level value.

* [OS Login Reference](https://cloud.google.com/compute/docs/instances/managing-instance-access?_ga=2.58720429.-1642039105.1585611311)

## Instructions
1. Access project
   * https://console.cloud.google.com/compute/instances?project=[project-id]
2. Click **Metadata**
3. Click **Edit**, and then click **Add item**.
4. Add an item with key **enable-oslogin** and value **TRUE**.
5. Click **Save**.


# LOGGING
These are the recommended filters, metrics, and alert policies to configure per project to adhere to CIS benchmarks. Repeat the `CREATE METRIC` and `CREATE ALERT POLICY` steps for each filter listed below.

## CREATE METRIC:
Go to https://console.cloud.google.com/logs/viewer?project=[project-id] click "CREATE METRIC", click the drop-down menu in the right-hand side of the search bar and select "Convert to advanced filter", clear any text from Advanced Filter and add the RecommendedLogFilter, set "Type" to "Counter" and "Units" to 1 (default), fill out the remaining fields and click "Create Metric". 

## CREATE ALERT POLICY:
Go to https://console.cloud.google.com/logs/metrics?project=[project-id] and in the section "User-defined Metrics", for the target metric (any one from the QualifiedLogMetricNames), click 3 dot icon in rightmost column and select "Create alert from Metric" (create a Stackdriver workspace for the project if you have not). In the Target section of the Alerting / Policies / Create window, remove "Resource type" from "Find resource type and metric" if it is there, leave "Filter" as is, set "Aligner" to "rate", "Reducer" to "count", and "Alignment Period" to 1 minute. Use the default values in the "Configuration" section and click "Save". In the overview page, add desired notification channel, and then click "Save".

## FILTERS:

### ROUTE_MONITORING
* `CIS 2.8`
```
resource.type="gce_route" AND jsonPayload.event_subtype="compute.routes.delete" OR jsonPayload.event_subtype="compute.routes.insert"
```

### SQL_INSTANCE_MONITORING
* `CIS 2.11`
```
protoPayload.methodName="cloudsql.instances.update"
```

### NETWORK_MONITORING
* `CIS 2.9`
```
resource.type=gce_network AND jsonPayload.event_subtype="compute.networks.insert" OR jsonPayload.event_subtype="compute.networks.patch" OR jsonPayload.event_subtype="compute.networks.delete" OR jsonPayload.event_subtype="compute.networks.removePeering" OR jsonPayload.event_subtype="compute.networks.addPeering"
```

### FIREWALL_MONITORING
* `CIS 2.7`
```
resource.type="gce_firewall_rule" AND jsonPayload.event_subtype="compute.firewalls.patch" OR jsonPayload.event_subtype="compute.firewalls.insert"
```

### OWNER_MONITORING
* `CIS 2.4`
```
(protoPayload.serviceName="cloudresourcemanager.googleapis.com") AND (ProjectOwnership OR projectOwnerInvitee) OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="REMOVE" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner") OR (protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD" AND protoPayload.serviceData.policyDelta.bindingDeltas.role="roles/owner")
```

### BUCKET_IAM_MONITORING
* `CIS 2.10`
```
resource.type=gcs_bucket AND protoPayload.methodName="storage.setIamPermissions"
```

### AUDIT_CONFIG_MONITORING
* `CIS 2.5`
```
protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*
```

### CUSTOM_ROLE_MONITORING
* `CIS 2.6`
```
resource.type="iam_role" AND protoPayload.methodName="google.iam.admin.v1.CreateRole" OR protoPayload.methodName="google.iam.admin.v1.DeleteRole" OR protoPayload.methodName="google.iam.admin.v1.UpdateRole"
```
