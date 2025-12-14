# 🔄 Disaster Recovery Plan

**A+ System Audit Utility - Production Deployment**

## Table of Contents
1. [Overview](#overview)
2. [Recovery Objectives](#recovery-objectives)
3. [Backup Strategy](#backup-strategy)
4. [Recovery Procedures](#recovery-procedures)
5. [Failure Scenarios](#failure-scenarios)
6. [Testing & Validation](#testing--validation)

---

## Overview

This document defines disaster recovery procedures for the A+ System Audit Utility in production environments. It specifies backup strategies, recovery time objectives (RTO), recovery point objectives (RPO), and step-by-step recovery procedures for various failure scenarios.

### Scope

- **Database Recovery**: SQLite, PostgreSQL, MySQL
- **Configuration Recovery**: .env files, secrets management
- **State Recovery**: Audit history, remediation tracking
- **Application Recovery**: Service restoration, rollback procedures

### Key Personnel

| Role | Responsibility | Contact |
|------|---------------|---------|
| **Platform Owner** | Overall system responsibility | Kevin Hormaza (@OddSageID) |
| **Ops Team** | 24/7 incident response | ops-team@example.com |
| **Database Admin** | Database recovery | dba-team@example.com |
| **Security Team** | Security incident response | security@example.com |

---

## Recovery Objectives

### Recovery Time Objective (RTO)

Maximum acceptable downtime before business impact:

| Severity | RTO Target | Maximum RTO |
|----------|-----------|-------------|
| **Critical** (Production outage) | 15 minutes | 1 hour |
| **High** (Degraded service) | 1 hour | 4 hours |
| **Medium** (Non-critical feature) | 4 hours | 24 hours |
| **Low** (Cosmetic issue) | 24 hours | 1 week |

### Recovery Point Objective (RPO)

Maximum acceptable data loss:

| Data Type | RPO Target | Backup Frequency |
|-----------|-----------|------------------|
| **Audit Results** | 1 hour | Continuous replication |
| **Configuration** | 24 hours | Daily backups |
| **Database** | 1 hour | Hourly incremental + daily full |
| **Application Code** | Real-time | Git repository |

---

## Backup Strategy

### 1. Database Backups

#### SQLite (Development/Small Deployments)

```bash
#!/bin/bash
# Daily SQLite backup script
# Location: /opt/aplus-audit/scripts/backup-sqlite.sh

BACKUP_DIR="/var/backups/aplus-audit/sqlite"
DB_PATH="/app/audit_history.db"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup with SQLite checkpoint
sqlite3 "$DB_PATH" "VACUUM INTO '$BACKUP_DIR/audit_history_$TIMESTAMP.db'"

# Compress backup
gzip "$BACKUP_DIR/audit_history_$TIMESTAMP.db"

# Upload to S3 (optional)
aws s3 cp "$BACKUP_DIR/audit_history_$TIMESTAMP.db.gz" \
    s3://aplus-audit-backups/sqlite/$(date +%Y/%m/%d)/

# Clean up old backups (keep 30 days)
find "$BACKUP_DIR" -name "*.db.gz" -mtime +30 -delete

echo "✅ SQLite backup completed: audit_history_$TIMESTAMP.db.gz"
```

**Schedule**: Daily at 02:00 UTC (cron: `0 2 * * *`)

#### PostgreSQL (Production)

```bash
#!/bin/bash
# PostgreSQL backup script with point-in-time recovery
# Location: /opt/aplus-audit/scripts/backup-postgres.sh

BACKUP_DIR="/var/backups/aplus-audit/postgres"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DB_NAME="aplus_audit"
DB_USER="aplus_app"

# Full backup
pg_dump -U "$DB_USER" -F c -b -v \
    -f "$BACKUP_DIR/full_backup_$TIMESTAMP.dump" \
    "$DB_NAME"

# Compress
gzip "$BACKUP_DIR/full_backup_$TIMESTAMP.dump"

# Upload to S3 with versioning
aws s3 cp "$BACKUP_DIR/full_backup_$TIMESTAMP.dump.gz" \
    s3://aplus-audit-backups/postgres/full/$(date +%Y/%m/%d)/ \
    --storage-class STANDARD_IA

# WAL archiving for PITR (continuous)
# Configure in postgresql.conf:
# wal_level = replica
# archive_mode = on
# archive_command = 'aws s3 cp %p s3://aplus-audit-backups/postgres/wal/%f'

echo "✅ PostgreSQL full backup completed"
```

**Schedule**:
- Full backup: Daily at 01:00 UTC (cron: `0 1 * * *`)
- Incremental: Hourly (cron: `0 * * * *`)
- WAL archiving: Continuous

#### MySQL (Alternative)

```bash
#!/bin/bash
# MySQL backup script
# Location: /opt/aplus-audit/scripts/backup-mysql.sh

BACKUP_DIR="/var/backups/aplus-audit/mysql"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DB_NAME="aplus_audit"
DB_USER="aplus_app"

# Full backup with mysqldump
mysqldump -u "$DB_USER" -p"$DB_PASSWORD" \
    --single-transaction \
    --routines \
    --triggers \
    --events \
    "$DB_NAME" | gzip > "$BACKUP_DIR/full_backup_$TIMESTAMP.sql.gz"

# Binary log backup for PITR
mysqlbinlog --read-from-remote-server \
    --host=localhost \
    --user="$DB_USER" \
    --raw \
    --stop-never \
    mysql-bin.000001

echo "✅ MySQL full backup completed"
```

**Schedule**: Daily at 01:30 UTC (cron: `30 1 * * *`)

### 2. Configuration Backups

```bash
#!/bin/bash
# Configuration backup script
# Location: /opt/aplus-audit/scripts/backup-config.sh

BACKUP_DIR="/var/backups/aplus-audit/config"
APP_DIR="/opt/aplus-audit"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

# Backup configuration (excluding secrets)
tar -czf "$BACKUP_DIR/config_$TIMESTAMP.tar.gz" \
    "$APP_DIR/.env.example" \
    "$APP_DIR/config/" \
    --exclude="*.key" \
    --exclude="*.pem"

# Backup secrets (encrypted)
# Secrets should be stored in AWS Secrets Manager, HashiCorp Vault, etc.
# This is a fallback only
if [ -f "$APP_DIR/.env" ]; then
    # Encrypt with GPG before backup
    gpg --encrypt --recipient ops-team@example.com \
        "$APP_DIR/.env" \
        -o "$BACKUP_DIR/env_$TIMESTAMP.gpg"
fi

echo "✅ Configuration backup completed"
```

**Schedule**: Daily at 03:00 UTC (cron: `0 3 * * *`)

### 3. Audit Results Export

```bash
#!/bin/bash
# Export recent audit results for archival
# Location: /opt/aplus-audit/scripts/export-audits.sh

EXPORT_DIR="/var/backups/aplus-audit/exports"
TIMESTAMP=$(date +%Y%m%d)

mkdir -p "$EXPORT_DIR"

# Export last 30 days of audit results
sqlite3 /app/audit_history.db <<EOF
.headers on
.mode csv
.output $EXPORT_DIR/audits_$TIMESTAMP.csv
SELECT * FROM audit_runs WHERE timestamp >= datetime('now', '-30 days');
.quit
EOF

# Compress and upload
gzip "$EXPORT_DIR/audits_$TIMESTAMP.csv"
aws s3 cp "$EXPORT_DIR/audits_$TIMESTAMP.csv.gz" \
    s3://aplus-audit-backups/exports/$(date +%Y/%m)/

echo "✅ Audit results exported"
```

**Schedule**: Weekly on Sunday (cron: `0 4 * * 0`)

### 4. Backup Verification

```bash
#!/bin/bash
# Verify backup integrity
# Location: /opt/aplus-audit/scripts/verify-backups.sh

BACKUP_DIR="/var/backups/aplus-audit"
LOG_FILE="/var/log/aplus-audit/backup-verification.log"

echo "Starting backup verification: $(date)" >> "$LOG_FILE"

# Test SQLite backup
LATEST_SQLITE=$(ls -t $BACKUP_DIR/sqlite/*.db.gz | head -1)
if [ -f "$LATEST_SQLITE" ]; then
    gunzip -c "$LATEST_SQLITE" > /tmp/test.db
    sqlite3 /tmp/test.db "PRAGMA integrity_check;" >> "$LOG_FILE"
    rm /tmp/test.db
fi

# Test PostgreSQL backup (sample restore)
LATEST_PG=$(ls -t $BACKUP_DIR/postgres/*.dump.gz | head -1)
if [ -f "$LATEST_PG" ]; then
    createdb -U postgres test_restore_db
    gunzip -c "$LATEST_PG" | pg_restore -U postgres -d test_restore_db -v >> "$LOG_FILE" 2>&1
    dropdb -U postgres test_restore_db
fi

echo "✅ Backup verification completed" >> "$LOG_FILE"
```

**Schedule**: Weekly on Monday (cron: `0 5 * * 1`)

---

## Recovery Procedures

### Scenario 1: Complete Database Loss

**Impact**: All audit history lost  
**RTO**: 1 hour  
**RPO**: 1 hour (hourly backups)

#### Recovery Steps:

```bash
# 1. Stop application
systemctl stop aplus-audit.service

# 2. Identify latest valid backup
LATEST_BACKUP=$(aws s3 ls s3://aplus-audit-backups/postgres/full/ \
    --recursive | sort | tail -1 | awk '{print $4}')

# 3. Download backup
aws s3 cp "s3://aplus-audit-backups/$LATEST_BACKUP" \
    /tmp/restore.dump.gz

# 4. Create new database
createdb -U postgres aplus_audit

# 5. Restore from backup
gunzip -c /tmp/restore.dump.gz | pg_restore -U postgres -d aplus_audit -v

# 6. Apply WAL files for PITR (if needed)
# Get WAL files from archive
aws s3 sync s3://aplus-audit-backups/postgres/wal/ /var/lib/postgresql/wal_restore/

# Configure recovery.conf
cat > /var/lib/postgresql/data/recovery.conf <<EOF
restore_command = 'cp /var/lib/postgresql/wal_restore/%f %p'
recovery_target_time = '2024-12-14 14:30:00'
EOF

# 7. Start PostgreSQL
systemctl start postgresql

# 8. Verify database integrity
psql -U postgres -d aplus_audit -c "SELECT COUNT(*) FROM audit_runs;"

# 9. Restart application
systemctl start aplus-audit.service

# 10. Verify application functionality
python /opt/aplus-audit/main.py --quick --no-admin
```

**Verification Checklist**:
- [ ] Database contains expected number of audit runs
- [ ] Latest audit timestamp matches expectations
- [ ] Application can write new audit results
- [ ] No database errors in application logs
- [ ] All audit runs have associated findings

**Estimated Recovery Time**: 30-45 minutes

---

### Scenario 2: Corrupted Configuration

**Impact**: Application cannot start  
**RTO**: 15 minutes  
**RPO**: 24 hours

#### Recovery Steps:

```bash
# 1. Download latest configuration backup
aws s3 cp s3://aplus-audit-backups/config/latest/config.tar.gz /tmp/

# 2. Extract to temporary location
tar -xzf /tmp/config.tar.gz -C /tmp/restore/

# 3. Compare with current config
diff /opt/aplus-audit/.env.example /tmp/restore/.env.example

# 4. Restore configuration files
cp /tmp/restore/.env.example /opt/aplus-audit/
cp -r /tmp/restore/config/* /opt/aplus-audit/config/

# 5. Restore secrets (if encrypted backup exists)
aws secretsmanager get-secret-value \
    --secret-id aplus-audit/prod/env \
    --query SecretString \
    --output text > /opt/aplus-audit/.env

# 6. Verify configuration
python /opt/aplus-audit/setup_check.py

# 7. Restart application
systemctl restart aplus-audit.service
```

**Verification Checklist**:
- [ ] setup_check.py passes all checks
- [ ] Application starts without errors
- [ ] API keys are valid and working
- [ ] Database connection successful

**Estimated Recovery Time**: 10-15 minutes

---

### Scenario 3: Failed Remediation with System Damage

**Impact**: Remediation script caused system misconfiguration  
**RTO**: 30 minutes  
**RPO**: Real-time (rollback scripts)

#### Recovery Steps:

```bash
# 1. Identify the problematic remediation
SELECT script_id, check_id, executed_at, execution_log
FROM remediation_executions
WHERE execution_success = false
ORDER BY executed_at DESC
LIMIT 1;

# 2. Retrieve rollback script
SCRIPT_ID="remediation_20241214_143022"
sqlite3 /app/audit_history.db \
    "SELECT rollback_script FROM remediation_executions 
     WHERE script_id = '$SCRIPT_ID';" > /tmp/rollback.sh

# 3. Review rollback script (IMPORTANT: Always review!)
cat /tmp/rollback.sh

# 4. Execute rollback script
chmod +x /tmp/rollback.sh
bash /tmp/rollback.sh > /tmp/rollback.log 2>&1

# 5. Verify system state restored
python /opt/aplus-audit/main.py --quick --no-admin

# 6. Mark remediation as rolled back in database
sqlite3 /app/audit_history.db <<EOF
UPDATE remediation_executions
SET rolled_back = 1,
    rolled_back_at = datetime('now'),
    rollback_success = 1,
    rollback_log = '$(cat /tmp/rollback.log)'
WHERE script_id = '$SCRIPT_ID';
EOF

# 7. Document incident
echo "Rollback completed for $SCRIPT_ID at $(date)" >> /var/log/aplus-audit/rollbacks.log
```

**Verification Checklist**:
- [ ] System configuration returned to pre-remediation state
- [ ] No new security findings introduced
- [ ] Application functioning normally
- [ ] Rollback documented in database

**Estimated Recovery Time**: 20-30 minutes

---

### Scenario 4: Application Service Crash

**Impact**: Service unavailable  
**RTO**: 5 minutes  
**RPO**: None (no data loss)

#### Recovery Steps:

```bash
# 1. Check service status
systemctl status aplus-audit.service

# 2. Review recent logs
journalctl -u aplus-audit.service -n 100 --no-pager

# 3. Attempt restart
systemctl restart aplus-audit.service

# 4. If restart fails, check for:
# - Port conflicts
netstat -tulpn | grep :8080

# - File permissions
ls -la /opt/aplus-audit/

# - Database connectivity
psql -U aplus_app -d aplus_audit -c "SELECT 1;"

# 5. If issue persists, rollback to previous version
cd /opt/aplus-audit
git log --oneline -10  # Find last stable commit
git checkout <stable-commit-hash>
systemctl restart aplus-audit.service

# 6. Verify application health
curl http://localhost:8080/health
```

**Verification Checklist**:
- [ ] Service running and accepting requests
- [ ] No errors in application logs
- [ ] Database connections successful
- [ ] Can execute test audit

**Estimated Recovery Time**: 5-10 minutes

---

### Scenario 5: Data Center Outage

**Impact**: Complete infrastructure unavailable  
**RTO**: 4 hours  
**RPO**: 1 hour

#### Recovery Steps (AWS Example):

```bash
# 1. Launch recovery environment in alternate region
# Use Terraform/CloudFormation to provision infrastructure

# 2. Restore database from S3 cross-region replica
aws s3 sync s3://aplus-audit-backups-us-east-1/postgres/full/ \
    s3://aplus-audit-backups-us-west-2/postgres/full/

# 3. Deploy application from Git repository
git clone https://github.com/OddSageID/aplus-audit-utility.git
cd aplus-audit-utility
pip install -r requirements.txt

# 4. Configure for new environment
cp .env.example .env
# Update database connection strings, API endpoints, etc.

# 5. Restore database
# Follow "Scenario 1: Complete Database Loss" procedure

# 6. Update DNS/load balancer to point to recovery region
aws route53 change-resource-record-sets \
    --hosted-zone-id Z1234567890ABC \
    --change-batch file://dns-failover.json

# 7. Verify application in new region
curl https://aplus-audit.example.com/health
```

**Verification Checklist**:
- [ ] All services running in failover region
- [ ] Database fully restored with latest data
- [ ] DNS cutover completed
- [ ] Application accessible from public internet
- [ ] Monitoring and alerting operational

**Estimated Recovery Time**: 2-4 hours

---

## Failure Scenarios

### Prevention Matrix

| Failure Type | Prevention | Detection | Recovery |
|--------------|-----------|-----------|----------|
| **Database corruption** | WAL archiving, checksums | Integrity checks | PITR restore |
| **Accidental deletion** | Soft deletes, retention | Audit logs | Backup restore |
| **Configuration error** | Version control, validation | Health checks | Config rollback |
| **Code deployment bug** | CI/CD testing, staging | Monitoring | Git rollback |
| **Infrastructure failure** | Multi-AZ, auto-scaling | CloudWatch alarms | Failover |
| **Security breach** | Encryption, access control | IDS/IPS, SIEM | Incident response |
| **Data center outage** | Multi-region replication | Route53 health checks | Region failover |

---

## Testing & Validation

### Disaster Recovery Testing Schedule

| Test Type | Frequency | Objective | Duration |
|-----------|-----------|-----------|----------|
| **Backup Verification** | Weekly | Verify backup integrity | 30 minutes |
| **Database Restore** | Monthly | Test full recovery procedure | 2 hours |
| **Configuration Recovery** | Monthly | Test config restoration | 30 minutes |
| **Failover Test** | Quarterly | Test multi-region failover | 4 hours |
| **Full DR Simulation** | Annually | Test complete recovery | 8 hours |

### Test Execution Template

```bash
#!/bin/bash
# DR Test Execution Script
# Location: /opt/aplus-audit/scripts/dr-test.sh

TEST_DATE=$(date +%Y%m%d)
TEST_RESULTS="/var/log/aplus-audit/dr-tests/$TEST_DATE.log"

echo "=== DR Test Started: $(date) ===" >> "$TEST_RESULTS"

# 1. Create test environment
echo "[TEST] Creating isolated test environment..." >> "$TEST_RESULTS"
createdb -U postgres test_dr_${TEST_DATE}

# 2. Simulate failure
echo "[TEST] Simulating database corruption..." >> "$TEST_RESULTS"
# Intentionally corrupt test database

# 3. Execute recovery procedure
echo "[TEST] Executing recovery procedure..." >> "$TEST_RESULTS"
START_TIME=$(date +%s)

# Run recovery steps
# ... (specific to scenario being tested)

END_TIME=$(date +%s)
RECOVERY_DURATION=$((END_TIME - START_TIME))

# 4. Verify recovery
echo "[TEST] Verifying recovery..." >> "$TEST_RESULTS"
# Run verification checks

# 5. Calculate metrics
echo "[TEST] Recovery completed in ${RECOVERY_DURATION} seconds" >> "$TEST_RESULTS"
echo "[TEST] RTO Target: 3600 seconds (1 hour)" >> "$TEST_RESULTS"

if [ $RECOVERY_DURATION -lt 3600 ]; then
    echo "✅ [PASS] RTO met" >> "$TEST_RESULTS"
else
    echo "❌ [FAIL] RTO exceeded" >> "$TEST_RESULTS"
fi

# 6. Cleanup
dropdb -U postgres test_dr_${TEST_DATE}

echo "=== DR Test Completed: $(date) ===" >> "$TEST_RESULTS"
```

---

## Appendix

### A. Emergency Contacts

```
Primary On-Call: ops-oncall@example.com (24/7)
Database Team: dba-team@example.com
Security Team: security@example.com
AWS Support: 1-800-XXX-XXXX (Enterprise Support)
```

### B. Backup Storage Locations

```
Primary: s3://aplus-audit-backups (us-east-1)
Secondary: s3://aplus-audit-backups-replica (us-west-2)
Tertiary: glacier://aplus-audit-archive (long-term)
```

### C. Key Configuration Files

```
/opt/aplus-audit/.env                  # Application configuration
/opt/aplus-audit/config/               # Additional configs
/etc/systemd/system/aplus-audit.service  # Service definition
/etc/postgresql/postgresql.conf       # Database config
/var/backups/aplus-audit/              # Local backup staging
```

### D. Recovery Time Tracking

| Incident ID | Date | Failure Type | Actual RTO | Target RTO | Post-Mortem |
|-------------|------|--------------|------------|------------|-------------|
| INC-001 | 2024-12-01 | DB corruption | 45 min | 1 hour | [Link](#) |
| INC-002 | 2024-11-15 | Config error | 12 min | 15 min | [Link](#) |

---

**Document Version**: 1.0  
**Last Updated**: December 14, 2024  
**Owner**: Kevin Hormaza (@OddSageID)  
**Review Schedule**: Quarterly

**Next Review**: March 14, 2025
