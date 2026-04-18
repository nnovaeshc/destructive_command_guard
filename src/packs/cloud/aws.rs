//! AWS CLI patterns - protections against destructive aws commands.
//!
//! This includes patterns for:
//! - ec2 terminate-instances
//! - s3 rm --recursive
//! - rds delete-db-instance
//! - cloudformation delete-stack
//! - athena delete-data-catalog/work-group and destructive query strings
//!   (DROP DATABASE/TABLE, TRUNCATE, DELETE without WHERE)
//! - glue delete-database/table/partition/crawler/job/dev-endpoint

use crate::packs::{DestructivePattern, Pack, SafePattern};
use crate::{destructive_pattern, safe_pattern};

/// Create the AWS pack.
#[must_use]
pub fn create_pack() -> Pack {
    Pack {
        id: "cloud.aws".to_string(),
        name: "AWS CLI",
        description: "Protects against destructive AWS CLI operations like terminate-instances, \
                      delete-db-instance, s3 rm --recursive, Athena/Glue catalog deletions, and \
                      destructive Athena queries (DROP, TRUNCATE, DELETE without WHERE)",
        keywords: &[
            "aws",
            "terminate",
            "delete",
            "s3",
            "ec2",
            "rds",
            "ecr",
            "logs",
            "athena",
            "glue",
        ],
        safe_patterns: create_safe_patterns(),
        destructive_patterns: create_destructive_patterns(),
        keyword_matcher: None,
        safe_regex_set: None,
        safe_regex_set_is_complete: false,
    }
}

fn create_safe_patterns() -> Vec<SafePattern> {
    vec![
        // describe/list/get operations are safe (read-only)
        safe_pattern!("aws-describe", r"aws\s+\S+\s+describe-"),
        safe_pattern!("aws-list", r"aws\s+\S+\s+list-"),
        safe_pattern!("aws-get", r"aws\s+\S+\s+get-"),
        // s3 ls is safe
        safe_pattern!("s3-ls", r"aws\s+s3\s+ls"),
        // s3 cp is generally safe (copy)
        safe_pattern!("s3-cp", r"aws\s+s3\s+cp"),
        // dry-run flag
        safe_pattern!("aws-dry-run", r"aws\s+.*--dry-run"),
        // sts get-caller-identity is safe
        safe_pattern!("sts-identity", r"aws\s+sts\s+get-caller-identity"),
        // cloudformation describe/list
        safe_pattern!("cfn-describe", r"aws\s+cloudformation\s+(?:describe|list)-"),
        // ecr get-login-password is safe
        safe_pattern!("ecr-login", r"aws\s+ecr\s+get-login"),

        // --- Athena start-query-execution: non-destructive query shapes ---
        //
        // Each pattern anchors the safe SQL verb directly on the opening
        // of `--query-string` (after any `=`/whitespace and an optional
        // single/double quote). This is deliberate: `\bSELECT\b` anywhere
        // in the command would let `DROP TABLE /* SELECT */ prod` bypass
        // the destructive check, since safe patterns short-circuit
        // `matches_safe` first.  Requiring the verb at the head of the
        // query-string matches real usage (AWS Athena's
        // `start-query-execution` takes a single statement and rejects
        // semicolon-separated compound statements, so the head verb is
        // the effective verb).
        //
        // Only verbs that would otherwise be swept up by a destructive
        // regex need a safe pattern here — `athena-delete-with-where`
        // exists specifically to escape `athena-query-delete-without-where`
        // (which matches every `DELETE FROM …`). Pure SELECT / SHOW /
        // DESCRIBE / EXPLAIN / CREATE / INSERT / UPDATE queries already
        // fall through both sets and are allowed by default, so we keep
        // the surface small.
        //
        // The trailing `(?!.*;)` is a negative lookahead that rejects
        // any statement separator after the WHERE clause. Athena's
        // `start-query-execution` takes a single statement, so a `;` is
        // either a compound-statement attempt or an embedded literal
        // (pathological). Either way, we don't want the safe-first
        // short-circuit to swallow a trailing destructive statement
        // like `DELETE FROM t WHERE id=1; DROP TABLE t`.
        safe_pattern!(
            "athena-delete-with-where",
            // `aws\b.*?\bathena\b` instead of `aws\s+athena` so global
            // flags between `aws` and the service (e.g.
            // `aws --profile prod athena …`, `aws --region us-east-1 …`)
            // don't let the pattern silently desync and slip the command
            // through as "not an athena command."
            //
            // Table identifier is `[^\s;]+` rather than `\S+` — otherwise
            // a greedy `\S+` absorbs the `;` in `DELETE FROM t; DELETE
            // FROM u WHERE id=1`, letting the regex slide forward to the
            // second (scoped) DELETE's WHERE and ALLOWING the leading
            // unscoped DELETE. Excluding `;` from the identifier forces
            // the regex to stop at the statement boundary, so the
            // destructive `athena-query-delete-without-where` rule still
            // fires on the unscoped head statement.
            //
            // The character class still covers bare names (`t`),
            // schema-qualified names (`db.t`), double-quoted identifiers
            // (`"my-t"`), and backtick-quoted identifiers (`` `my-t` ``).
            r#"(?i)aws\b.*?\bathena\s+start-query-execution\b.*?--query-string[=\s]+['"]?\s*DELETE\s+FROM\s+[^\s;]+\s+.*?\bWHERE\b(?!.*;)"#
        ),
    ]
}

#[allow(clippy::too_many_lines)]
fn create_destructive_patterns() -> Vec<DestructivePattern> {
    vec![
        // ec2 terminate-instances
        destructive_pattern!(
            "ec2-terminate",
            r"aws\s+ec2\s+terminate-instances",
            "aws ec2 terminate-instances permanently destroys EC2 instances.",
            Critical,
            "terminate-instances permanently destroys EC2 instances:\n\n\
             - Instance is stopped and deleted\n\
             - Instance store volumes are lost\n\
             - EBS root volumes deleted (unless DeleteOnTermination=false)\n\
             - Elastic IPs are disassociated\n\n\
             This cannot be undone. The instance ID will never be reusable.\n\n\
             Preview first:\n  \
             aws ec2 describe-instances --instance-ids i-xxx\n\n\
             Consider stop instead:\n  \
             aws ec2 stop-instances --instance-ids i-xxx"
        ),
        // ec2 delete-* commands
        destructive_pattern!(
            "removes AWS resources",
            r"aws\s+ec2\s+delete-(?:snapshot|volume|vpc|subnet|security-group|key-pair|image)",
            "aws ec2 delete-* permanently removes AWS resources.",
            High,
            "EC2 delete commands permanently remove resources:\n\n\
             - delete-snapshot: Removes EBS snapshot (backup data lost)\n\
             - delete-volume: Destroys EBS volume and all data\n\
             - delete-vpc: Removes VPC (must be empty)\n\
             - delete-image: Deregisters AMI\n\
             - delete-security-group: Removes firewall rules\n\
             - delete-key-pair: Removes SSH key (can't SSH to instances using it)\n\n\
             Always verify resource IDs:\n  \
             aws ec2 describe-<resource> --<resource>-ids xxx"
        ),
        // s3 rm --recursive
        destructive_pattern!(
            "s3-rm-recursive",
            r"aws\s+s3\s+rm\s+.*--recursive",
            "aws s3 rm --recursive permanently deletes all objects in the path.",
            Critical,
            "s3 rm --recursive deletes ALL objects under the specified path:\n\n\
             - All files and 'folders' are deleted\n\
             - Versioned objects: only current version deleted\n\
             - No trash/recycle bin\n\
             - Cannot be undone (unless versioning enabled)\n\n\
             Preview what would be deleted:\n  \
             aws s3 ls s3://bucket/path/ --recursive\n  \
             aws s3 rm s3://bucket/path/ --recursive --dryrun\n\n\
             Consider versioning for recovery:\n  \
             aws s3api list-object-versions --bucket bucket"
        ),
        // s3 rb (remove bucket)
        destructive_pattern!(
            "s3-rb",
            r"aws\s+s3\s+rb\b",
            "aws s3 rb removes the entire S3 bucket.",
            Critical,
            "s3 rb removes an S3 bucket:\n\n\
             - Bucket must be empty (use --force to delete contents first)\n\
             - With --force: deletes all objects then bucket\n\
             - Bucket name becomes available for others\n\
             - Cannot be undone\n\n\
             Check bucket contents:\n  \
             aws s3 ls s3://bucket --recursive --summarize\n\n\
             Verify bucket name:\n  \
             aws s3api head-bucket --bucket bucket-name"
        ),
        // s3api delete-bucket
        destructive_pattern!(
            "s3api-delete-bucket",
            r"aws\s+s3api\s+delete-bucket",
            "aws s3api delete-bucket removes the entire S3 bucket.",
            Critical,
            "s3api delete-bucket removes a bucket (must be empty):\n\n\
             - Returns error if bucket not empty\n\
             - Bucket name released for reuse by anyone\n\
             - Associated policies and configurations lost\n\n\
             Empty bucket first if needed:\n  \
             aws s3 rm s3://bucket --recursive\n\n\
             Or use s3 rb --force for both operations."
        ),
        // rds delete-db-instance
        destructive_pattern!(
            "rds-delete",
            r"aws\s+rds\s+delete-db-(?:instance|cluster|snapshot|cluster-snapshot)",
            "aws rds delete-db-instance/cluster permanently destroys the database.",
            Critical,
            "RDS delete commands permanently remove database resources:\n\n\
             - delete-db-instance: Destroys the database instance\n\
             - delete-db-cluster: Destroys Aurora cluster\n\
             - delete-db-snapshot: Removes backup\n\
             - delete-db-cluster-snapshot: Removes cluster backup\n\n\
             Consider:\n\
             - Create final snapshot before deletion\n\
             - Skip final snapshot only for test instances\n\n\
             Create backup:\n  \
             aws rds create-db-snapshot --db-instance-id xxx --db-snapshot-id backup"
        ),
        // cloudformation delete-stack
        destructive_pattern!(
            "cfn-delete-stack",
            r"aws\s+cloudformation\s+delete-stack",
            "aws cloudformation delete-stack removes the entire stack and its resources.",
            Critical,
            "CloudFormation delete-stack removes the stack AND all resources it created:\n\n\
             - EC2 instances terminated\n\
             - RDS databases deleted (unless DeletionPolicy: Retain)\n\
             - S3 buckets removed (if empty)\n\
             - All IAM resources deleted\n\n\
             Resources with DeletionPolicy: Retain are kept but orphaned.\n\n\
             Preview resources:\n  \
             aws cloudformation describe-stack-resources --stack-name xxx\n\n\
             Consider:\n  \
             aws cloudformation delete-stack --retain-resources res1 res2"
        ),
        // lambda delete-function
        destructive_pattern!(
            "lambda-delete",
            r"aws\s+lambda\s+delete-function",
            "aws lambda delete-function permanently removes the Lambda function.",
            High,
            "delete-function removes a Lambda function completely:\n\n\
             - Function code is deleted\n\
             - All versions and aliases removed\n\
             - Event source mappings deleted\n\
             - Cannot be undone\n\n\
             Backup function code first:\n  \
             aws lambda get-function --function-name xxx --query Code.Location\n\n\
             List versions:\n  \
             aws lambda list-versions-by-function --function-name xxx"
        ),
        // iam delete-user/role/policy
        destructive_pattern!(
            "iam-delete",
            r"aws\s+iam\s+delete-(?:user|role|policy|group)",
            "aws iam delete-* removes IAM resources. Verify dependencies first.",
            High,
            "IAM delete commands remove identity resources:\n\n\
             - delete-user: Removes IAM user (must detach policies first)\n\
             - delete-role: Removes role (must detach policies first)\n\
             - delete-policy: Removes managed policy\n\
             - delete-group: Removes IAM group\n\n\
             Check dependencies:\n  \
             aws iam list-attached-user-policies --user-name xxx\n  \
             aws iam list-entities-for-policy --policy-arn xxx\n\n\
             Roles used by services (Lambda, EC2) will break!"
        ),
        // dynamodb delete-table
        destructive_pattern!(
            "dynamodb-delete",
            r"aws\s+dynamodb\s+delete-table",
            "aws dynamodb delete-table permanently deletes the table and all data.",
            Critical,
            "delete-table removes a DynamoDB table and ALL its data:\n\n\
             - All items are deleted\n\
             - Table configuration is lost\n\
             - Global secondary indexes deleted\n\
             - Cannot be undone\n\n\
             Backup first:\n  \
             aws dynamodb create-backup --table-name xxx --backup-name backup\n\n\
             Or export to S3:\n  \
             aws dynamodb export-table-to-point-in-time ..."
        ),
        // eks delete-cluster
        destructive_pattern!(
            "eks-delete",
            r"aws\s+eks\s+delete-cluster",
            "aws eks delete-cluster removes the entire EKS cluster.",
            Critical,
            "delete-cluster removes an EKS cluster:\n\n\
             - Control plane is deleted\n\
             - Node groups must be deleted separately first\n\
             - Kubernetes resources (deployments, services) are lost\n\
             - Persistent volumes may remain as orphaned EBS\n\n\
             Delete node groups first:\n  \
             aws eks list-nodegroups --cluster-name xxx\n  \
             aws eks delete-nodegroup --cluster-name xxx --nodegroup-name yyy\n\n\
             Then delete cluster."
        ),
        // ecr delete-repository
        destructive_pattern!(
            "ecr-delete-repository",
            r"aws\s+ecr\s+delete-repository",
            "aws ecr delete-repository permanently deletes the repository and its images.",
            High,
            "delete-repository removes an ECR repository:\n\n\
             - All images in the repository are deleted\n\
             - Repository configuration lost\n\
             - Requires --force if repository not empty\n\n\
             List images first:\n  \
             aws ecr list-images --repository-name xxx\n\n\
             Consider keeping critical images:\n  \
             docker pull <account>.dkr.ecr.<region>.amazonaws.com/repo:tag"
        ),
        // ecr batch-delete-image
        destructive_pattern!(
            "ecr-batch-delete-image",
            r"aws\s+ecr\s+batch-delete-image",
            "aws ecr batch-delete-image permanently deletes one or more images.",
            High,
            "batch-delete-image removes specific images from ECR:\n\n\
             - Images are permanently deleted\n\
             - Can delete by tag or digest\n\
             - Running containers using these images may fail on restart\n\n\
             List images:\n  \
             aws ecr describe-images --repository-name xxx\n\n\
             Verify image usage before deletion."
        ),
        // ecr delete-lifecycle-policy
        destructive_pattern!(
            "ecr-delete-lifecycle-policy",
            r"aws\s+ecr\s+delete-lifecycle-policy",
            "aws ecr delete-lifecycle-policy removes the repository lifecycle policy.",
            Medium,
            "delete-lifecycle-policy removes automatic image cleanup rules:\n\n\
             - Old images will no longer be automatically deleted\n\
             - May lead to storage cost increases\n\
             - Repository will retain all images indefinitely\n\n\
             View current policy:\n  \
             aws ecr get-lifecycle-policy --repository-name xxx"
        ),
        // CloudWatch Logs delete-log-group
        destructive_pattern!(
            "logs-delete-log-group",
            r"aws\s+logs\s+delete-log-group",
            "aws logs delete-log-group permanently deletes a log group and all events.",
            High,
            "delete-log-group removes a CloudWatch log group:\n\n\
             - All log streams are deleted\n\
             - All log events are lost\n\
             - Metric filters and subscriptions removed\n\
             - Cannot be undone\n\n\
             Export logs before deletion:\n  \
             aws logs create-export-task --log-group-name xxx \\\n    \
             --destination bucket --from 0 --to $(date +%s)000"
        ),
        // CloudWatch Logs delete-log-stream
        destructive_pattern!(
            "logs-delete-log-stream",
            r"aws\s+logs\s+delete-log-stream",
            "aws logs delete-log-stream permanently deletes a log stream and all events.",
            High,
            "delete-log-stream removes a specific log stream:\n\n\
             - All events in the stream are deleted\n\
             - Log group remains intact\n\
             - Cannot be undone\n\n\
             View log stream events before deletion:\n  \
             aws logs get-log-events --log-group-name xxx \\\n    \
             --log-stream-name yyy --limit 100"
        ),

        // ---- Athena catalog / workgroup deletions ---------------------------
        //
        // Every Athena + Glue pattern below uses `aws\b.*?\b<svc>\b` in
        // place of `aws\s+<svc>\s+` so that global flags between `aws`
        // and the service name (`--profile`, `--region`, `--debug`,
        // `--output`, `--endpoint-url`, …) don't silently neuter the
        // rule. See `athena_patterns_match_with_global_flags_before_service`
        // for the regression coverage.
        destructive_pattern!(
            "athena-delete-data-catalog",
            r"aws\b.*?\bathena\s+delete-data-catalog\b",
            "aws athena delete-data-catalog removes the data catalog and all \
             database/table definitions tied to it.",
            Critical,
            "delete-data-catalog detaches and removes an Athena DataCatalog:\n\n\
             - All databases and table definitions linked to the catalog are lost\n\
             - Queries referencing this catalog will fail\n\
             - Underlying S3 data is NOT deleted, but becomes unreadable via Athena\n\
             - Cannot be undone (catalog metadata is gone)\n\n\
             List catalogs first:\n  \
             aws athena list-data-catalogs\n  \
             aws athena get-data-catalog --name xxx"
        ),
        destructive_pattern!(
            "athena-delete-work-group",
            r"aws\b.*?\bathena\s+delete-work-group\b",
            "aws athena delete-work-group removes the Athena workgroup and its configuration.",
            High,
            "delete-work-group removes an Athena workgroup:\n\n\
             - Query history, IAM-scoped configuration, and cost controls are lost\n\
             - In-flight queries are cancelled\n\
             - With --recursive-delete-option, named queries in the workgroup are also dropped\n\n\
             Preview first:\n  \
             aws athena get-work-group --work-group xxx"
        ),
        destructive_pattern!(
            "athena-delete-named-query",
            r"aws\b.*?\bathena\s+delete-named-query\b",
            "aws athena delete-named-query permanently removes a saved query.",
            Medium,
            "delete-named-query deletes a saved Athena query:\n\n\
             - The stored query text and metadata are removed\n\
             - No data is lost, but the query must be rewritten from scratch if \
             it wasn't stored elsewhere\n\n\
             Retrieve the query before deleting:\n  \
             aws athena get-named-query --named-query-id xxx"
        ),

        // ---- Athena destructive query strings -------------------------------
        // These intentionally run *after* the safe patterns above, so a
        // SELECT / SHOW / CREATE / INSERT / UPDATE…SET / DELETE…WHERE
        // will match as safe first and never reach these checks.
        destructive_pattern!(
            "athena-query-drop-database",
            r"(?i)aws\b.*?\bathena\s+start-query-execution\b.*\bDROP\s+(?:DATABASE|SCHEMA)\b",
            "Athena DROP DATABASE/SCHEMA removes the database from the Glue catalog.",
            Critical,
            "DROP DATABASE/SCHEMA removes a database from the Glue catalog:\n\n\
             - All table definitions inside the database are lost\n\
             - Queries referencing this database will fail\n\
             - Underlying S3 data is NOT deleted, just unreadable via Athena\n\
             - Cannot be undone (catalog metadata lost)\n\n\
             List tables first:\n  \
             aws athena start-query-execution \\\n    \
             --query-string 'SHOW TABLES IN database_name'\n\n\
             For more control, use `aws glue delete-database` \
             (which this pack also blocks)."
        ),
        destructive_pattern!(
            "athena-query-drop-table",
            r"(?i)aws\b.*?\bathena\s+start-query-execution\b.*\bDROP\s+(?:TABLE|VIEW|EXTERNAL\s+TABLE)\b",
            "Athena DROP TABLE/VIEW removes the table definition from the Glue catalog.",
            High,
            "DROP TABLE/VIEW removes a table or view from the catalog:\n\n\
             - Table definition is lost\n\
             - Queries referencing this table will fail\n\
             - Underlying S3 data is NOT deleted\n\n\
             Preview schema first:\n  \
             aws athena start-query-execution \\\n    \
             --query-string 'SHOW CREATE TABLE db.table'"
        ),
        destructive_pattern!(
            "athena-query-truncate",
            r"(?i)aws\b.*?\bathena\s+start-query-execution\b.*\bTRUNCATE\s+TABLE\b",
            "Athena TRUNCATE TABLE deletes all rows from an Iceberg table.",
            Critical,
            "TRUNCATE TABLE in Athena (Iceberg tables):\n\n\
             - All rows are deleted from the table\n\
             - The table definition is preserved\n\
             - Underlying S3 objects are removed for Iceberg tables\n\
             - Cannot be undone (no implicit snapshot retention)\n\n\
             Consider a targeted DELETE with WHERE clause instead."
        ),
        destructive_pattern!(
            "athena-query-string-from-file",
            // AWS CLI's `file://` and `fileb://` protocols load the
            // parameter value from a file — so the SQL content never
            // appears on the command line and the DROP/TRUNCATE/
            // unscoped-DELETE regexes have nothing to grep. Block the
            // shape so users can't hide destructive SQL inside
            // `--query-string file://query.sql`.
            r#"(?i)aws\b.*?\bathena\s+start-query-execution\b.*--query-string[=\s]+['"]?\s*(?:file|fileb)://"#,
            "Athena --query-string loaded from file:// or fileb:// — SQL content is opaque to the guard.",
            High,
            "Athena `start-query-execution --query-string file://…` loads the\n\
             SQL from disk, so DCG can't inspect the statement. The file may\n\
             contain DROP DATABASE, TRUNCATE TABLE, or an unscoped DELETE.\n\n\
             Prefer the inline form so the guard can see what you're running:\n  \
             aws athena start-query-execution \\\n    \
             --query-string 'SELECT … FROM …'\n\n\
             If a file-loaded query is genuinely required, cat it first so\n\
             the content is inspectable, and allowlist this rule in your\n\
             project DCG config with a justification."
        ),
        destructive_pattern!(
            "athena-cli-input-file",
            // `--cli-input-json file://…` / `--cli-input-yaml file://…`
            // loads the whole invocation (including QueryString) from a
            // file on disk. DCG can't inspect the file, so destructive
            // SQL inside it is invisible. Only block the file-backed
            // form — inline JSON/YAML is still visible to the broader
            // DROP/TRUNCATE/DELETE regexes elsewhere in the pack, so no
            // need to over-block inline usage.
            r#"(?i)aws\b.*?\bathena\s+start-query-execution\b.*--cli-input-(?:json|yaml)[=\s]+['"]?\s*(?:file|fileb)://"#,
            "Athena --cli-input-json/yaml loaded from file:// or fileb:// — content is opaque to the guard.",
            High,
            "`--cli-input-json file://…` (or `-yaml`) supplies the whole\n\
             invocation — including QueryString — from a file on disk. DCG\n\
             only greps the command line, so a DROP or TRUNCATE buried in\n\
             the JSON/YAML body on disk slips past every other Athena rule.\n\n\
             Inline JSON/YAML (e.g. `--cli-input-json '{…}'`) is still\n\
             allowed because DCG can read the literal in the command line\n\
             and catch a DROP there.\n\n\
             Prefer explicit `--query-string '…'`, or inline the JSON blob.\n\
             If the file-backed form is genuinely required, allowlist this\n\
             rule with a justification."
        ),
        destructive_pattern!(
            "athena-query-delete-without-where",
            // Match DELETE FROM <table> with no WHERE later in the query.
            // (The safe `athena-delete-with-where` pattern short-circuits
            // `matches_safe` first, so this only fires on unscoped DELETE.)
            // `\S+` is deliberately broad so quoted identifiers like
            // `"my-table"` or `` `my-table` `` can't evade the block.
            r"(?i)aws\b.*?\bathena\s+start-query-execution\b.*\bDELETE\s+FROM\s+\S+",
            "Athena DELETE without a WHERE clause removes all rows from the target table.",
            Critical,
            "DELETE FROM <table> without a WHERE clause:\n\n\
             - Every row in the table is deleted\n\
             - Iceberg tables: underlying S3 data is dropped\n\
             - Hive tables: operation fails (Athena rejects unscoped DELETE on Hive)\n\
             - Cannot be undone (no automatic snapshots)\n\n\
             Rewrite with a WHERE clause that scopes the deletion:\n  \
             DELETE FROM db.table WHERE <predicate>"
        ),

        // ---- Glue catalog deletions -----------------------------------------
        destructive_pattern!(
            "glue-delete-database",
            r"aws\b.*?\bglue\s+delete-database\b",
            "aws glue delete-database removes the database and every table definition inside it.",
            Critical,
            "delete-database drops a Glue database and every table/partition in it:\n\n\
             - All table definitions in the database are lost\n\
             - Athena / EMR / Redshift Spectrum queries referencing these tables will fail\n\
             - Underlying S3 data is preserved, but becomes unreadable via the catalog\n\
             - Cannot be undone (metadata is gone)\n\n\
             List tables first:\n  \
             aws glue get-tables --database-name xxx"
        ),
        destructive_pattern!(
            "glue-delete-table",
            r"aws\b.*?\bglue\s+delete-table\b",
            "aws glue delete-table removes the table definition from the catalog.",
            High,
            "delete-table removes a Glue table definition:\n\n\
             - Table schema and partition metadata are lost\n\
             - Underlying S3 data is NOT deleted\n\
             - Queries referencing this table will fail\n\n\
             Preview the table first:\n  \
             aws glue get-table --database-name xxx --name yyy"
        ),
        destructive_pattern!(
            "glue-batch-delete-table",
            r"aws\b.*?\bglue\s+batch-delete-table\b",
            "aws glue batch-delete-table removes multiple table definitions in one call.",
            Critical,
            "batch-delete-table drops several Glue tables in one API call:\n\n\
             - All listed table definitions are lost\n\
             - Underlying S3 data is preserved\n\
             - Queries referencing these tables will fail\n\
             - Cannot be undone\n\n\
             Review the exact names first:\n  \
             aws glue get-tables --database-name xxx"
        ),
        destructive_pattern!(
            "glue-delete-partition",
            r"aws\b.*?\bglue\s+delete-partition\b",
            "aws glue delete-partition removes partition metadata; the partition is no longer \
             queryable until recreated.",
            High,
            "delete-partition removes a Glue partition's metadata:\n\n\
             - Partition metadata is lost (column stats, location pointer)\n\
             - Underlying S3 data is preserved\n\
             - Queries scoped to that partition will return no rows until re-registered"
        ),
        destructive_pattern!(
            "glue-batch-delete-partition",
            r"aws\b.*?\bglue\s+batch-delete-partition\b",
            "aws glue batch-delete-partition removes multiple partition definitions in one call.",
            High,
            "batch-delete-partition drops several Glue partitions at once:\n\n\
             - Every listed partition's metadata is lost\n\
             - Underlying S3 data is preserved\n\
             - Recreate via `aws glue batch-create-partition` if you still have the list"
        ),
        destructive_pattern!(
            "glue-delete-crawler",
            r"aws\b.*?\bglue\s+delete-crawler\b",
            "aws glue delete-crawler removes the crawler configuration.",
            Medium,
            "delete-crawler removes a Glue crawler:\n\n\
             - Crawler configuration (targets, schedule, schema detection rules) is lost\n\
             - Schedules and classifiers tied to the crawler are orphaned\n\
             - Can be re-created from Infrastructure-as-Code if present"
        ),
        destructive_pattern!(
            "glue-delete-job",
            r"aws\b.*?\bglue\s+delete-job\b",
            "aws glue delete-job removes the ETL job definition and all of its run history.",
            High,
            "delete-job removes a Glue ETL job:\n\n\
             - Job script reference, connections, arguments, and schedule are lost\n\
             - All run history and metrics for the job are removed\n\
             - Scheduled triggers referencing the job will fail\n\n\
             Export the job definition first:\n  \
             aws glue get-job --job-name xxx > job-backup.json"
        ),
        destructive_pattern!(
            "glue-delete-dev-endpoint",
            r"aws\b.*?\bglue\s+delete-dev-endpoint\b",
            "aws glue delete-dev-endpoint tears down the development endpoint and any attached \
             SageMaker notebook configuration.",
            Medium,
            "delete-dev-endpoint shuts down a Glue DevEndpoint:\n\n\
             - Endpoint is stopped and deleted\n\
             - Attached SageMaker notebook (if any) must be cleaned up separately\n\
             - Ongoing sessions / jobs on the endpoint are terminated"
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::test_helpers::*;

    #[test]
    fn ec2_and_rds_patterns_block() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws ec2 delete-key-pair --key-name my-key",
            "removes AWS resources",
        );
        assert_blocks(
            &pack,
            "aws ec2 delete-image --image-id ami-12345678",
            "removes AWS resources",
        );
        assert_blocks(
            &pack,
            "aws rds delete-db-snapshot --db-snapshot-identifier my-snapshot",
            "destroys the database",
        );
        assert_blocks(
            &pack,
            "aws rds delete-db-cluster-snapshot --db-cluster-snapshot-identifier my-cluster-snapshot",
            "destroys the database",
        );
    }

    #[test]
    fn ecr_and_logs_patterns_block() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws ecr delete-repository --repository-name example",
            "delete-repository",
        );
        assert_blocks(
            &pack,
            "aws ecr batch-delete-image --repository-name example --image-ids imageTag=latest",
            "batch-delete-image",
        );
        assert_blocks(
            &pack,
            "aws ecr delete-lifecycle-policy --repository-name example",
            "delete-lifecycle-policy",
        );
        assert_blocks(
            &pack,
            "aws logs delete-log-group --log-group-name /aws/lambda/thing",
            "delete-log-group",
        );
        assert_blocks(
            &pack,
            "aws logs delete-log-stream --log-group-name /aws/lambda/thing --log-stream-name foo",
            "delete-log-stream",
        );
    }

    // ======================================================================
    // Athena
    // ======================================================================

    #[test]
    fn athena_catalog_and_workgroup_deletions_block() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws athena delete-data-catalog --name my_catalog",
            "delete-data-catalog",
        );
        assert_blocks(
            &pack,
            "aws athena delete-work-group --work-group primary",
            "delete-work-group",
        );
        assert_blocks(
            &pack,
            "aws athena delete-named-query --named-query-id abc-123",
            "delete-named-query",
        );
    }

    #[test]
    fn athena_destructive_query_with_safe_keyword_in_comment_still_blocked() {
        // Regression: safe patterns anchor the verb at the head of
        // `--query-string`, so a SQL comment that embeds SELECT/SHOW/etc.
        // must not bypass a surrounding DROP TABLE.
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string '/* SELECT old_table */ DROP TABLE prod.customers'",
            "DROP TABLE",
        );
        // Multi-statement is invalid Athena SQL, but defense-in-depth:
        // a SELECT-first query with a trailing DROP must still block.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'SELECT 1; DROP TABLE prod.customers'",
            "DROP TABLE",
        );
        // Same for SELECT followed by TRUNCATE.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'SELECT 1; TRUNCATE TABLE prod.events'",
            "TRUNCATE",
        );
        // DELETE-with-WHERE followed by DROP must still block (the
        // safe-first short-circuit cannot be exploited this way even on
        // the one safe pattern we do keep, because Athena rejects
        // compound statements; we still block as defense in depth).
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM t WHERE id = 1; DROP TABLE t'",
            "DROP TABLE",
        );
        // Regression: unscoped DELETE followed by a scoped DELETE must
        // NOT be allowed just because the *trailing* statement has a
        // WHERE clause. Previously `\S+` was greedy enough to absorb the
        // `;` into the "table name" slot and let the head anchor slide
        // past it to the later WHERE.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM t; DELETE FROM u WHERE id = 1'",
            "DELETE without a WHERE clause",
        );
    }

    #[test]
    fn athena_destructive_queries_block() {
        let pack = create_pack();
        // DROP DATABASE / SCHEMA (both keywords)
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DROP DATABASE test_db'",
            "DROP DATABASE",
        );
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string \"drop schema reporting\"",
            "DROP DATABASE",
        );
        // Case-insensitive
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'Drop Database Test_DB'",
            "DROP DATABASE",
        );
        // DROP TABLE / VIEW
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DROP TABLE sales.orders'",
            "DROP TABLE",
        );
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DROP VIEW reporting_v1'",
            "DROP TABLE",
        );
        // TRUNCATE
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'TRUNCATE TABLE iceberg_db.events'",
            "TRUNCATE",
        );
        // DELETE without WHERE
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM iceberg_db.events'",
            "DELETE without a WHERE clause",
        );
    }

    #[test]
    fn athena_safe_queries_allowed() {
        let pack = create_pack();
        // SELECT
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'SELECT COUNT(*) FROM sales.orders'",
        );
        // SHOW
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'SHOW TABLES IN reporting'",
        );
        // DESCRIBE
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'DESCRIBE sales.orders'",
        );
        // EXPLAIN
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'EXPLAIN SELECT * FROM t LIMIT 1'",
        );
        // CREATE TABLE / DATABASE / VIEW
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'CREATE DATABASE analytics'",
        );
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'CREATE TABLE analytics.t (id int)'",
        );
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'CREATE OR REPLACE VIEW reporting.v AS SELECT 1'",
        );
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string \"CREATE EXTERNAL TABLE t (a string) LOCATION 's3://bkt/'\"",
        );
        // INSERT INTO / OVERWRITE
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'INSERT INTO analytics.t VALUES (1)'",
        );
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'INSERT OVERWRITE analytics.t SELECT * FROM staging.t'",
        );
        // UPDATE ... SET
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'UPDATE analytics.t SET status = '\"'\"'ok'\"'\"' WHERE id = 1'",
        );
        // DELETE with WHERE
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM iceberg_db.events WHERE id = 1'",
        );
        // Case-insensitive safe verbs
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'select * from t'",
        );
    }

    #[test]
    fn athena_delete_with_where_on_schema_qualified_table_is_allowed() {
        let pack = create_pack();
        // Regression: DELETE FROM db.table WHERE ... must match
        // athena-delete-with-where, not athena-query-delete-without-where.
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM reporting.events WHERE ts < now() - interval 30 day'",
        );
    }

    #[test]
    fn athena_cli_input_inline_json_still_grepped_by_existing_rules() {
        // Regression: `--cli-input-json '{…}'` with INLINE JSON is
        // visible on the command line, so destructive SQL inside the
        // blob must still be caught by the broad DROP/TRUNCATE/DELETE
        // patterns. The `athena-cli-input-file` rule is narrowed to
        // file-backed forms only so it doesn't over-block legitimate
        // inline usage — but the defense in depth comes from the
        // existing per-verb destructive rules still firing.
        let pack = create_pack();
        // Safe inline JSON (SELECT): allowed.
        assert_allows(
            &pack,
            r#"aws athena start-query-execution --cli-input-json '{"QueryString": "SELECT 1 FROM t"}'"#,
        );
        // Destructive inline JSON (DROP DATABASE): blocked by the
        // existing broad DROP DATABASE rule, not the new file-backed rule.
        assert_blocks(
            &pack,
            r#"aws athena start-query-execution --cli-input-json '{"QueryString": "DROP DATABASE prod"}'"#,
            "DROP DATABASE",
        );
    }

    #[test]
    fn athena_file_protocol_edge_cases() {
        // Edge cases the simple matcher must still handle:
        let pack = create_pack();
        // `=` separator instead of space.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string=file:///tmp/q.sql",
            "file",
        );
        // Quoted file path.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string \"file:///tmp/q.sql\"",
            "file",
        );
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'file:///tmp/q.sql'",
            "file",
        );
        // Case-insensitive on the protocol.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string FILE:///tmp/q.sql",
            "file",
        );
        // `--cli-input-json=file://…` with `=`.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --cli-input-json=file:///tmp/input.json",
            "cli-input",
        );
    }

    #[test]
    fn athena_query_string_via_file_protocol_is_flagged() {
        // Regression: AWS CLI's `file://` and `fileb://` protocols load
        // the parameter value from a file, and `--cli-input-json` /
        // `--cli-input-yaml` load the entire invocation from a file. In
        // all of these cases the destructive SQL never appears on the
        // command line, so the `DROP DATABASE`/`TRUNCATE`/unscoped
        // `DELETE` regexes have nothing to grep. These shapes need to
        // be blocked (or at least flagged) so a user can't hide a
        // `DROP DATABASE` inside `file://query.sql` and slip past.
        let pack = create_pack();
        // file:// loading
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string file:///tmp/secret-query.sql",
            "file",
        );
        // fileb:// (binary) loading
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string fileb:///tmp/secret-query.sql",
            "file",
        );
        // --cli-input-json: whole invocation from a file
        assert_blocks(
            &pack,
            "aws athena start-query-execution --cli-input-json file:///tmp/input.json",
            "cli-input",
        );
        // --cli-input-yaml: same, YAML flavor
        assert_blocks(
            &pack,
            "aws athena start-query-execution --cli-input-yaml file:///tmp/input.yaml",
            "cli-input",
        );
        // Also with global flags ahead of the service
        assert_blocks(
            &pack,
            "aws --profile prod athena start-query-execution --query-string file:///tmp/q.sql",
            "file",
        );
    }

    #[test]
    fn athena_patterns_match_with_global_flags_before_service() {
        // Regression: the AWS CLI accepts global flags like `--profile`,
        // `--region`, `--debug` BEFORE the service name. If those break
        // the pattern, an attacker (or any normal user with a multi-profile
        // setup) can evade the block entirely with
        // `aws --profile prod athena start-query-execution ...`.
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws --profile prod athena start-query-execution --query-string 'DROP DATABASE critical'",
            "DROP DATABASE",
        );
        assert_blocks(
            &pack,
            "aws --region us-east-1 --profile prod athena start-query-execution --query-string 'DROP TABLE t'",
            "DROP TABLE",
        );
        assert_blocks(
            &pack,
            "aws --debug glue delete-database --name analytics",
            "delete-database",
        );
        assert_blocks(
            &pack,
            "aws --profile prod --region us-east-1 glue batch-delete-table --database-name x --tables-to-delete foo bar",
            "batch-delete-table",
        );
        assert_blocks(
            &pack,
            "aws --output json athena delete-data-catalog --name my_catalog",
            "delete-data-catalog",
        );
    }

    #[test]
    fn athena_delete_with_quoted_identifiers_is_still_matched() {
        // Regression: quoted table identifiers (backticks, double-quotes,
        // hyphenated names) must not evade either the safe allowlist for
        // DELETE-WITH-WHERE or the destructive block for DELETE-WITHOUT-WHERE.
        let pack = create_pack();

        // Double-quoted, WHERE present → safe.
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM \"reporting-events\" WHERE ts < now()'",
        );
        // Backtick-quoted, WHERE present → safe.
        assert_allows(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM `reporting-events` WHERE ts < now()'",
        );
        // Double-quoted, WHERE missing → blocked.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM \"reporting-events\"'",
            "DELETE without a WHERE clause",
        );
        // Backtick-quoted, WHERE missing → blocked.
        assert_blocks(
            &pack,
            "aws athena start-query-execution --query-string 'DELETE FROM `reporting-events`'",
            "DELETE without a WHERE clause",
        );
    }

    // ======================================================================
    // Glue
    // ======================================================================

    #[test]
    fn glue_catalog_deletions_block() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws glue delete-database --name analytics",
            "delete-database",
        );
        assert_blocks(
            &pack,
            "aws glue delete-table --database-name analytics --name orders",
            "delete-table",
        );
        assert_blocks(
            &pack,
            "aws glue batch-delete-table --database-name analytics --tables-to-delete orders fulfillment",
            "batch-delete-table",
        );
        assert_blocks(
            &pack,
            "aws glue delete-partition --database-name analytics --table-name orders --partition-values 2026 01",
            "delete-partition",
        );
        assert_blocks(
            &pack,
            "aws glue batch-delete-partition --database-name analytics --table-name orders --partitions-to-delete '[...]'",
            "batch-delete-partition",
        );
    }

    #[test]
    fn glue_tooling_deletions_block() {
        let pack = create_pack();
        assert_blocks(
            &pack,
            "aws glue delete-crawler --name nightly-catalog-scan",
            "delete-crawler",
        );
        assert_blocks(
            &pack,
            "aws glue delete-job --job-name orders-etl",
            "delete-job",
        );
        assert_blocks(
            &pack,
            "aws glue delete-dev-endpoint --endpoint-name analytics-dev",
            "delete-dev-endpoint",
        );
    }

    #[test]
    fn glue_read_only_commands_allowed() {
        let pack = create_pack();
        assert_allows(&pack, "aws glue get-tables --database-name analytics");
        assert_allows(&pack, "aws glue get-database --name analytics");
        assert_allows(&pack, "aws glue list-crawlers");
        assert_allows(&pack, "aws glue get-job --job-name orders-etl");
    }
}
