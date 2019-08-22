--Advisory: event time limits for queries not set. It is not recommended to run these without a time filter.


--AWS Config Recorder disabled
CREATE OR REPLACE VIEW rules.CLOUDTRAIL_CONFIG_DELETION_ALERT_QUERY COPY GRANTS
  COMMENT='AWS Config Snapshot Recorder or Delivery Channel deleted
  @id 3bab686c1ac841c586c2b3d206a81d8b
  @tags aws, logging'
AS
SELECT OBJECT_CONSTRUCT(
         'cloud', 'AWS',
         'account_id', recipientaccountid
       ) AS environment
     , ARRAY_CONSTRUCT('CloudTrail') AS sources
     , requestparameters:configurationRecorderName AS object
     , 'AWS Config Recorder Disabled' AS title
     , eventtime AS event_time
     , CURRENT_TIMESTAMP() AS alert_time
     , (
         CASE
           WHEN useridentity:"type" = 'IAMUser'
             THEN useridentity:"userName"
           WHEN useridentity:"type" = 'Root'
             THEN 'Root'
           WHEN useridentity:"type" = 'AssumedRole'
             THEN useridentity:"sessionContext":"sessionIssuer":"userName"
           WHEN useridentity:"type" = 'AWSAccount'
             THEN useridentity:"accountId"
           WHEN useridentity:"type" = 'AWSService'
             THEN useridentity:"invokedBy"
         END
       ) AS actor
     , (
         'Actor ' || actor || ' ' ||
         'performed ' || eventname || ' ' ||
         'on ' || requestparameters:configurationRecorderName || ', ' ||
         'working from ' || sourceipaddress
       ) AS description
     , eventname AS action
     , 'SnowAlert' AS detector
     , OBJECT_CONSTRUCT(*) AS event_data
     , 'medium' AS severity
     , '3bab686c1ac841c586c2b3d206a81d8b' AS query_id
     , OBJECT_CONSTRUCT(*) AS event_data
FROM cloudtrail
WHERE 1=1
  AND eventname IN (
    'DeleteDeliveryChannel',
    'DeleteConfigurationRecorder'
  )
;

--AWS Systems manager Run Command Usage
--Note: The following activity is common in test case
CREATE OR REPLACE VIEW rules.CLOUDTRAIL_AWSSM_RUNCOMMAND_ALERT_QUERY COPY GRANTS
  COMMENT='SendCommands sent to the SSM service, compromise vector for EC2
  @id 4363513205bd49ec9bd26bf63acbec72
  @tags aws, ec2'
AS
SELECT OBJECT_CONSTRUCT(
         'cloud', 'AWS',
         'account_id', recipientaccountid
       ) AS environment
     , ARRAY_TO_STRING(PARSE_JSON(requestparameters:instanceIds), ', ') AS object
     , ARRAY_CONSTRUCT('CloudTrail') AS sources
     , 'AWS Systems Manager Run Command Usage' AS title
     , eventtime AS event_time
     , CURRENT_TIMESTAMP() AS alert_time
     , (
         CASE
           WHEN useridentity:"type" = 'IAMUser'
             THEN useridentity:"userName"
           WHEN useridentity:"type" = 'Root'
             THEN 'Root'
           WHEN useridentity:"type" = 'AssumedRole'
             THEN useridentity:"sessionContext":"sessionIssuer":"userName"
           WHEN useridentity:"type" = 'AWSAccount'
             THEN useridentity:"accountId"
           WHEN useridentity:"type" = 'AWSService'
             THEN useridentity:"invokedBy"
         END
       ) AS actor
     , (
         'Actor ' || actor || ' used AWS SSM Run Command on ' || object
       ) AS description
     , eventname AS action
     , 'SnowAlert' AS detector
     , OBJECT_CONSTRUCT(*) AS event_data
     , 'high' AS severity
     , '4363513205bd49ec9bd26bf63acbec72' AS query_id
FROM cloudtrail
WHERE 1=1
  AND eventsource = 'ssm.amazonaws.com'
  AND eventname = 'SendCommand'
;


--AWS Access Denied for Instance Termination
CREATE OR REPLACE VIEW rules.AWS_TERMINATE_INSTANCE_ACCESS_DENIED_ALERT_QUERY COPY GRANTS
  COMMENT='User attempting to terminate instances without permission in AWS
  @id yvoaik0dsvn
  @tags aws, failed action'
AS
SELECT OBJECT_CONSTRUCT(
         'cloud', 'AWS',
         'account_id', recipientaccountid
       ) AS environment
     , ARRAY_CONSTRUCT('CloudTrail') AS sources
     , eventname AS object
     , 'AWS Access Denied for TerminateInstance' AS title
     , eventtime AS event_time
     , CURRENT_TIMESTAMP() AS alert_time
     , (
         CASE
           WHEN useridentity:"type" = 'IAMUser'
             THEN useridentity:"userName"
           WHEN useridentity:"type" = 'Root'
             THEN 'Root'
           WHEN useridentity:"type" = 'AssumedRole'
             THEN useridentity:"sessionContext":"sessionIssuer":"userName"
           WHEN useridentity:"type" = 'AWSAccount'
             THEN useridentity:"accountId"
           WHEN useridentity:"type" = 'AWSService'
             THEN useridentity:"invokedBy"
         END
       ) AS actor
     , eventname AS action
     , (
         'Terminate instance operation blocked for ' || actor || ' ' ||
         'trying to ' || action || ' ' ||
         'from ' || sourceipaddress
       ) AS description
     , 'SnowAlert' AS detector
     , OBJECT_CONSTRUCT(*) AS event_data
     , 'medium' AS severity
     , 'yvoaik0dsvn' AS query_id
FROM cloudtrail
WHERE 1=1
  AND errorcode = 'AccessDenied'
  AND eventname = 'TerminateInstances'
;



--AWS Access Denied for IAM Operation
CREATE OR REPLACE VIEW rules.AWS_IAM_ACCESS_DENIED_ALERT_QUERY COPY GRANTS
  COMMENT='User trying IAM action without permission
  @id d839e4d0695c4a9db582c681f87b6ced
  @tags aws, failed action'
AS
SELECT OBJECT_CONSTRUCT(
         'cloud', 'AWS',
         'account_id', recipientaccountid
       ) AS environment
     , ARRAY_CONSTRUCT('CloudTrail') AS sources
     , REGEXP_SUBSTR(errormessage, 'resource:\\W{1}(.*)$', 1, 1, 'e') AS object
     , 'AWS Access Denied for IAM Operation' AS title
     , eventtime AS event_time
     , CURRENT_TIMESTAMP() AS alert_time
     , (
         CASE
           WHEN useridentity:"type" = 'IAMUser'
             THEN useridentity:"userName"
           WHEN useridentity:"type" = 'Root'
             THEN 'Root'
           WHEN useridentity:"type" = 'AssumedRole'
             THEN useridentity:"sessionContext":"sessionIssuer":"userName"
           WHEN useridentity:"type" = 'AWSAccount'
             THEN useridentity:"accountId"
           WHEN useridentity:"type" = 'AWSService'
             THEN useridentity:"invokedBy"
         END
       ) AS actor
     , eventname AS action
     , (
         'IAM operation blocked for ' || actor ||
         ' trying to ' || action ||
         ' from ' || sourceipaddress
       ) AS description
     , 'SnowAlert' AS detector
     , OBJECT_CONSTRUCT(*) AS event_data
     , 'low' AS severity
     , 'd839e4d0695c4a9db582c681f87b6ced' AS query_id
FROM cloudtrail
WHERE 1=1
  AND errorcode = 'AccessDenied'
  AND eventsource = 'iam.amazonaws.com'
;

--Excessive Compute Resources Requested
--Note: Incomplete, requires definition for excessive based on value type.
--Where to insert threshold commented below. 

CREATE OR REPLACE VIEW rules.AQ_WKHSSRZ904_ALERT_QUERY COPY GRANTS
  COMMENT='User requesting excessive resources for an instance
  ***********NEEDS THRESHOLDS***************
  @id WKHSSRZ904
  @tags cloudtrail, aws'
AS
SELECT OBJECT_CONSTRUCT(
         'role', roles,
         'instance_type', instance_type,
         'account_id', recipientaccountid
       ) AS environment
     , ARRAY_CONSTRUCT('CloudTrail') AS sources
     , recipientaccountid AS object
     , 'Excessive Compute Resources Requested' AS title
     , eventtime AS event_time
     , CURRENT_TIMESTAMP() AS alert_time
     , roles AS actor
     , eventname AS action
     , (
         'User with role ' || actor || ' ' ||
         'ran ' || action || ' ' ||
         'requesting instance type ' || instance_type || ' ' ||
         'at ' || alert_time
       ) AS description
     , 'SnowAlert' AS detector
     , OBJECT_CONSTRUCT(*) AS event_data
     , NULL AS handlers
     , 'low' AS severity
     , 'WKHSSRZ904' AS query_id
FROM (
  SELECT event_data
       , eventtime
       , value:"instanceType" AS instance_type
       , roles
       , recipientaccountid
       , eventname
  FROM (
    SELECT DISTINCT responseelements:"instancesSet":"items" AS instance_details
                  , COALESCE(
                      useridentity:"userName",
                      useridentity:"sessionContext":"sessionIssuer":"userName"
                    ) AS roles
                  , OBJECT_CONSTRUCT(*) AS event_data
                  , eventtime
                  , recipientaccountid
                  , eventname
    FROM cloudtrail
    WHERE eventname IN ('RunInstances')
    ), LATERAL FLATTEN(input => instance_details)
  WHERE (value:"cpuOptions":"coreCount" >= 18  -- * Change this threshold
     OR value:"cpuOptions":"threadsPerCore" > 2 ) -- * Change this threshold 
  UNION ALL
  SELECT DISTINCT event_data
                , eventtime
                , value:"value"
                , roles
                , recipientaccountid
                , eventname
  FROM (
    SELECT requestparameters
         , COALESCE(
             useridentity:"userName",
             useridentity:"sessionContext":"sessionIssuer":"userName"
           ) AS roles
         , OBJECT_CONSTRUCT(*) AS event_data
         , eventtime
         , recipientaccountid
         , eventname
    FROM cloudtrail
    WHERE eventname IN ('ModifyInstanceAttribute')
  ), LATERAL FLATTEN(input => requestparameters)
  WHERE path IN (
    'ramdisk',
    'instanceType'
  )
  --  and *Insert threshold here*
)
WHERE 1=1
  AND 2=2
;



--Impossible Travel for Console Login
--Requires geolocation source

;

--User Assigned Escalated Policy to Themselves
CREATE OR REPLACE VIEW rules.AQ_Q8ZKNXX4BOP_ALERT_QUERY COPY GRANTS
  COMMENT='User assigned IAM Policy to themselves, their role, or to star
  @id Q8ZKNXX4BOP
  @tags cloudtrail, policies'
AS
SELECT OBJECT_CONSTRUCT(
         'user_session', user_session,
         'role', roles,
         'policy', actions,
         'resources', resources
       ) AS environment
     , ARRAY_CONSTRUCT('CloudTrail') AS sources
     , event_data:recipientaccountid AS object
     , 'Cloudtrail User Assigned Escalated Policy to Themselves' AS title
     , eventtime AS event_time
     , CURRENT_TIMESTAMP() AS alert_time
     , user_session AS actor
     , (
         actor || ' applied policy ' || actions || ' ' ||
         'to resources ' || resources || ' ' ||
         'at ' || eventtime
       ) AS description
     , eventname AS action
     , 'SnowAlert' AS detector
     , OBJECT_CONSTRUCT(*) AS event_data
     , NULL AS handlers
     , 'low' AS severity
     , 'Q8ZKNXX4BOP' AS query_id
FROM (
  SELECT useridentity
       , COALESCE(
           useridentity:"userName",
           regexp_substr(useridentity:"arn", '.*/(.*?)(\\.([1-9])*)', 1, 1,'e'),
           regexp_substr(useridentity:"arn", '.*/(.*)$', 1, 1,'e')
         ) AS user_session
       , COALESCE(
           useridentity:"userName",
           useridentity:"sessionContext":"sessionIssuer":"userName"
         ) AS roles
       , event_data
       , eventtime
       , eventname
       , value:"Action" AS actions
       , value:"Resource" AS resources
  FROM (
    SELECT PARSE_JSON(requestparameters:"policyDocument"):"Statement" AS policy_statements
         , useridentity:"userName", useridentity:"arn"
         , useridentity
         , eventtime
         , OBJECT_CONSTRUCT(*) AS event_data
         , eventname
    FROM cloudtrail
    WHERE eventname in (
      'UpdatePolicy',
      'UpdateUserPolicy',
      'PutUserPolicy',
      'PutRolePolicy',
      'PutUserPolicy'
    )
  ), LATERAL FLATTEN(input => policy_statements)
)
WHERE 1=1
  AND actions ILIKE '%iam:%'
  AND (
    resources RLIKE '.*(:user\\/\\*)".*'
    OR resources ILIKE '%"*"%'
    OR resources = '*'
    OR resources ILIKE '%' || roles || '%'
    OR resources ILIKE '%' || user_session || '%'
  )
;


--Possible EC2 Backdoor Shell Script
--EC2 Startup shell script

CREATE OR REPLACE VIEW rules.AWS_EC2_STARTUP_SHELL_SCRIPT_ALERT_QUERY COPY GRANTS
  COMMENT='Startup scripts getting added to EC2 instances, a vector for persistent compromise
  @id f15346a9c9684abe85993a233d27f8ba
  @tags aws, ec2, logon scripts'
AS
SELECT OBJECT_CONSTRUCT(
        'cloud', 'AWS',
        'account', recipientaccountid
       ) AS environment
     , ARRAY_CONSTRUCT('CloudTrail') AS sources
     , COALESCE(
         requestparameters:instanceId,
         requestparameters
       ) AS object
     , 'Possible EC2 Startup Shell Script' AS title
     , eventtime AS event_time
     , CURRENT_TIMESTAMP() AS alert_time
     , (
         CASE
           WHEN useridentity:"type" = 'IAMUser'
             THEN useridentity:"userName"
           WHEN useridentity:"type" = 'Root'
             THEN 'Root'
           WHEN useridentity:"type" = 'AssumedRole'
             THEN useridentity:"sessionContext":"sessionIssuer":"userName"
           WHEN useridentity:"type" = 'AWSAccount'
             THEN useridentity:"accountId"
           WHEN useridentity:"type" = 'AWSService'
             THEN useridentity:"invokedBy"
         END
       ) AS actor
     , (
         'User ' || actor || ' modified the startup shell script, ' ||
         'whcih may indicate instance compromise of '  || object || 
         ', working from ' || sourceipaddress
       ) AS description
     , eventname AS action
     , 'SnowAlert' AS detector
     , OBJECT_CONSTRUCT(*) AS event_data
     , 'high' AS severity
     , 'f15346a9c9684abe85993a233d27f8ba' AS query_id
FROM cloudtrail
WHERE 1=1
  AND eventsource = 'ec2.amazonaws.com'
  AND eventname = 'ModifyInstanceAttribute'
  AND requestparameters:userData IS NOT NULL
;

--User Logging in Without MFA
CREATE OR REPLACE VIEW rules.AWS_CONSOLE_WITHOUT_MFA_ALERT_QUERY COPY GRANTS
  COMMENT='AWS Console login without MFA
  @id ETV1GDUPBSR
  @tags aws, login, mfa, successful activity'
AS
SELECT OBJECT_CONSTRUCT(
         'cloud', 'aws',
         'region', awsregion,
         'account_id', recipientaccountid,
         'useridentity:"type"', useridentity:"type",
         'principal_id_of_user', useridentity:"principalId"
       ) AS environment
     , ARRAY_CONSTRUCT('CloudTrail') AS sources
     , recipientaccountid AS object
     , 'AWS Console Login without MFA' AS title
     , eventtime AS event_time
     , CURRENT_TIMESTAMP() AS alert_time
     , responseelements:"ConsoleLogin" AS action
     , COALESCE(useridentity:"userName", useridentity:"arn") AS actor
     , (
         'Actor ' || actor || ' logged in without MFA, ' ||
         'status: ' || action
       ) AS description
     , 'SnowAlert' AS detector
     , OBJECT_CONSTRUCT(*) AS event_data
     , 'low' AS severity
     , 'ETV1GDUPBSR' AS query_id
FROM cloudtrail
WHERE 1=1
  AND eventname = 'ConsoleLogin'
  AND responseelements:"ConsoleLogin" != 'Failure'
  AND useridentity:"type" = 'IAMUser'
  AND (
    (
      PARSE_JSON(additionalEventData):"MFAUsed" != 'Yes'
      OR PARSE_JSON(additionalEventData):"MFAUsed" IS NULL
    )
    OR PARSE_JSON(additionalEventData):"SamlProviderArn" IS NULL
  )
;

--Root Account Activity
CREATE OR REPLACE VIEW rules.CLOUDTRAIL_ROOT_ACTIVITY_ALERT_QUERY COPY GRANTS
  COMMENT='Activity by root user, which should only happen under well-documented circumstances covered by suppressions
  @id 33856532b3954b18b21ad1b3bc64cdd3
  @tags aws, admin activity'
AS
SELECT OBJECT_CONSTRUCT(
         'cloud', 'AWS',
         'account', recipientaccountid,
         'region', awsregion
       ) AS environment
     , ARRAY_CONSTRUCT('CloudTrail') AS sources
     , 'AWS Root Account' AS object
     , 'Activity by Root' AS title
     , eventtime AS event_time
     , CURRENT_TIMESTAMP() AS alert_time
     , 'root' AS actor
     , eventname AS action
     , (
         'User ' || actor || ' ' ||
         'performed ' || action || ', ' ||
         'working from ' || sourceipaddress
       ) AS description
     , 'SnowAlert' AS detector
     , OBJECT_CONSTRUCT(*) AS event_data
     , 'critical' AS severity
     , '33856532b3954b18b21ad1b3bc64cdd3' AS query_id
FROM cloudtrail
WHERE 1=1
  AND useridentity:"type" = 'Root'
;

