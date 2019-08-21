--Advisory: event times for queries below may or may not be set. Recommended adding event time parameter and running. 


--AWS Config Recorder disabled 
CREATE OR REPLACE VIEW rules.CLOUDTRAIL_CONFIG_DELETION_ALERT_QUERY COPY GRANTS
  COMMENT='This alerts on the deletion of aws config snapshot recorders or delivery channels
  @id 3bab686c1ac841c586c2b3d206a81d8b
  @tags aws, logging'
AS
SELECT OBJECT_CONSTRUCT(
         'cloud', 'AWS',
         'account_id', cloudtrail.RECIPIENTACCOUNTID
       ) AS environment
     , ARRAY_CONSTRUCT('cloudtrail') AS sources
     , cloudtrail.REQUESTPARAMETERS:configurationRecorderName AS object
     , 'AWS Config Recorder Disabled' AS title
     , cloudtrail.EVENTTIME AS EVENT_TIME
     , CURRENT_TIMESTAMP() AS alert_time
     , (
         'User ' || CASE
           WHEN cloudtrail.USERIDENTITY:"type" = 'IAMUser'
           THEN cloudtrail.USERIDENTITY:"userName"
           WHEN cloudtrail.USERIDENTITY:"type" = 'Root'
           THEN 'Root'
           WHEN cloudtrail.USERIDENTITY:"type" = 'AssumedRole'
           THEN cloudtrail.USERIDENTITY:"sessionContext":"sessionIssuer":"userName"
           WHEN cloudtrail.USERIDENTITY:"type" = 'AWSAccount'
           THEN cloudtrail.USERIDENTITY:"accountId"
           WHEN cloudtrail.USERIDENTITY:"type" = 'AWSService'
           THEN cloudtrail.USERIDENTITY:"invokedBy"
         END
         || ' performed ' || cloudtrail.EVENTNAME
         || ' on ' || cloudtrail.REQUESTPARAMETERS:configurationRecorderName
         || ', working from ' || 
          cloudtrail.SOURCEIPADDRESS
         END
       ) AS description
     , CASE
         WHEN cloudtrail.USERIDENTITY:"type" = 'IAMUser'
         THEN cloudtrail.USERIDENTITY:"userName"
         WHEN cloudtrail.USERIDENTITY:"type" = 'Root'
         THEN 'Root'
         WHEN cloudtrail.USERIDENTITY:"type" = 'AssumedRole'
         THEN cloudtrail.USERIDENTITY:"sessionContext":"sessionIssuer":"userName"
         WHEN cloudtrail.USERIDENTITY:"type" = 'AWSAccount'
         THEN cloudtrail.USERIDENTITY:"accountId"
         WHEN cloudtrail.USERIDENTITY:"type" = 'AWSService'
         THEN cloudtrail.USERIDENTITY:"invokedBy"
       END AS actor
     , cloudtrail.EVENTNAME AS action
     , 'SnowAlert' AS detector
     , object_construct(*) AS event_data
     , 'medium' AS severity
     , '3bab686c1ac841c586c2b3d206a81d8b' AS query_id
     , 'cloudtrail_config_deletion_v' AS query_name
     , OBJECT_CONSTRUCT(*) AS event_data
FROM data.cloudtrail AS cloudtrail
WHERE 1=1
  AND (
  cloudtrail.EVENTNAME  = 'DeleteDeliveryChannel'
  OR cloudtrail.EVENTNAME  = 'DeleteConfigurationRecorder'
 )
;



--AWS Systems manager Run Command Usage
CREATE OR REPLACE VIEW rules.CLOUDTRAIL_AWSSM_RUNCOMMAND_ALERT_QUERY COPY GRANTS
  COMMENT='This alerts on SendCommands to the SSM service, a vector of compromising EC2 instances
  @id 4363513205bd49ec9bd26bf63acbec72
  @tags aws, ec2'
AS
SELECT OBJECT_CONSTRUCT(
         'cloud', 'AWS',
         'account_id', recipientaccountid
       ) AS environment
     , ARRAY_TO_STRING(REQUESTPARAMETERS:instanceIds, ', ') AS object
     , ARRAY_CONSTRUCT('cloudtrail') AS sources
     , 'AWS Systems Manager Run Command Usage' AS title
     , EVENTTIME AS EVENT_TIME
     , CURRENT_TIMESTAMP() AS alert_time
     , (
         CASE
           WHEN USERIDENTITY:"type" = 'IAMUser'
           THEN USERIDENTITY:"userName"

           WHEN USERIDENTITY:"type" = 'Root'
           THEN 'Root'

           WHEN USERIDENTITY:"type" = 'AssumedRole'
           THEN USERIDENTITY:"sessionContext":"sessionIssuer":"userName"

           WHEN USERIDENTITY:"type" = 'AWSAccount'
           THEN USERIDENTITY:"accountId"

           WHEN USERIDENTITY:"type" = 'AWSService'
           THEN USERIDENTITY:"invokedBy"
         END || ' used AWS Systems Managed Run Command on ' || object
       ) AS description
     , CASE
         WHEN USERIDENTITY:"type" = 'IAMUser'
         THEN USERIDENTITY:"userName"

         WHEN USERIDENTITY:"type" = 'Root'
         THEN 'Root'

         WHEN USERIDENTITY:"type" = 'AssumedRole'
         THEN USERIDENTITY:"sessionContext":"sessionIssuer":"userName"

         WHEN USERIDENTITY:"type" = 'AWSAccount'
         THEN USERIDENTITY:"accountId"

         WHEN USERIDENTITY:"type" = 'AWSService'
         THEN USERIDENTITY:"invokedBy"

       END AS actor
     , EVENTNAME AS action
     , 'SnowAlert' AS detector
     , object_construct(*) AS event_data
     , 'high' AS severity
     , '4363513205bd49ec9bd26bf63acbec72' AS query_id
     , 'cloudtrail_awssm_runcommand_v' AS query_name
FROM data.cloudtrail
WHERE 1=1
  AND ERRORSOURCE = 'ssm.amazonaws.com'
  AND EVENTNAME = 'SendCommand'
;


--AWS Access Denied for Instance Termination
CREATE OR REPLACE VIEW rules.AWS_TERMINATE_INSTANCE_ACCESS_DENIED_ALERT_QUERY COPY GRANTS
  COMMENT='This alerts on users attempting to terminate instances without permission in AWS
  @id yvoaik0dsvn
  @tags aws, failed action'
AS
SELECT OBJECT_CONSTRUCT(
              'cloud', 'AWS',
              'account_id', cloudtrail.RECIPIENTACCOUNTID
           ) AS environment
     , array_construct('CloudTrail') AS sources
     , cloudtrail.EVENTNAME AS object
     , 'AWS Access Denied for TerminateInstance' AS title
     , cloudtrail.EVENTTIME AS EVENT_TIME
     , CURRENT_TIMESTAMP() AS alert_time
     , (
         'Terminate instance operation blocked for user ' || (
             CASE
               WHEN cloudtrail.USERIDENTITY:"type" = 'IAMUser'
                 THEN cloudtrail.USERIDENTITY:"userName"
               WHEN cloudtrail.USERIDENTITY:"type" = 'Root'
                 THEN 'Root'
               WHEN cloudtrail.USERIDENTITY:"type" = 'AssumedRole'
                 THEN cloudtrail.USERIDENTITY:"sessionContext":"sessionIssuer":"userName"
               WHEN cloudtrail.USERIDENTITY:"type" = 'AWSAccount'
                 THEN cloudtrail.USERIDENTITY:"accountId"
               WHEN cloudtrail.USERIDENTITY:"type" = 'AWSService'
                 THEN cloudtrail.USERIDENTITY:"invokedBy"
             END
           ) || ' trying to ' || cloudtrail.EVENTNAME || ' from ' ||  cloudtrail.SOURCEIPADDRESS
       ) AS description
     , CASE
         WHEN cloudtrail.USERIDENTITY:"type" = 'IAMUser'
           THEN cloudtrail.USERIDENTITY:"userName"
         WHEN cloudtrail.USERIDENTITY:"type" = 'Root'
           THEN 'Root'
         WHEN cloudtrail.USERIDENTITY:"type" = 'AssumedRole'
           THEN cloudtrail.USERIDENTITY:"sessionContext":"sessionIssuer":"userName"
         WHEN cloudtrail.USERIDENTITY:"type" = 'AWSAccount'
           THEN cloudtrail.USERIDENTITY:"accountId"
         WHEN cloudtrail.USERIDENTITY:"type" = 'AWSService'
           THEN cloudtrail.USERIDENTITY:"invokedBy"
       END AS actor
     , cloudtrail.EVENTNAME AS action
     , 'SnowAlert' AS detector
     , object_construvt(*) AS event_data
     , 'medium' AS severity
     , 'AWS_TERMINATE_INSTANCE_ACCESS_DENIED' AS query_name
     , 'yvoaik0dsvn' AS query_id
FROM data.cloudtrail AS cloudtrail
WHERE 1=1
  AND cloudtrail.ERRORCODE = 'AccessDenied'
  AND ACTION = 'TerminateInstances'
;



--AWS Access Denied for IAM Operation
CREATE OR REPLACE VIEW rules.AWS_IAM_ACCESS_DENIED_ALERT_QUERY COPY GRANTS
  COMMENT='This alert detects users attempting to perform actions related to IAM permissions without authorization in AWS
  @id d839e4d0695c4a9db582c681f87b6ced
  @tags aws, failed action'
AS
SELECT OBJECT_CONSTRUCT(
              'cloud', 'AWS',
              'account_id', cloudtrail.RECIPIENTACCOUNTID
)
           AS environment
     , ARRAY_CONSTRUCT('cloudtrail') AS sources
     , REGEXP_SUBSTR(cloudtrail.ERRORMESSAGE, 'resource:\\W{1}(.*)$', 1, 1, 'e') AS object
     , 'AWS Access Denied for IAM Operation' AS title
     , cloudtrail.EVENTTIME AS EVENT_TIME
     , CURRENT_TIMESTAMP() AS alert_time
     , (
         'IAM operation blocked for user ' || (
             CASE
               WHEN cloudtrail.USERIDENTITY:"type" = 'IAMUser'
                 THEN cloudtrail.USERIDENTITY:"userName"
               WHEN cloudtrail.USERIDENTITY:"type" = 'Root'
                 THEN 'Root'
               WHEN cloudtrail.USERIDENTITY:"type" = 'AssumedRole'
                 THEN cloudtrail.USERIDENTITY:"sessionContext":"sessionIssuer":"userName"
               WHEN cloudtrail.USERIDENTITY:"type" = 'AWSAccount'
                 THEN cloudtrail.USERIDENTITY:"accountId"
               WHEN cloudtrail.USERIDENTITY:"type" = 'AWSService'
                 THEN cloudtrail.USERIDENTITY:"invokedBy"
             END
           ) || ' trying to ' || cloudtrail.EVENTNAME || ' from ' ||  cloudtrail.SOURCEIPADDRESS
       ) AS description
     , CASE
         WHEN cloudtrail.USERIDENTITY:"type" = 'IAMUser'
           THEN cloudtrail.USERIDENTITY:"userName"
         WHEN cloudtrail.USERIDENTITY:"type" = 'Root'
           THEN 'Root'
         WHEN cloudtrail.USERIDENTITY:"type" = 'AssumedRole'
           THEN cloudtrail.USERIDENTITY:"sessionContext":"sessionIssuer":"userName"
         WHEN cloudtrail.USERIDENTITY:"type" = 'AWSAccount'
           THEN cloudtrail.USERIDENTITY:"accountId"
         WHEN cloudtrail.USERIDENTITY:"type" = 'AWSService'
           THEN cloudtrail.USERIDENTITY:"invokedBy"
       END AS actor
     , cloudtrail.EVENTNAME AS action
     , 'SnowAlert' AS detector
     , OBJECT_CONSTRUCT(*) AS event_data
     , 'low' AS severity
     , 'd839e4d0695c4a9db582c681f87b6ced' AS query_id
FROM data.cloudtrail AS cloudtrail
WHERE 1=1
  AND cloudtrail.ERRORCODE = 'AccessDenied'
  AND cloudtrail.ERRORSOURCE = 'iam.amazonaws.com'
;

--Excessive Compute Resources Requested
--Needs: definition for excessive based on value type 

CREATE OR REPLACE VIEW rules.AQ_WKHSSRZ904_ALERT_QUERY COPY GRANTS
  COMMENT='This alerts on a user requesting excessive resources for an instance
  ***********NEEDS THRESHOLDS***************
  @id WKHSSRZ904
  @tags cloudtrail, aws'
AS
SELECT OBJECT_CONSTRUCT('role', roles, 'instance_type', instance_type, 'account_id', recipientAccountId) AS environment
     , ARRAY_CONSTRUCT('Cloudtrail') AS sources
     , recipientAccountId AS object
     , 'Excessive Compute Resources Requested' AS title
     , EVENTTIME AS EVENT_TIME
     , CURRENT_TIMESTAMP() AS alert_time
     , 'Actor with role '||roles||' ran ' || eventName|| ' requesting instance type '|| instance_type|| ' at '|| alert_time AS description
     , roles AS actor
     , eventname AS action
     , 'SnowAlert' AS detector
     , object_construct(*) AS event_data
     , NULL AS handlers
     , 'low' AS severity
     , 'WKHSSRZ904' AS query_id
FROM (
SELECT  raw, EVENTTIME, value:"instanceType" as instance_type, roles
FROM (
  SELECT distinct response_elements:"instancesSet":"items" as instance_details
  , coalesce(USERIDENTITY:"userName"
                , user_identity:"sessionContext":"sessionIssuer":"userName"
               ) as roles 
  , raw
  , EVENTTIME
FROM SNOWALERT.BASE_DATA.CLOUDTRAIL_T 
  WHERE EVENTTIME >= '2019-08-14' 
  AND EVENTNAME in ('RunInstances')
), lateral flatten(input=>instance_details)
where value:"cpuOptions":"coreCount" >= 18 or value:"cpuOptions":"threadsPerCore" >2
UNION ALL
SELECT distinct raw, EVENTTIME, value:"value", roles FROM (SELECT REQUESTPARAMETERS
  , coalesce(USERIDENTITY:"userName"
                , user_identity:"sessionContext":"sessionIssuer":"userName"
               ) as roles 
                                                     , raw, EVENTTIME
                                                     
                                                     FROM SNOWALERT.BASE_DATA.CLOUDTRAIL_T 
  WHERE EVENTTIME >= '2019-08-01' 
  AND EVENTNAME in ('ModifyInstanceAttribute')), lateral flatten(input=>REQUESTPARAMETERS) where path in ('ramdisk', 'instanceType') 

)
WHERE 1=1
  AND 2=2
;



--Impossible Travel for Console Login
--Requires geolocation source

;

--User Assigned Escalated Policy to Themselves
CREATE OR REPLACE VIEW rules.AQ_Q8ZKNXX4BOP_ALERT_QUERY COPY GRANTS
  COMMENT='This alerts on a user applying an iam policy to themselves, their role, or to star
  @id Q8ZKNXX4BOP
  @tags cloudtrail, policies'
AS
SELECT OBJECT_CONSTRUCT('user_session', user_session, 'role', roles, 'policy', actions, 'resources', resources) AS environment
     , ARRAY_CONSTRUCT('Cloudtrail') AS sources
     , RAW:"recipientAccountId" AS object
     , 'Cloudtrail User Assigned Escalated Policy to Themselves Alert' AS title
     , EVENTTIME AS EVENT_TIME
     , CURRENT_TIMESTAMP() AS alert_time
     , USER_SESSION ||' applied policy ' || ACTIONS || ' to resources '|| RESOURCES || ' at ' || EVENTTIME AS description
     , USER_SESSION AS actor
     , eventName AS action
     , 'SnowAlert' AS detector
     , object_construct(*) AS event_data
     , NULL AS handlers
     , 'low' AS severity
     , 'Q8ZKNXX4BOP' AS query_id
FROM (SELECT USER_IDENTITY
     , coalesce(USERIDENTITY:"userName"
                , regexp_substr(user_identity:"arn", '.*/(.*?)(\\.([1-9])*)', 1, 1,'e')
                , regexp_substr(user_identity:"arn", '.*/(.*)$', 1, 1,'e')
               ) as user_session
     , coalesce(USERIDENTITY:"userName"
                , user_identity:"sessionContext":"sessionIssuer":"userName"
               ) as roles 
     , RAW
     , EVENTTIME
     , VALUE:"Action" as actions
     ,  VALUE:"Resource" as resources 
     FROM
    (SELECT parse_json(REQUESTPARAMETERS:"policyDocument"):"Statement" as policy_statements
    , USERIDENTITY:"userName", user_identity:"arn"
    , user_identity
    , raw, EVENTTIME
    FROM SNOWALERT.BASE_DATA.CLOUDTRAIL_T
    WHERE EVENTNAME in ('UpdatePolicy', 'UpdateUserPolicy', 'PutUserPolicy', 'PutRolePolicy', 'PutUserPolicy')
    ), lateral flatten(input=>policy_statements)
     )
WHERE 1=1
  AND ACTIONS ILIKE '%iam:%' and (RESOURCES rlike '.*(:user\\/\\*)".*' or resources ilike '%"*"%' OR RESOURCES ='*' OR RESOURCES ILIKE '%'||ROLES||'%' OR RESOURCES ILIKE '%'||USER_SESSION||'%') 
    
;



--Possible EC2 Backdoor Shell Script
--EC2 Startup shell script

CREATE OR REPLACE VIEW rules.AWS_EC2_STARTUP_SHELL_SCRIPT_ALERT_QUERY COPY GRANTS
COMMENT='This alert detects startup scripts getting added to EC2 instances, which is a vector for persistent compromise of an instance
@id f15346a9c9684abe85993a233d27f8ba
@tags aws, ec2, logon scripts'
AS;
SELECT OBJECT_CONSTRUCT(
  'cloud', 'AWS',
  'account', cloudtrail.recipientaccountid
) AS environment
, ARRAY_CONSTRUCT('Cloudtrail') AS sources
, IFF(cloudtrail.REQUESTPARAMETERS:instanceId IS NOT NULL,
      cloudtrail.REQUESTPARAMETERS:instanceId,
      cloudtrail.REQUESTPARAMETERS
) AS object
, 'Possible EC2 Startup Shell Script' AS title
, cloudtrail.eventtime AS EVENT_TIME
, CURRENT_TIMESTAMP() AS alert_time
, ('User ' ||
     CASE
   WHEN cloudtrail.USERIDENTITY:"type" = 'IAMUser' THEN cloudtrail.USERIDENTITY:"userName"
   WHEN cloudtrail.USERIDENTITY:"type" = 'Root' THEN 'Root'
   WHEN cloudtrail.USERIDENTITY:"type" = 'AssumedRole' THEN cloudtrail.USERIDENTITY:"sessionContext":"sessionIssuer":"userName"
   WHEN cloudtrail.USERIDENTITY:"type" = 'AWSAccount' THEN cloudtrail.USERIDENTITY:"accountId"
   WHEN cloudtrail.USERIDENTITY:"type" = 'AWSService' THEN cloudtrail.USERIDENTITY:"invokedBy"
   END
   || ' modified the startup shell script, an action associated with instance compromise, on '  ||
     IFF(cloudtrail.REQUESTPARAMETERS:instanceId IS NOT NULL,
         cloudtrail.REQUESTPARAMETERS:instanceId,
         cloudtrail.REQUESTPARAMETERS
     ) || ', working from ' ||
     cloudtrail.SOURCEIPADDRESS
   
) AS description
, CASE
WHEN cloudtrail.USERIDENTITY:"type" = 'IAMUser' THEN cloudtrail.USERIDENTITY:"userName"
WHEN cloudtrail.USERIDENTITY:"type" = 'Root' THEN 'Root'
WHEN cloudtrail.USERIDENTITY:"type" = 'AssumedRole' THEN cloudtrail.USERIDENTITY:"sessionContext":"sessionIssuer":"userName"
WHEN cloudtrail.USERIDENTITY:"type" = 'AWSAccount' THEN cloudtrail.USERIDENTITY:"accountId"
WHEN cloudtrail.USERIDENTITY:"type" = 'AWSService' THEN cloudtrail.USERIDENTITY:"invokedBy"
END AS actor
, cloudtrail.eventname AS action
, 'SnowAlert' AS detector
, object_construct(*) AS event_data
, 'high' AS severity
, 'f15346a9c9684abe85993a233d27f8ba' AS query_id
, 'aws_ec2_startup_shell_script_v' AS query_name
FROM XXX cloudtrail

WHERE 1=1 AND EVENTTIME>=dateadd(minute,-1,current_timestamp)
AND cloudtrail.eventsource  = 'ec2.amazonaws.com'
AND cloudtrail.eventname = 'ModifyInstanceAttribute'
AND cloudtrail.requestparameters:userData IS NOT NULL
;

--User Logging in Without MFA
CREATE OR REPLACE VIEW rules.AWS_CONSOLE_WITHOUT_MFA_ALERT_QUERY COPY GRANTS
  COMMENT='This alert of an aws console login without MFA
  @id ETV1GDUPBSR
  @tags aws, login, mfa, successfu activity'
AS;
SELECT OBJECT_CONSTRUCT('cloud', 'aws', 'region', awsregion, 'account_id', recipientAccountId, 'USERIDENTITY:"type"', useridentity:"type", 'principal_id_of_user', useridentity:"principalId") AS environment
     , ARRAY_CONSTRUCT('Cloudtrail') AS sources
     , recipientAccountId AS object
     , 'AWS Console Login without MFA' AS title
     , eventtime AS EVENT_TIME
     , CURRENT_TIMESTAMP() AS alert_time
     , 'AWS Console without MFA with status:'||responseelements:"ConsoleLogin" AS description
     , coalesce(useridentity:"userName", useridentity:"arn") AS actor
     , responseelements:"ConsoleLogin" AS action
     , 'SnowAlert' AS detector
     , OBJECT_CONSTRUCT(*) AS event_data
     , 'low' AS severity
     , 'ETV1GDUPBSR' AS query_id
FROM 
XXX
WHERE 1=1
and eventtime >= dateadd(day, -1, current_timestamp)
and eventname = 'ConsoleLogin' 
and responseelements:"ConsoleLogin" != 'Failure'
AND USERIDENTITY:"type" = 'IAMUser'
and ((parse_json(additionalEventData):"MFAUsed" != 'Yes' 
  or parse_json(additionalEventData):"MFAUsed" is null) 
     or parse_json(additionalEventData):"SamlProviderArn" is null
    )

;

--Root Account Activity
CREATE OR REPLACE VIEW rules.CLOUDTRAIL_ROOT_ACTIVITY_ALERT_QUERY COPY GRANTS
  COMMENT='This alerts on activity by the root user in AWS, which should only happen under very specific and well-documented circumstances covered by suppressions
  @id 33856532b3954b18b21ad1b3bc64cdd3
  @tags aws, admin activity'
AS;
SELECT OBJECT_CONSTRUCT(
         'cloud', 'AWS',
         'account', cloudtrail.recipientaccountid,
         'region', cloudtrail.awsregion
       ) AS environment
     , ARRAY_CONSTRUCT('Cloudtrail') AS sources
     , 'AWS Root Account' AS object
     , 'Activity by Root' AS title
     , cloudtrail.eventtime AS EVENT_TIME
     , CURRENT_TIMESTAMP() AS alert_time
     , (
         'User root performed ' || cloudtrail.eventname
         || ', working from ' || cloudtrail.sourceipaddress
        
       ) AS description
     , 'root' AS actor
     , cloudtrail.EVENTNAME AS action
     , 'SnowAlert' AS detector
     , object_construct(cloudtrail.*) AS event_data
     , 'critical' AS severity
     , '33856532b3954b18b21ad1b3bc64cdd3' AS query_id
     , 'cloudtrail_root_activity_v' AS query_name
FROM XXX AS cloudtrail
WHERE 1=1
  AND cloudtrail.useridentity:"type" = 'Root'

;



